import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseArguments(arguments_) {
  const values = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index]?.replace(/^--/, '').replaceAll('-', '_');
    const value = arguments_[index + 1];
    assert(key && value, `incomplete argument ${arguments_[index]}`);
    values[key] = value;
  }

  for (const required of ['repository', 'image_tag', 'region', 'output']) {
    assert(values[required], `missing --${required.replaceAll('_', '-')}`);
  }
  return {
    ...values,
    maxAttempts: Number(values.max_attempts ?? 40),
    delaySeconds: Number(values.delay_seconds ?? 15)
  };
}

function run(command, arguments_, environment) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, { env: environment });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => rejectPromise(new Error(`cannot start ${command}: ${error.message}`, {
      cause: error
    })));
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

function awsInvocation(options) {
  const arguments_ = [
    'ecr',
    'describe-image-scan-findings',
    '--repository-name',
    options.repository,
    '--image-id',
    `imageTag=${options.image_tag}`,
    '--region',
    options.region,
    '--output',
    'json'
  ];

  if (!options.aws_cli_container) {
    return { command: 'aws', arguments_, environment: process.env };
  }

  return {
    command: 'docker',
    arguments_: [
      'run',
      '--rm',
      '-e',
      'AWS_ACCESS_KEY_ID',
      '-e',
      'AWS_SECRET_ACCESS_KEY',
      '-e',
      'AWS_SESSION_TOKEN',
      '-e',
      'AWS_REGION',
      '-e',
      'AWS_DEFAULT_REGION',
      options.aws_cli_container,
      ...arguments_
    ],
    environment: process.env
  };
}

export function normalizeEcrResponse(response, options) {
  assert(response.imageScanStatus?.status === 'COMPLETE', 'ECR scan is not complete');
  assert(
    Array.isArray(response.imageScanFindings?.findings),
    'ECR response lacks imageScanFindings.findings'
  );
  assert(
    response.imageScanFindings.findingSeverityCounts &&
      typeof response.imageScanFindings.findingSeverityCounts === 'object',
    'ECR response lacks findingSeverityCounts'
  );
  assert(typeof response.imageId?.imageDigest === 'string', 'ECR response lacks image digest');

  const severityMap = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFORMATIONAL: 'low',
    UNDEFINED: 'low'
  };
  const findings = response.imageScanFindings.findings.map((finding) => {
    assert(typeof finding.name === 'string', 'ECR finding lacks name');
    const severity = severityMap[finding.severity];
    assert(severity, `unsupported ECR severity ${finding.severity}`);
    return { id: finding.name, severity };
  });
  const severityCounts = findings.reduce((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, {});

  return {
    schemaVersion: 1,
    source: 'aws-ecr-basic',
    scanStatus: 'COMPLETE',
    image: {
      repository: options.repository,
      imageTag: options.image_tag,
      imageDigest: response.imageId.imageDigest
    },
    severityCounts,
    findings
  };
}

export async function pollEcrScan(options) {
  assert(Number.isInteger(options.maxAttempts) && options.maxAttempts > 0, 'invalid max attempts');
  assert(Number.isFinite(options.delaySeconds) && options.delaySeconds >= 0, 'invalid delay');
  const invocation = awsInvocation(options);

  for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
    const result = await run(invocation.command, invocation.arguments_, invocation.environment);
    if (result.code === 0) {
      let response;
      try {
        response = JSON.parse(result.stdout);
      } catch (error) {
        throw new Error(`AWS CLI returned malformed JSON: ${error.message}`, { cause: error });
      }
      const status = response.imageScanStatus?.status;
      console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: ${status ?? 'UNKNOWN'}`);
      if (status === 'COMPLETE') {
        return normalizeEcrResponse(response, options);
      }
      if (!['IN_PROGRESS', 'PENDING', 'ACTIVE'].includes(status)) {
        throw new Error(`ECR image scan ended with status ${status ?? 'UNKNOWN'}`);
      }
    } else {
      console.log(`ECR image scan attempt ${attempt}/${options.maxAttempts}: not ready`);
      if (attempt === options.maxAttempts) {
        throw new Error(`AWS CLI failed while polling ECR: ${result.stderr.trim()}`);
      }
    }

    if (attempt < options.maxAttempts) {
      await delay(options.delaySeconds * 1000);
    }
  }

  throw new Error('ECR image scan did not complete before the polling limit');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const report = await pollEcrScan(options);
  await mkdir(dirname(options.output), { recursive: true });
  await writeFile(options.output, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`ECR image scan report written to ${options.output}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
