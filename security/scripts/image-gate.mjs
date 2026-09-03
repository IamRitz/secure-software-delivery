import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseSimplePolicy, policyAction } from './security-gate.mjs';

const DEFAULT_PATHS = {
  policy: 'security/policy.yaml',
  report: 'reports/ecr-image-scan.json',
  output: 'reports/image-gate.json'
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function readJson(path) {
  let source;

  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`missing image scan report ${path}`, { cause: error });
    }
    throw new Error(`cannot read image scan report ${path}: ${error.message}`, { cause: error });
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`malformed JSON in image scan report ${path}: ${error.message}`, {
      cause: error
    });
  }
}

function validatePolicy(policy) {
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const action = policyAction(policy, `image.${severity}`);
    const expected = ['critical', 'high'].includes(severity) ? 'BLOCK_DEPLOY' : 'LOG';
    assert(action === expected, `image.${severity} must be ${expected} for this POC`);
  }
}

function evaluate(policy, report) {
  assert(report?.schemaVersion === 1, 'image scan report has unsupported schemaVersion');
  assert(report.source === 'aws-ecr-basic', 'image scan report has unsupported source');
  assert(report.scanStatus === 'COMPLETE', 'image scan report status is not COMPLETE');
  assert(typeof report.image?.repository === 'string', 'image scan report lacks repository');
  assert(typeof report.image?.imageTag === 'string', 'image scan report lacks imageTag');
  assert(typeof report.image?.imageDigest === 'string', 'image scan report lacks imageDigest');
  assert(Array.isArray(report.findings), 'image scan report lacks findings array');
  assert(
    report.severityCounts && typeof report.severityCounts === 'object',
    'image scan report lacks severityCounts'
  );

  const findings = report.findings.map((finding) => {
    assert(typeof finding.id === 'string', 'image finding lacks id');
    assert(typeof finding.severity === 'string', `image finding ${finding.id} lacks severity`);
    const severity = finding.severity.toLowerCase();
    assert(
      ['critical', 'high', 'medium', 'low'].includes(severity),
      `image finding ${finding.id} has unsupported severity ${finding.severity}`
    );
    const policyRule = `image.${severity}`;
    return {
      source: 'ecr-image-scan',
      id: finding.id,
      severity,
      action: policyAction(policy, policyRule),
      policyRule,
      reason: `${severity} image finding`
    };
  });

  const severities = ['critical', 'high', 'medium', 'low'];
  for (const severity of Object.keys(report.severityCounts)) {
    assert(severities.includes(severity), `unsupported image severity count ${severity}`);
  }
  for (const severity of severities) {
    const reported = report.severityCounts[severity] ?? 0;
    const observed = findings.filter((finding) => finding.severity === severity).length;
    assert(
      Number.isInteger(reported) && reported >= 0,
      `image ${severity} severity count must be a non-negative integer`
    );
    assert(reported === observed, `image ${severity} count does not match findings array`);
  }

  const blockDeploy = findings.filter((finding) => finding.action === 'BLOCK_DEPLOY').length;
  const log = findings.filter((finding) => finding.action === 'LOG').length;
  return {
    verdict: blockDeploy > 0 ? 'BLOCK_DEPLOY' : 'DEPLOY',
    summary: { blockDeploy, log },
    image: report.image,
    findings
  };
}

async function writeResult(path, result) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(result, null, 2)}\n`);
}

export async function runImageGate(customPaths = {}) {
  const paths = { ...DEFAULT_PATHS, ...customPaths };
  let result;

  try {
    const policy = parseSimplePolicy(await readFile(paths.policy, 'utf8'));
    validatePolicy(policy);
    result = evaluate(policy, await readJson(paths.report));
  } catch (error) {
    result = {
      verdict: 'BLOCK_DEPLOY',
      summary: { blockDeploy: 1, log: 0 },
      findings: [
        {
          source: 'image-gate',
          id: 'report-integrity',
          severity: 'unknown',
          action: 'BLOCK_DEPLOY',
          policyRule: 'image.report_integrity',
          reason: error.message
        }
      ]
    };
  }

  await writeResult(paths.output, result);
  return result;
}

function parseArguments(arguments_) {
  const aliases = { '--policy': 'policy', '--report': 'report', '--output': 'output' };
  const paths = {};

  for (let index = 0; index < arguments_.length; index += 2) {
    const key = aliases[arguments_[index]];
    const value = arguments_[index + 1];
    assert(key && value, `unknown or incomplete argument ${arguments_[index]}`);
    paths[key] = value;
  }

  return paths;
}

async function main() {
  let paths;

  try {
    paths = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`IMAGE GATE: BLOCK_DEPLOY\n${error.message}`);
    process.exitCode = 1;
    return;
  }

  const result = await runImageGate(paths);
  for (const finding of result.findings) {
    console.log(
      `${finding.action} ${finding.id} (${finding.policyRule}): ${finding.reason}`
    );
  }
  console.log(`IMAGE GATE: ${result.verdict}`);
  process.exitCode = result.verdict === 'BLOCK_DEPLOY' ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
