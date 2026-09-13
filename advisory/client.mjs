// CI side of the advisory explainer POC — SHADOW MODE.
//
// Builds the allowlisted payload from the decided gate result, invokes the
// Lambda with the job's short-lived OIDC credentials, and writes what came
// back to the WORKFLOW LOG ONLY. It never writes a PR comment, a job summary,
// a step output, or an exit code anyone could read as a verdict: the
// deterministic comment (notify.mjs) is authoritative and posts independently.
//
// Every failure path logs and exits 0. The workflow step is also
// continue-on-error; this is belt and braces, not the only guard.

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildAdvisoryPayload } from './payload.mjs';

export const INVOKE_TIMEOUT_MS = 75_000;

// Default transport: the AWS CLI preinstalled on GitHub-hosted runners, using
// the credentials configure-aws-credentials exported from the OIDC exchange.
// AWS_MAX_ATTEMPTS=1: the single retry lives at the model call, not here, so
// one CI invocation can never fan out into several model calls.
export async function invokeWithAwsCli(payload, { functionName }) {
  const dir = await mkdtemp(join(tmpdir(), 'advisory-'));
  const requestPath = join(dir, 'request.json');
  const responsePath = join(dir, 'response.json');
  await writeFile(requestPath, JSON.stringify(payload));

  const stdout = await new Promise((resolvePromise, reject) => {
    const child = spawn(
      'aws',
      [
        'lambda', 'invoke',
        '--function-name', functionName,
        '--cli-binary-format', 'raw-in-base64-out',
        '--cli-connect-timeout', '10',
        '--cli-read-timeout', '60',
        '--payload', `fileb://${requestPath}`,
        responsePath
      ],
      { env: { ...process.env, AWS_MAX_ATTEMPTS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => (out += chunk));
    child.stderr.on('data', (chunk) => (err += chunk));
    const timer = globalThis.setTimeout(() => child.kill('SIGKILL'), INVOKE_TIMEOUT_MS);
    child.on('error', reject);
    child.on('close', (code) => {
      globalThis.clearTimeout(timer);
      if (code === 0) resolvePromise(out);
      else reject(new Error(`aws lambda invoke exited ${code}: ${err.trim().split('\n').at(-1) ?? ''}`));
    });
  });

  const meta = JSON.parse(stdout || '{}');
  if (meta.FunctionError) {
    throw new Error(`Lambda function error: ${meta.FunctionError}`);
  }
  return JSON.parse(await readFile(responsePath, 'utf8'));
}

function summarizeStatuses(results = []) {
  const counts = { ok: 0, rejected: 0, missing: 0 };
  for (const result of results) counts[result.status] = (counts[result.status] ?? 0) + 1;
  return counts;
}

export async function run({ gatePath, functionName, invoke = invokeWithAwsCli, log = console.log }) {
  // Model output and PR-influenced identifiers are printed below. Suspend
  // workflow-command processing so neither can emit `::add-mask::`,
  // `::set-output`, `::error` or similar into the runner.
  const stopToken = randomUUID();
  const metrics = { transport: 'lambda-oidc', mode: 'shadow', gatePath };

  let gate;
  try {
    gate = JSON.parse(await readFile(gatePath, 'utf8'));
  } catch (error) {
    log(`ADVISORY: no readable gate result at ${gatePath} (${error.code ?? 'parse error'}); Tier 0 comment is unaffected.`);
    log(`ADVISORY_METRICS ${JSON.stringify({ ...metrics, outcome: 'no-gate-result' })}`);
    return { outcome: 'no-gate-result' };
  }

  const payload = buildAdvisoryPayload(gate);
  if (payload.findings.length === 0) {
    log('ADVISORY: no advisable findings (none blocking, or Tier 0 only: secrets / integrity). No model call made.');
    log(`ADVISORY_METRICS ${JSON.stringify({ ...metrics, outcome: 'nothing-to-explain' })}`);
    return { outcome: 'nothing-to-explain' };
  }
  if (!functionName) {
    log('ADVISORY: ADVISORY_FUNCTION_NAME is not set; skipping.');
    return { outcome: 'not-configured' };
  }

  const started = Date.now();
  let response;
  try {
    response = await invoke(payload, { functionName });
  } catch (error) {
    const wallMs = Date.now() - started;
    log(`ADVISORY: invocation failed (${error.message}). Tier 0 comment stands alone.`);
    log(`ADVISORY_METRICS ${JSON.stringify({ ...metrics, outcome: 'invoke-failed', wallMs, findings: payload.findings.length })}`);
    return { outcome: 'invoke-failed' };
  }
  const wallMs = Date.now() - started;

  const outcome = response?.ok ? 'explained' : 'explainer-error';
  log(`::stop-commands::${stopToken}`);
  log('===== 🤖 ADVISORY EXPLANATION — SHADOW MODE: unverified model output, NOT shown to developers, gates nothing =====');
  if (!response?.ok) {
    log(`explainer returned an error: ${String(response?.error ?? 'unknown')}`);
  } else {
    for (const result of response.results ?? []) {
      const finding = payload.findings[result.index];
      log(`--- [${result.index}] ${finding?.policyKey} ${finding?.advisoryId} ${finding?.package ?? ''} -> ${result.status}${result.reason ? ` (${result.reason})` : ''}`);
      if (result.status === 'ok') {
        log(`summary:      ${result.explanation.summary}`);
        log(`whyItMatters: ${result.explanation.whyItMatters}`);
        log(`nextStep:     ${result.explanation.nextStep}`);
      }
    }
  }
  log('===== end advisory explanation =====');
  log(`::${stopToken}::`);

  log(
    `ADVISORY_METRICS ${JSON.stringify({
      ...metrics,
      outcome,
      wallMs,
      lambdaTotalMs: response?.totalLatencyMs ?? null,
      modelLatencyMs: response?.modelLatencyMs ?? null,
      model: response?.model ?? null,
      usage: response?.usage ?? null,
      findings: payload.findings.length,
      statuses: summarizeStatuses(response?.results),
      rejections: (response?.results ?? []).filter((r) => r.status === 'rejected').map((r) => r.reason)
    })}`
  );
  return { outcome };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const gateIndex = process.argv.indexOf('--gate');
  const gatePath = gateIndex === -1 ? 'reports/security-gate.json' : process.argv[gateIndex + 1];
  try {
    await run({ gatePath, functionName: process.env.ADVISORY_FUNCTION_NAME });
  } catch (error) {
    console.log(`ADVISORY: unexpected error (${error.message}); ignored — advisory only.`);
  }
  process.exitCode = 0;
}
