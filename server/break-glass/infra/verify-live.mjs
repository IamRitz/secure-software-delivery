// Live verification of the deployed Lambda broker. Run from AWS CloudShell with
// the same admin identity that ran deploy.sh (it reads the signing secret and
// invokes break-glass-ci directly):
//
//   node server/break-glass/infra/verify-live.mjs \
//     --repo IamRitz/secure-software-delivery --pr 51 \
//     --approver U0BV6TWN60J --other-repo-approver U0OTHERREPO [--region us-east-1] [--skip-timeout]
//
// Prerequisite: SLACK_APPROVER_IDS_BY_REPO on the interactions function lists
// --approver under --repo, and --other-repo-approver under some OTHER repo only.
//
// Clicks here are synthesized and signed with the real signing secret — the
// exact bytes-on-the-wire Slack sends — so they exercise the deployed
// verification, authorization, and DynamoDB claim path. They are labelled
// "verify-live-synthetic" in the audit comment. Human clicks in Slack are a
// separate check (see server/break-glass/lambda/README.md).
//
// Writes an evidence file (reports/break-glass-live-evidence.json) with every
// request, HTTP status, outcome header, and the final DynamoDB items.
import { execFile } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs, promisify } from 'node:util';

const run = promisify(execFile);
const { values: args } = parseArgs({
  options: {
    repo: { type: 'string' },
    pr: { type: 'string' },
    approver: { type: 'string' },
    'other-repo-approver': { type: 'string' },
    region: { type: 'string', default: process.env.AWS_REGION || 'us-east-1' },
    prefix: { type: 'string', default: 'break-glass' },
    concurrency: { type: 'string', default: '25' },
    'skip-timeout': { type: 'boolean', default: false }
  }
});
for (const required of ['repo', 'pr', 'approver', 'other-repo-approver']) {
  if (!args[required]) throw new Error(`--${required} is required`);
}

const evidence = { startedAt: new Date().toISOString(), region: args.region, checks: [] };
let failures = 0;
function check(name, passed, detail) {
  evidence.checks.push({ name, passed, ...detail });
  if (!passed) failures += 1;
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ${JSON.stringify(detail)}` : ''}`);
}

const aws = async (...argv) => JSON.parse((await run('aws', [...argv, '--region', args.region, '--output', 'json'], { maxBuffer: 10 * 1024 * 1024 })).stdout || '{}');

const CI_FN = `${args.prefix}-ci`;
const INT_FN = `${args.prefix}-interactions`;
const TABLE = `${args.prefix}-requests`;

const url = (await aws('lambda', 'get-function-url-config', '--function-name', INT_FN)).FunctionUrl;
const signingSecret = (await aws('secretsmanager', 'get-secret-value', '--secret-id', `${args.prefix}/slack-signing-secret`)).SecretString;

async function invokeCi(event) {
  const { writeFile: write, readFile, mkdtemp, rm } = await import('node:fs/promises');
  const dir = await mkdtemp('/tmp/bg-');
  try {
    await write(`${dir}/in.json`, JSON.stringify(event));
    await run('aws', ['lambda', 'invoke', '--function-name', CI_FN, '--region', args.region,
      '--cli-binary-format', 'raw-in-base64-out', '--payload', `fileb://${dir}/in.json`, `${dir}/out.json`]);
    return JSON.parse(await readFile(`${dir}/out.json`, 'utf8'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function notify(timeoutSeconds = 900) {
  const result = await invokeCi({
    action: 'notify',
    payload: {
      schemaVersion: 1,
      gateDigest: createHmac('sha256', 'verify-live').update(String(Date.now())).digest('hex'),
      timeoutSeconds,
      context: { repository: args.repo, commitSha: 'verify-live-synthetic', pullRequest: args.pr, ciSystem: 'verify-live' },
      findings: [{ source: 'semgrep', id: 'verify-live.synthetic', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'synthetic live verification' }]
    }
  });
  if (!result.ok) throw new Error(`notify failed: ${JSON.stringify(result)}`);
  return result.body.requestId;
}

const status = async (requestId) => (await invokeCi({ action: 'status', requestId })).body;
const item = async (requestId) =>
  (await aws('dynamodb', 'get-item', '--table-name', TABLE, '--consistent-read', '--key', JSON.stringify({ requestId: { S: requestId } }))).Item;

function sign(body, { secret = signingSecret, ageSeconds = 0 } = {}) {
  const ts = String(Math.floor(Date.now() / 1000) - ageSeconds);
  return { ts, signature: `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}` };
}
const clickBody = (requestId, { userId, action = 'approve', type = 'block_actions' }) =>
  `payload=${encodeURIComponent(JSON.stringify({
    type,
    user: { id: userId, username: 'verify-live-synthetic' },
    actions: [{ action_id: `breakglass:${requestId}:${action}` }]
  }))}`;

async function post(body, headers) {
  const response = await globalThis.fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body
  });
  await response.arrayBuffer();
  return { http: response.status, outcome: response.headers.get('x-break-glass-outcome') };
}
async function signedPost(body, options) {
  const { ts, signature } = sign(body, options);
  return post(body, { 'x-slack-signature': signature, 'x-slack-request-timestamp': ts });
}

// ---- 1. Signature verification -------------------------------------------------
{
  const requestId = await notify();
  const approve = clickBody(requestId, { userId: args.approver });
  check('unsigned request rejected', (await post(approve, {})).http === 401);

  const genuineNonButton = await signedPost(clickBody(requestId, { userId: args.approver, type: 'view_submission' }));
  check('genuine signed request accepted', genuineNonButton.http === 200 && genuineNonButton.outcome === 'ignored', genuineNonButton);

  const { ts, signature } = sign(clickBody(requestId, { userId: args.approver, action: 'deny' }));
  const tampered = await post(approve, { 'x-slack-signature': signature, 'x-slack-request-timestamp': ts });
  check('tampered body rejected', tampered.http === 401, tampered);

  const stale = await signedPost(approve, { ageSeconds: 301 });
  check('stale timestamp rejected', stale.http === 401, stale);

  const wrong = await signedPost(approve, { secret: 'not-the-signing-secret' });
  check('wrong signing secret rejected', wrong.http === 401, wrong);

  const malformed = await signedPost('payload=%7Bnot-json');
  check('signed malformed payload rejected', malformed.http === 400, malformed);

  check('request still pending after all rejected requests', (await status(requestId)).status === 'pending', { requestId });

  // ---- 2. Authorization --------------------------------------------------------
  const stranger = await signedPost(clickBody(requestId, { userId: 'U0VERIFYNOBODY' }));
  check('unauthorized user is a no-op', stranger.outcome === 'unauthorized' && (await status(requestId)).status === 'pending', stranger);

  const otherRepo = await signedPost(clickBody(requestId, { userId: args['other-repo-approver'] }));
  check('approver for another repo rejected for this repo', otherRepo.outcome === 'unauthorized' && (await status(requestId)).status === 'pending', otherRepo);
  evidence.authorizationRequestId = requestId;
}

// ---- 3. Concurrent claim race ------------------------------------------------------
{
  const requestId = await notify();
  const n = Number(args.concurrency);
  // Sign everything first, then release all requests at once.
  const prepared = Array.from({ length: n }, (_, index) => {
    const body = clickBody(requestId, { userId: args.approver, action: index % 2 ? 'deny' : 'approve' });
    const { ts, signature } = sign(body);
    return { body, headers: { 'x-slack-signature': signature, 'x-slack-request-timestamp': ts } };
  });
  const results = await Promise.all(prepared.map(({ body, headers }) => post(body, headers)));
  const outcomes = results.reduce((acc, r) => ({ ...acc, [r.outcome ?? `http_${r.http}`]: (acc[r.outcome ?? `http_${r.http}`] || 0) + 1 }), {});
  const final = await status(requestId);
  check(`${n} concurrent clicks -> exactly one claimed`, outcomes.claimed === 1 && outcomes.duplicate === n - 1, { requestId, outcomes, final: final.status });
  check('race winner recorded as final state', ['approved', 'denied'].includes(final.status) && final.approver?.id === args.approver, final);
  await sleep(8000);
  const raced = await item(requestId);
  check('side effects claimed exactly once, claim cleared', Boolean(raced.sideEffectsAt) && !raced.claimUserId, {
    status: raced.status.S,
    sideEffectsAt: raced.sideEffectsAt?.S
  });
  evidence.raceRequestId = requestId;
}

// ---- 4. Timeout -> expired ---------------------------------------------------------
if (!args['skip-timeout']) {
  const requestId = await notify(60);
  console.log('waiting 65s for the 60s request to expire...');
  await sleep(65_000);
  const expired = await status(requestId);
  check('no decision within timeout -> expired', expired.status === 'expired', expired);
  const late = await signedPost(clickBody(requestId, { userId: args.approver }));
  check('click after expiry refused', late.outcome === 'expired' && (await status(requestId)).status === 'expired', late);
  evidence.timeoutRequestId = requestId;
}

evidence.finishedAt = new Date().toISOString();
evidence.failures = failures;
await mkdir('reports', { recursive: true });
await writeFile('reports/break-glass-live-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`} — evidence: reports/break-glass-live-evidence.json`);
process.exitCode = failures === 0 ? 0 : 1;
