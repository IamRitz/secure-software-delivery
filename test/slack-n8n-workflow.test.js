import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const workflow = JSON.parse(
  await readFile('n8n/workflows/slack-break-glass-workflow.json', 'utf8')
);

function node(name) {
  const found = workflow.nodes.find((candidate) => candidate.name === name);
  assert(found, `workflow node ${name} is missing`);
  return found;
}

const SIGNING_SECRET = 'test-signing-secret';
const REQUEST_ID = '11111111-1111-4111-8111-111111111111';

function signedSlackItem(interaction, { timestamp, secret = SIGNING_SECRET } = {}) {
  const ts = timestamp ?? String(Math.floor(Date.now() / 1000));
  const rawBody = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const base = `v0:${ts}:${rawBody}`;
  const signature = `v0=${createHmac('sha256', secret).update(base).digest('hex')}`;
  return {
    ts,
    signature,
    input: {
      first: () => ({
        json: {
          headers: { 'x-slack-signature': signature, 'x-slack-request-timestamp': ts }
        },
        binary: { data: { data: Buffer.from(rawBody).toString('base64') } }
      })
    }
  };
}

describe('n8n Slack break-glass workflow definition', () => {
  it('exposes the Slack routes and reuses shared/GitHub credentials, distinct from Discord', () => {
    assert.equal(node('Webhook A - Slack Notify').parameters.authentication, 'headerAuth');
    assert.equal(node('Webhook C - Slack Status').parameters.authentication, 'headerAuth');
    assert.equal(node('Webhook - Slack Interactions').parameters.path, 'dev/slack/interactions');
    assert.equal(node('Webhook - Slack Interactions').parameters.options.rawBody, true);
    // finalize runs before the best-effort side effects
    assert.deepEqual(
      workflow.connections['Decision Claimed'].main[0].map((c) => c.node),
      ['Finalize Request State']
    );
    assert.equal(node('Post GitHub Audit Comment').continueOnFail, true);
    assert.equal(node('Update Slack Message').continueOnFail, true);
  });

  it('accepts a genuinely valid HMAC-signed request in the actual Verify node', async () => {
    const code = node('Verify Slack Signature').parameters.jsCode;
    // Shadow URLSearchParams to undefined to mimic the n8n Code-node sandbox,
    // which does not expose it — the parse must use only core-JS globals.
    const execute = new AsyncFunction('require', '$input', '$env', 'URLSearchParams', code);
    const interaction = {
      type: 'block_actions',
      user: { id: 'U-REAL', username: 'approver' },
      actions: [{ action_id: `breakglass:${REQUEST_ID}:approve` }]
    };
    const { input } = signedSlackItem(interaction);
    const result = await execute.call(
      { helpers: { getBinaryDataBuffer: async () => Buffer.from('') } },
      (await import('node:module')).createRequire(import.meta.url),
      input,
      { SLACK_SIGNING_SECRET: SIGNING_SECRET },
      undefined
    );
    assert.equal(result[0].json.responseCode, 200);
    assert.equal(result[0].json.processComponent, true);
    assert.equal(result[0].json.interaction.user.id, 'U-REAL');
  });

  it('rejects a tampered signature in the actual Verify node', async () => {
    const code = node('Verify Slack Signature').parameters.jsCode;
    // Shadow URLSearchParams to undefined to mimic the n8n Code-node sandbox,
    // which does not expose it — the parse must use only core-JS globals.
    const execute = new AsyncFunction('require', '$input', '$env', 'URLSearchParams', code);
    const interaction = { type: 'block_actions', user: { id: 'U-REAL' }, actions: [{ action_id: `breakglass:${REQUEST_ID}:approve` }] };
    const { input } = signedSlackItem(interaction);
    // Corrupt the signature header
    const original = input.first();
    const badInput = {
      first: () => ({
        json: { headers: { ...original.json.headers, 'x-slack-signature': `v0=${'0'.repeat(64)}` } },
        binary: original.binary
      })
    };
    const result = await execute.call(
      { helpers: { getBinaryDataBuffer: async () => Buffer.from('') } },
      (await import('node:module')).createRequire(import.meta.url),
      badInput,
      { SLACK_SIGNING_SECRET: SIGNING_SECRET },
      undefined
    );
    assert.equal(result[0].json.responseCode, 401);
    assert.equal(result[0].json.responseBody.error, 'invalid_request_signature');
  });

  it('leaves pending state unchanged for an unauthorized Slack click in the actual Claim node', async () => {
    const code = node('Authorize and Claim Decision').parameters.jsCode;
    const execute = new AsyncFunction('$json', '$env', '$getWorkflowStaticData', code);
    const state = { requests: { [REQUEST_ID]: { status: 'pending', expiresAt: '2099-01-01T00:00:00.000Z', findings: [], gateDigest: 'd' } } };
    const result = await execute(
      { interaction: { type: 'block_actions', user: { id: 'U-INTRUDER', username: 'intruder' }, actions: [{ action_id: `breakglass:${REQUEST_ID}:approve` }] } },
      { SLACK_APPROVER_IDS: 'U-ALLOWED' },
      () => state
    );
    assert.equal(result[0].json.outcome, 'unauthorized');
    assert.equal(state.requests[REQUEST_ID].status, 'pending');
    assert.equal(state.requests[REQUEST_ID].claim, undefined);
  });

  it('claims and prepares side effects for an authorized Slack approval in the actual Claim node', async () => {
    const code = node('Authorize and Claim Decision').parameters.jsCode;
    const execute = new AsyncFunction('$json', '$env', '$getWorkflowStaticData', code);
    const state = { requests: { [REQUEST_ID]: { requestId: REQUEST_ID, status: 'pending', expiresAt: '2099-01-01T00:00:00.000Z', gateDigest: 'abc123', findings: [{ policyRule: 'sast.high_new', id: 'demo.rule' }], context: { repository: 'o/r', pullRequest: '12' } } } };
    const result = await execute(
      { interaction: { type: 'block_actions', user: { id: 'U-ALLOWED', username: 'approver' }, actions: [{ action_id: `breakglass:${REQUEST_ID}:approve` }], response_url: 'https://hooks.slack.test/x' } },
      { SLACK_APPROVER_IDS: 'U-ALLOWED' },
      () => state
    );
    assert.equal(result[0].json.outcome, 'claimed');
    assert.equal(state.requests[REQUEST_ID].status, 'processing');
    assert.match(result[0].json.githubComment, /APPROVED/);
    assert.equal(result[0].json.slackUpdate.replace_original, true);
    assert.equal(result[0].json.responseUrl, 'https://hooks.slack.test/x');
  });
});
