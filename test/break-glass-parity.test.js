// Parity: the n8n Slack workflow (its actual Code-node JavaScript, executed from
// the committed workflow JSON) and the Lambda broker must reach the SAME verdict
// for the same input. Outcome labels may differ (n8n says "rejected" for an
// unknown request where the shared authorize module says "unauthorized"); what is
// compared is what matters to the gate and the audit trail: the HTTP response to
// Slack, the resulting stored status, the recorded approver, and the CI poll view.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

import { parseApproverMapFromEnv } from '../security/scripts/slack-authorize.mjs';
import { createBroker } from '../server/break-glass/lambda/broker.mjs';
import { createDynamoStore } from '../server/break-glass/lambda/dynamodb-store.mjs';
import { createCiHandler, createInteractionsHandler } from '../server/break-glass/lambda/handlers.mjs';
import { createFakeDynamo } from './helpers/fake-dynamodb.mjs';

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const require = createRequire(import.meta.url);
const workflow = JSON.parse(await readFile('n8n/workflows/slack-break-glass-workflow.json', 'utf8'));
const code = (name) => workflow.nodes.find((node) => node.name === name).parameters.jsCode;

const SIGNING_SECRET = 'parity-signing-secret';
const REPO_A = 'owner/repo-a';
const REPO_B = 'owner/repo-b';
const APPROVERS = JSON.stringify({ [REPO_A]: ['U-A'], [REPO_B]: ['U-B'] });

// ---- n8n path: executes the workflow's Code nodes in node order -------------
function n8nPath({ approverEnv = APPROVERS } = {}) {
  const staticData = {};
  const $env = { SLACK_SIGNING_SECRET: SIGNING_SECRET, SLACK_APPROVER_IDS_BY_REPO: approverEnv, SLACK_CHANNEL_ID: 'C-TEST' };
  const run = (name, bindings) => {
    const names = ['require', '$json', '$input', '$env', '$getWorkflowStaticData', '$', 'URLSearchParams'];
    const fn = new AsyncFunction(...names, code(name));
    return fn.call(
      { helpers: { getBinaryDataBuffer: async () => { throw new Error('no binary'); } } },
      require,
      bindings.$json,
      bindings.$input,
      $env,
      () => staticData,
      bindings.$,
      undefined
    );
  };
  const nodeRef = (json) => () => ({ first: () => ({ json }) });

  return {
    staticData,
    async notify(payload) {
      try {
        const [validated] = await run('Validate and Store Pending Request', { $json: { body: payload } });
        const [stored] = await run('Store Slack Message Reference', {
          $json: { ok: true, channel: 'C-TEST', ts: '1.1' },
          $: nodeRef(validated.json)
        });
        return { accepted: true, requestId: stored.json.requestId, request: staticData.requests[stored.json.requestId] };
      } catch {
        return { accepted: false };
      }
    },
    async status(requestId) {
      const [out] = await run('Read Request Status', { $json: { query: { requestId } } });
      return { code: out.json.responseCode, body: out.json.responseBody };
    },
    async interact({ headers, rawBody }) {
      const input = { first: () => ({ json: { headers }, binary: { data: { data: Buffer.from(rawBody).toString('base64') } } }) };
      const [verified] = await run('Verify Slack Signature', { $input: input });
      if (!verified.json.processComponent) return { code: verified.json.responseCode };
      const [claimed] = await run('Authorize and Claim Decision', { $json: verified.json });
      if (claimed.json.outcome === 'claimed') {
        await run('Finalize Request State', { $: nodeRef(claimed.json) });
      }
      return { code: verified.json.responseCode };
    },
    expire(requestId) {
      staticData.requests[requestId].expiresAt = new Date(Date.now() - 1000).toISOString();
    }
  };
}

// ---- Lambda path --------------------------------------------------------------
function lambdaPath({ approverEnv = APPROVERS } = {}) {
  const dynamo = createFakeDynamo();
  const broker = createBroker({
    store: createDynamoStore({ client: dynamo.client, tableName: 't' }),
    slack: { postMessage: async () => ({ ok: true, channel: 'C-TEST', ts: '1.1' }), update: async () => {}, respond: async () => {} },
    github: { postComment: async () => {} },
    signingSecret: SIGNING_SECRET,
    approverMap: parseApproverMapFromEnv(approverEnv),
    slackChannelId: 'C-TEST',
    log: () => {}
  });
  const ci = createCiHandler({ getBroker: async () => broker });
  const interactions = createInteractionsHandler({ getBroker: async () => broker, enqueue: async () => {} });
  return {
    async notify(payload) {
      const result = await ci({ action: 'notify', payload });
      if (!result.ok) return { accepted: false };
      const request = await broker.status(result.body.requestId);
      return { accepted: true, requestId: result.body.requestId, request: request.body };
    },
    async status(requestId) {
      const result = await ci({ action: 'status', requestId });
      return { code: result.statusCode, body: result.ok ? result.body : { error: result.error } };
    },
    async interact({ headers, rawBody }) {
      const response = await interactions({
        requestContext: { http: { method: 'POST' } },
        headers,
        body: rawBody,
        isBase64Encoded: false
      });
      return { code: response.statusCode };
    },
    expire(requestId) {
      const item = dynamo.table.get(requestId);
      const past = new Date(Date.now() - 1000).toISOString();
      const doc = JSON.parse(item.doc.S);
      doc.expiresAt = past;
      item.expiresAt = { S: past };
      item.doc = { S: JSON.stringify(doc) };
    }
  };
}

// ---- shared inputs --------------------------------------------------------------
const payload = (overrides = {}) => ({
  schemaVersion: 1,
  gateDigest: 'b'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: REPO_A, commitSha: 'abcdef1234567890', pullRequest: '51' },
  findings: [{ id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high' }],
  ...overrides
});

function signed(body, { secret = SIGNING_SECRET, ageSeconds = 0 } = {}) {
  const ts = String(Math.floor(Date.now() / 1000) - ageSeconds);
  const signature = `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}`;
  return { headers: { 'x-slack-signature': signature, 'x-slack-request-timestamp': ts }, rawBody: body };
}
const clickBody = (requestId, { userId = 'U-A', action = 'approve', type = 'block_actions' } = {}) =>
  `payload=${encodeURIComponent(JSON.stringify({
    type,
    user: { id: userId, username: `user-${userId}` },
    actions: [{ action_id: `breakglass:${requestId}:${action}` }],
    response_url: 'https://hooks.slack.com/actions/T/1/x'
  }))}`;

// A verdict is what the gate and the audit trail observe.
async function verdict(path, requestId) {
  const status = await path.status(requestId);
  return { code: status.code, status: status.body.status, approverId: status.body.approver?.id ?? null };
}

// Each scenario receives a path and returns its observable result.
const scenarios = {
  'authorized approve': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId)));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'authorized deny': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId, { action: 'deny' })));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'unauthorized user': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId, { userId: 'U-STRANGER' })));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'repo-B approver on a repo-A request': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId, { userId: 'U-B' })));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'repo-B approver on a repo-B request': async (p) => {
    const { requestId } = await p.notify(payload({ context: { ...payload().context, repository: REPO_B } }));
    const click = await p.interact(signed(clickBody(requestId, { userId: 'U-B' })));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'approve then deny (second click)': async (p) => {
    const { requestId } = await p.notify(payload());
    await p.interact(signed(clickBody(requestId)));
    const second = await p.interact(signed(clickBody(requestId, { action: 'deny' })));
    return { click: second.code, ...(await verdict(p, requestId)) };
  },
  'click after expiry': async (p) => {
    const { requestId } = await p.notify(payload());
    p.expire(requestId);
    const click = await p.interact(signed(clickBody(requestId)));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'timeout with no click': async (p) => {
    const { requestId } = await p.notify(payload());
    p.expire(requestId);
    return verdict(p, requestId);
  },
  'tampered body': async (p) => {
    const { requestId } = await p.notify(payload());
    const genuine = signed(clickBody(requestId, { action: 'deny' }));
    const click = await p.interact({ ...genuine, rawBody: clickBody(requestId) });
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'stale timestamp': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId), { ageSeconds: 301 }));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'wrong signing secret': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId), { secret: 'attacker' }));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'signed malformed payload': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed('payload=%7Bbroken'));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'signed non-button interaction': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody(requestId, { type: 'view_submission' })));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'invalid control id': async (p) => {
    const { requestId } = await p.notify(payload());
    const click = await p.interact(signed(clickBody('not-a-uuid')));
    return { click: click.code, ...(await verdict(p, requestId)) };
  },
  'unknown request status': async (p) => ({ code: (await p.status('00000000-0000-4000-8000-000000000000')).code }),
  'notify: verified secret finding': async (p) =>
    p.notify(payload({ findings: [{ id: 's', action: 'BLOCK', policyRule: 'secrets.verified' }] })).then((r) => r.accepted),
  'notify: malicious package': async (p) =>
    p.notify(payload({ findings: [{ id: 'm', action: 'BLOCK', policyRule: 'dependencies.malicious_package' }] })).then((r) => r.accepted),
  'notify: mixed eligible + hard block': async (p) =>
    p.notify(payload({ findings: [...payload().findings, { id: 'i', action: 'BLOCK', policyRule: 'integrity.untrusted' }] })).then((r) => r.accepted),
  'notify: missing pull request': async (p) =>
    p.notify(payload({ context: { repository: REPO_A, commitSha: 'abc' } })).then((r) => r.accepted),
  'notify: bad gate digest': async (p) => p.notify(payload({ gateDigest: 'xyz' })).then((r) => r.accepted),
  'notify: empty findings': async (p) => p.notify(payload({ findings: [] })).then((r) => r.accepted),
  'notify: timeout clamps (5s -> 60s, 99999s -> 3600s)': async (p) => {
    const spans = [];
    for (const timeoutSeconds of [5, 99999, undefined]) {
      const { request } = await p.notify(payload({ timeoutSeconds }));
      spans.push((new Date(request.expiresAt) - new Date(request.createdAt)) / 1000);
    }
    return spans;
  }
};

describe('n8n workflow vs Lambda broker: identical verdicts on identical input', () => {
  for (const [name, scenario] of Object.entries(scenarios)) {
    it(name, async () => {
      const n8n = await scenario(n8nPath());
      const lambda = await scenario(lambdaPath());
      assert.deepEqual(lambda, n8n);
    });
  }

  it('malformed approver map authorizes nobody on both paths', async () => {
    const run = async (p) => {
      const { requestId } = await p.notify(payload());
      await p.interact(signed(clickBody(requestId)));
      return verdict(p, requestId);
    };
    const n8n = await run(n8nPath({ approverEnv: '{not json' }));
    const lambda = await run(lambdaPath({ approverEnv: '{not json' }));
    assert.deepEqual(lambda, n8n);
    assert.equal(lambda.status, 'pending');
  });

  it('pins the expected verdicts so parity cannot pass by both paths being wrong', async () => {
    const lambda = lambdaPath();
    assert.deepEqual(await scenarios['authorized approve'](lambda), { click: 200, code: 200, status: 'approved', approverId: 'U-A' });
    assert.deepEqual(await scenarios['unauthorized user'](lambda), { click: 200, code: 200, status: 'pending', approverId: null });
    assert.deepEqual(await scenarios['repo-B approver on a repo-A request'](lambda), { click: 200, code: 200, status: 'pending', approverId: null });
    assert.deepEqual(await scenarios['timeout with no click'](lambda), { code: 200, status: 'expired', approverId: null });
    assert.equal((await scenarios['tampered body'](lambda)).click, 401);
    assert.equal((await scenarios['signed malformed payload'](lambda)).click, 400);
    assert.equal(await scenarios['notify: verified secret finding'](lambda), false);
    assert.deepEqual(await scenarios['notify: timeout clamps (5s -> 60s, 99999s -> 3600s)'](lambda), [60, 3600, 900]);
  });
});
