import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { describe, it } from 'node:test';
import request from 'supertest';

import { createBreakGlassApp } from '../server/break-glass/app.mjs';
import { createMemoryStore } from '../server/break-glass/store.mjs';

const CLOCK = new Date('2026-09-06T00:00:00.000Z');
const SHARED_SECRET = 'test-shared-secret';
const SIGNING_SECRET = 'test-signing-secret';

function baseConfig(overrides = {}) {
  return {
    sharedSecret: SHARED_SECRET,
    signingSecret: SIGNING_SECRET,
    botToken: 'xoxb-test',
    githubToken: 'ghp-test',
    slackChannelId: 'C-DEMO',
    approverIds: new Set(['U-APPROVER']),
    defaultTimeoutSeconds: 900,
    minTimeoutSeconds: 60,
    maxTimeoutSeconds: 3600,
    ...overrides
  };
}

function fakeSlack() {
  const calls = { postMessage: [], update: [], respond: [] };
  return {
    calls,
    postMessage: async (m) => {
      calls.postMessage.push(m);
      return { ok: true, ts: '1725400000.0001', channel: 'C-DEMO' };
    },
    update: async (m) => {
      calls.update.push(m);
      return { ok: true };
    },
    respond: async (url, m) => {
      calls.respond.push({ url, message: m });
    }
  };
}

function fakeGithub() {
  const calls = [];
  return { calls, postComment: async (repo, pr, body) => calls.push({ repo, pr, body }) };
}

function makeApp(overrides = {}) {
  const store = overrides.store || createMemoryStore();
  const slack = overrides.slack || fakeSlack();
  const github = overrides.github || fakeGithub();
  let handled;
  const app = createBreakGlassApp({
    config: baseConfig(overrides.config),
    store,
    slack,
    github,
    now: () => CLOCK,
    onInteractionHandled: (promise) => {
      handled = promise;
    }
  });
  return { app, store, slack, github, waitForInteraction: () => handled };
}

const validPayload = {
  schemaVersion: 1,
  gateDigest: 'a'.repeat(64),
  timeoutSeconds: 900,
  context: { repository: 'owner/repo', commitSha: 'abcdef123456', pullRequest: '12' },
  findings: [{ source: 'semgrep', id: 'demo.rule', action: 'BLOCK', policyRule: 'sast.high_new', reason: 'new high finding' }]
};

function signedInteraction(interaction, { timestamp, secret = SIGNING_SECRET } = {}) {
  const ts = timestamp ?? String(Math.floor(CLOCK.getTime() / 1000));
  const rawBody = `payload=${encodeURIComponent(JSON.stringify(interaction))}`;
  const signature = `v0=${createHmac('sha256', secret).update(`v0:${ts}:${rawBody}`).digest('hex')}`;
  return { rawBody, ts, signature };
}

function blockAction({ requestId, action = 'approve', userId = 'U-APPROVER' }) {
  return {
    type: 'block_actions',
    user: { id: userId, username: 'approver' },
    actions: [{ action_id: `breakglass:${requestId}:${action}` }],
    response_url: 'https://hooks.slack.test/actions/xyz'
  };
}

describe('break-glass service — shared-secret auth', () => {
  it('rejects notify with a missing or wrong token', async () => {
    const { app } = makeApp();
    assert.equal((await request(app).post('/break-glass/notify').send(validPayload)).status, 401);
    assert.equal(
      (await request(app).post('/break-glass/notify').set('x-break-glass-token', 'nope').send(validPayload)).status,
      401
    );
  });

  it('rejects status without the token', async () => {
    const { app } = makeApp();
    assert.equal((await request(app).get('/break-glass/status?requestId=x')).status, 401);
  });
});

describe('break-glass service — notify', () => {
  it('stores a pending request and posts the Slack message', async () => {
    const { app, store, slack } = makeApp();
    const res = await request(app)
      .post('/break-glass/notify')
      .set('x-break-glass-token', SHARED_SECRET)
      .set('content-type', 'application/json')
      .send(JSON.stringify(validPayload));

    assert.equal(res.status, 201);
    assert.equal(res.body.status, 'pending');
    assert.match(res.body.requestId, /^[0-9a-f-]{36}$/);
    assert.equal(res.body.gateDigest, validPayload.gateDigest);
    assert.ok(res.body.createdAt && res.body.expiresAt);

    assert.equal(slack.calls.postMessage.length, 1);
    const stored = store.get(res.body.requestId);
    assert.equal(stored.status, 'pending');
    assert.deepEqual(stored.slack, { channel: 'C-DEMO', ts: '1725400000.0001' });
    // Approve/Deny buttons carry the request id.
    const actions = slack.calls.postMessage[0].blocks.find((b) => b.type === 'actions');
    assert.equal(actions.elements[0].action_id, `breakglass:${res.body.requestId}:approve`);
  });

  it('rejects a non-overridable finding payload with 400', async () => {
    const { app } = makeApp();
    const bad = { ...validPayload, findings: [{ action: 'BLOCK', policyRule: 'secrets.verified' }] };
    const res = await request(app)
      .post('/break-glass/notify')
      .set('x-break-glass-token', SHARED_SECRET)
      .send(bad);
    assert.equal(res.status, 400);
  });

  it('fails closed and rolls back the request when Slack rejects', async () => {
    const slack = fakeSlack();
    slack.postMessage = async () => {
      throw new Error('not_in_channel');
    };
    const { app, store } = makeApp({ slack });
    const res = await request(app)
      .post('/break-glass/notify')
      .set('x-break-glass-token', SHARED_SECRET)
      .send(validPayload);
    assert.equal(res.status, 502);
    assert.equal(Object.keys(store.all()).length, 0);
  });
});

describe('break-glass service — status', () => {
  it('returns 404 for an unknown request and the poll shape for a known one', async () => {
    const { app, store } = makeApp();
    assert.equal((await request(app).get('/break-glass/status?requestId=nope').set('x-break-glass-token', SHARED_SECRET)).status, 404);

    await store.update((requests) => {
      requests['req-1'] = {
        requestId: 'req-1',
        gateDigest: 'digest-1',
        status: 'pending',
        createdAt: '2026-09-06T00:00:00.000Z',
        expiresAt: '2999-01-01T00:00:00.000Z'
      };
    });
    const res = await request(app).get('/break-glass/status?requestId=req-1').set('x-break-glass-token', SHARED_SECRET);
    assert.equal(res.status, 200);
    assert.equal(res.body.requestId, 'req-1');
    assert.equal(res.body.gateDigest, 'digest-1');
    assert.equal(res.body.status, 'pending');
    assert.equal(res.body.approver, null);
  });

  it('marks an elapsed pending request expired', async () => {
    const { app, store } = makeApp();
    await store.update((requests) => {
      requests['req-2'] = { requestId: 'req-2', gateDigest: 'd', status: 'pending', createdAt: 'x', expiresAt: '2000-01-01T00:00:00.000Z' };
    });
    const res = await request(app).get('/break-glass/status?requestId=req-2').set('x-break-glass-token', SHARED_SECRET);
    assert.equal(res.body.status, 'expired');
  });
});

describe('break-glass service — Slack interactions', () => {
  async function seedPending(store, requestId) {
    await store.update((requests) => {
      requests[requestId] = {
        requestId,
        gateDigest: 'abc123',
        status: 'pending',
        createdAt: CLOCK.toISOString(),
        expiresAt: '2999-01-01T00:00:00.000Z',
        context: { repository: 'owner/repo', pullRequest: '12', commitSha: 'abcdef' },
        findings: [{ policyRule: 'sast.high_new', id: 'demo.rule', reason: 'new' }],
        slack: { channel: 'C-DEMO', ts: '1.1' }
      };
    });
  }

  it('rejects a tampered signature with 401 (raw body reaches verification intact)', async () => {
    const { app } = makeApp();
    const requestId = '11111111-1111-4111-8111-111111111111';
    const { rawBody, ts } = signedInteraction(blockAction({ requestId }));
    const res = await request(app)
      .post('/slack/interactions')
      .set('x-slack-signature', `v0=${'0'.repeat(64)}`)
      .set('x-slack-request-timestamp', ts)
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(rawBody);
    assert.equal(res.status, 401);
  });

  it('accepts a genuinely signed approval end to end', async () => {
    const { app, store, slack, github, waitForInteraction } = makeApp();
    const requestId = '11111111-1111-4111-8111-111111111111';
    await seedPending(store, requestId);
    const { rawBody, ts, signature } = signedInteraction(blockAction({ requestId, action: 'approve' }));

    const res = await request(app)
      .post('/slack/interactions')
      .set('x-slack-signature', signature)
      .set('x-slack-request-timestamp', ts)
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(rawBody);
    assert.equal(res.status, 200);

    await waitForInteraction();
    const stored = store.get(requestId);
    assert.equal(stored.status, 'approved');
    assert.equal(stored.approver.id, 'U-APPROVER');
    assert.equal(slack.calls.update.length, 1);
    assert.equal(github.calls.length, 1);
    assert.match(github.calls[0].body, /APPROVED/);
    assert.equal(github.calls[0].pr, '12');
  });

  it('leaves state pending and replies ephemerally for an unauthorized click', async () => {
    const { app, store, slack, github, waitForInteraction } = makeApp();
    const requestId = '11111111-1111-4111-8111-111111111111';
    await seedPending(store, requestId);
    const { rawBody, ts, signature } = signedInteraction(blockAction({ requestId, userId: 'U-INTRUDER' }));

    const res = await request(app)
      .post('/slack/interactions')
      .set('x-slack-signature', signature)
      .set('x-slack-request-timestamp', ts)
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(rawBody);
    assert.equal(res.status, 200);

    await waitForInteraction();
    assert.equal(store.get(requestId).status, 'pending');
    assert.equal(store.get(requestId).claim, undefined);
    assert.equal(github.calls.length, 0);
    assert.equal(slack.calls.update.length, 0);
    assert.equal(slack.calls.respond.length, 1);
    assert.match(slack.calls.respond[0].message.text, /not an authorized/);
  });
});
