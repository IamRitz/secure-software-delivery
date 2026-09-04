import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  notifyBreakGlass,
  validateEligibleGate
} from '../security/scripts/break-glass-notify.mjs';
import { pollBreakGlass } from '../security/scripts/break-glass-poll.mjs';
import {
  claimDiscordDecision,
  verifyDiscordSignature
} from '../security/scripts/discord-interactions.mjs';

const ELIGIBLE_FINDING = {
  source: 'semgrep',
  id: 'demo.rule',
  action: 'BLOCK',
  policyRule: 'sast.high_new',
  reason: 'high Semgrep finding is new'
};

function gateWith({ eligible = [ELIGIBLE_FINDING], ineligible = [] } = {}) {
  return {
    verdict: 'BLOCK',
    summary: { block: eligible.length + ineligible.length, exception: 0, log: 0 },
    findings: [...eligible, ...ineligible],
    breakGlass: {
      eligible: eligible.length > 0 && ineligible.length === 0,
      eligibleFindings: eligible,
      ineligibleFindings: ineligible
    }
  };
}

function jsonResponse(body, status = 200) {
  return new globalThis.Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('break-glass CI flow', () => {
  it('allows an eligible request only after an approved status', async () => {
    const gate = gateWith();
    const request = await notifyBreakGlass({
      gate,
      endpoint: 'https://n8n.example.test/webhook/break-glass/notify',
      sharedSecret: 'test-only',
      context: { repository: 'owner/repo', commitSha: 'abc123' },
      fetchImpl: async () =>
        jsonResponse({
          requestId: '11111111-1111-4111-8111-111111111111',
          status: 'pending',
          createdAt: '2026-09-04T00:00:00.000Z',
          expiresAt: '2026-09-04T00:15:00.000Z'
        })
    });
    const decision = await pollBreakGlass({
      request,
      endpoint: 'https://n8n.example.test/webhook/break-glass/status',
      sharedSecret: 'test-only',
      fetchImpl: async () =>
        jsonResponse({
          requestId: request.requestId,
          gateDigest: request.gateDigest,
          status: 'approved',
          approver: { id: '123', username: 'real-user' }
        })
    });

    assert.equal(decision.status, 'approved');
    assert.equal(decision.approver.username, 'real-user');
  });

  it('keeps an eligible denied decision blocked', async () => {
    const request = { requestId: 'request-1', gateDigest: 'digest-1' };
    const decision = await pollBreakGlass({
      request,
      endpoint: 'https://n8n.example.test/webhook/break-glass/status',
      sharedSecret: 'test-only',
      fetchImpl: async () =>
        jsonResponse({ ...request, status: 'denied', approver: { id: '123', username: 'denier' } })
    });
    assert.equal(decision.status, 'denied');
  });

  it('fails closed when an eligible request times out', async () => {
    const request = { requestId: 'request-1', gateDigest: 'digest-1' };
    let clock = 0;
    const decision = await pollBreakGlass({
      request,
      endpoint: 'https://n8n.example.test/webhook/break-glass/status',
      sharedSecret: 'test-only',
      timeoutSeconds: 2,
      intervalMilliseconds: 1000,
      now: () => clock,
      sleep: async (milliseconds) => {
        clock += milliseconds;
      },
      fetchImpl: async () => jsonResponse({ ...request, status: 'pending' })
    });
    assert.equal(decision.status, 'timeout');
  });

  it('never calls n8n for verified-secret or malicious-package hard blocks', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      return jsonResponse({});
    };
    const hardBlocks = [
      { source: 'trufflehog', id: 'AWS', action: 'BLOCK', policyRule: 'secrets.verified' },
      {
        source: 'osv-scanner',
        id: 'MAL-2026-DEMO',
        action: 'BLOCK',
        policyRule: 'dependencies.malicious_package'
      }
    ];

    for (const finding of hardBlocks) {
      await assert.rejects(
        notifyBreakGlass({
          gate: gateWith({ eligible: [], ineligible: [finding] }),
          endpoint: 'https://n8n.example.test/webhook/break-glass/notify',
          sharedSecret: 'test-only',
          context: { repository: 'owner/repo', commitSha: 'abc123' },
          fetchImpl
        }),
        /no overridable finding set/
      );
    }
    assert.equal(calls, 0);
  });

  it('rejects a tampered Discord signature', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    const publicKeyHex = Buffer.from(publicJwk.x, 'base64url').toString('hex');
    const timestamp = '1725400000';
    const now = Number(timestamp) * 1000;
    const rawBody = Buffer.from('{"type":1}');
    const signatureHex = sign(
      null,
      Buffer.concat([Buffer.from(timestamp), rawBody]),
      privateKey
    ).toString('hex');

    // Accepts a genuinely valid, correctly-signed request against a real keypair.
    assert.equal(
      verifyDiscordSignature({ publicKeyHex, signatureHex, timestamp, rawBody, now }),
      true
    );
    // Rejects a request whose body no longer matches the signed bytes.
    assert.equal(
      verifyDiscordSignature({
        publicKeyHex,
        signatureHex,
        timestamp,
        rawBody: Buffer.from('{"type":3}'),
        now
      }),
      false
    );
    // Replay defense: a genuinely-signed but stale request is rejected.
    assert.equal(
      verifyDiscordSignature({
        publicKeyHex,
        signatureHex,
        timestamp,
        rawBody,
        now: now + 601_000
      }),
      false
    );
  });

  it('does not let an unauthorized Discord user claim approval', () => {
    const requestId = '11111111-1111-4111-8111-111111111111';
    const requests = {
      [requestId]: {
        status: 'pending',
        expiresAt: '2026-09-04T01:00:00.000Z'
      }
    };
    const result = claimDiscordDecision({
      interaction: {
        type: 3,
        data: { custom_id: `breakglass:${requestId}:approve` },
        member: { user: { id: 'unauthorized-id', username: 'intruder' } }
      },
      requests,
      authorizedUserIds: new Set(['authorized-id']),
      now: new Date('2026-09-04T00:00:00.000Z')
    });

    assert.equal(result.outcome, 'unauthorized');
    assert.equal(requests[requestId].status, 'pending');
    assert.equal(requests[requestId].claim, undefined);
  });

  it('validates eligibility without accepting arbitrary dependency rules', () => {
    assert.equal(validateEligibleGate(gateWith()).length, 1);
    assert.throws(
      () =>
        validateEligibleGate(
          gateWith({
            eligible: [
              {
                action: 'BLOCK',
                policyRule: 'dependencies.malicious_package'
              }
            ]
          })
        ),
      /not break-glass eligible/
    );
  });
});
