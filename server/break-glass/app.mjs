// Standalone break-glass approval service — replaces the n8n Slack workflow.
//
// NOTE: at this scale it co-locates in this app's repo. A future multi-repo
// rollout would likely move it to shared infrastructure rather than living
// inside one application's repo.
//
// The three reusable modules below are imported verbatim — the whole point of
// extracting them earlier was that they carry zero n8n coupling.
import { timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import express from 'express';

import {
  verifySlackSignature,
  parseSlackInteraction,
  extractSlackDecision
} from '../../security/scripts/slack-interaction-verify.mjs';
import { authorizeSlackInteraction } from '../../security/scripts/slack-authorize.mjs';
import {
  claimDecision,
  finalizeDecision,
  buildAuditComment
} from '../../security/scripts/break-glass-decision.mjs';
import { ELIGIBLE_POLICY_RULES } from './config.mjs';
import { buildApprovalMessage, buildDecisionUpdate, ephemeral } from './messages.mjs';

const GATE_DIGEST = /^[a-f0-9]{64}$/i;

function timingSafeEqualString(a, b) {
  const bufferA = Buffer.from(String(a), 'utf8');
  const bufferB = Buffer.from(String(b), 'utf8');
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

// Collect the raw request body ourselves. We never register a JSON/urlencoded
// body parser, so the exact bytes Slack signed reach signature verification
// unchanged — the raw-body discipline the n8n version relied on.
function captureRawBody(req, _res, next) {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    req.rawBody = Buffer.concat(chunks);
    next();
  });
  req.on('error', next);
}

function validateNotifyPayload(payload) {
  if (!payload || payload.schemaVersion !== 1) throw new Error('unsupported schema');
  if (!Array.isArray(payload.findings) || payload.findings.length === 0) {
    throw new Error('invalid or empty finding payload');
  }
  if (!payload.findings.every((f) => f.action === 'BLOCK' && ELIGIBLE_POLICY_RULES.has(f.policyRule))) {
    throw new Error('payload contains a non-overridable finding');
  }
  if (!GATE_DIGEST.test(payload.gateDigest || '')) throw new Error('invalid gate digest');
  const context = payload.context;
  if (!context || typeof context.repository !== 'string' || !context.repository.includes('/')) {
    throw new Error('repository is required');
  }
  if (!/^\d+$/.test(String(context.pullRequest ?? ''))) throw new Error('pull request number is required');
}

export function createBreakGlassApp({
  config,
  store,
  slack,
  github,
  now = () => new Date(),
  // Tests pass a hook to await the fire-and-forget interaction processing that
  // runs after the 3-second Slack ack.
  onInteractionHandled = () => {}
}) {
  const app = express();
  app.use(captureRawBody);

  function requireSharedSecret(req, res, next) {
    const token = req.get('x-break-glass-token') || '';
    if (!timingSafeEqualString(token, config.sharedSecret)) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    return next();
  }

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  // --- CI notify -----------------------------------------------------------
  app.post('/break-glass/notify', requireSharedSecret, async (req, res) => {
    let payload;
    try {
      payload = JSON.parse(req.rawBody.toString('utf8'));
      validateNotifyPayload(payload);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    const createdAt = now();
    const timeout = Math.min(
      Math.max(Number(payload.timeoutSeconds) || config.defaultTimeoutSeconds, config.minTimeoutSeconds),
      config.maxTimeoutSeconds
    );
    const request = {
      requestId: globalThis.crypto.randomUUID(),
      gateDigest: payload.gateDigest,
      status: 'pending',
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + timeout * 1000).toISOString(),
      context: payload.context,
      findings: payload.findings
    };

    // Store the pending request before posting so a fast click can still find it,
    // then post to Slack. If Slack rejects, roll the request back and fail closed.
    await store.update((requests) => {
      requests[request.requestId] = request;
    });
    try {
      const posted = await slack.postMessage(buildApprovalMessage(request, config.slackChannelId));
      await store.update((requests) => {
        requests[request.requestId].slack = { channel: posted.channel, ts: posted.ts };
      });
    } catch (error) {
      await store.update((requests) => {
        delete requests[request.requestId];
      });
      return res.status(502).json({ error: `slack_post_failed: ${error.message}` });
    }

    return res.status(201).json({
      requestId: request.requestId,
      gateDigest: request.gateDigest,
      status: request.status,
      createdAt: request.createdAt,
      expiresAt: request.expiresAt
    });
  });

  // --- CI status poll ------------------------------------------------------
  app.get('/break-glass/status', requireSharedSecret, async (req, res) => {
    const requestId = String(req.query.requestId || '');
    const request = store.get(requestId);
    if (!request) return res.status(404).json({ error: 'unknown_request' });
    if (request.status === 'pending' && new Date(request.expiresAt) <= now()) {
      await store.update((requests) => {
        if (requests[requestId]?.status === 'pending') requests[requestId].status = 'expired';
      });
    }
    return res.json({
      requestId: request.requestId,
      gateDigest: request.gateDigest,
      status: request.status,
      createdAt: request.createdAt,
      expiresAt: request.expiresAt,
      decidedAt: request.decidedAt || null,
      approver: request.approver || null
    });
  });

  // --- Slack interactivity callback ---------------------------------------
  app.post('/slack/interactions', (req, res) => {
    const verified = verifySlackSignature({
      signingSecret: config.signingSecret,
      signature: req.get('x-slack-signature'),
      timestamp: req.get('x-slack-request-timestamp'),
      rawBody: req.rawBody,
      now: now().getTime()
    });
    if (!verified) return res.status(401).json({ error: 'invalid_request_signature' });

    let interaction;
    try {
      interaction = parseSlackInteraction(req.rawBody);
    } catch {
      return res.status(400).json({ error: 'invalid_payload' });
    }
    if (interaction.type !== 'block_actions') return res.status(200).end();

    // Ack within Slack's 3-second window, then do the work asynchronously.
    res.status(200).end();
    const handled = processInteraction(interaction).catch((error) => {
      console.error(`interaction processing error: ${error.message}`);
    });
    onInteractionHandled(handled);
  });

  async function processInteraction(interaction) {
    const decision = extractSlackDecision(interaction);
    if (!decision) {
      return slack.respond(interaction.response_url, ephemeral('Invalid or stale approval control.'));
    }
    const auth = authorizeSlackInteraction({ interaction, authorizedUserIds: config.approverIds });
    if (!auth.authorized) {
      return slack.respond(
        interaction.response_url,
        ephemeral('You are not an authorized break-glass approver.')
      );
    }

    const claim = await store.update((requests) =>
      claimDecision({
        requestId: decision.requestId,
        action: decision.action,
        userId: auth.userId,
        username: auth.username,
        requests,
        now: now()
      })
    );
    if (claim.outcome !== 'claimed') {
      const message =
        claim.outcome === 'duplicate'
          ? `This request is already ${claim.status}.`
          : claim.outcome === 'expired'
            ? 'This approval request has expired.'
            : 'Unknown or invalid approval request.';
      return slack.respond(interaction.response_url, ephemeral(message));
    }

    // Finalize the decision into stored state BEFORE the side effects, so a
    // transient Slack/GitHub failure can never strand a valid decision.
    await store.update((requests) =>
      finalizeDecision({ request: requests[decision.requestId], userId: auth.userId, now: now() })
    );
    const request = store.get(decision.requestId);

    const results = await Promise.allSettled([
      slack.update(buildDecisionUpdate(request)),
      github.postComment(request.context.repository, request.context.pullRequest, buildAuditComment(request))
    ]);
    for (const result of results) {
      if (result.status === 'rejected') console.error(`break-glass side effect failed: ${result.reason}`);
    }
    return undefined;
  }

  return app;
}
