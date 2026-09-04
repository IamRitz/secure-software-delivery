import { createPublicKey, verify } from 'node:crypto';
import { Buffer } from 'node:buffer';

function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function verifyDiscordSignature({
  publicKeyHex,
  signatureHex,
  timestamp,
  rawBody,
  now = Date.now(),
  toleranceSeconds = 300
}) {
  try {
    if (!/^[0-9a-f]{64}$/i.test(publicKeyHex || '')) return false;
    if (!/^[0-9a-f]{128}$/i.test(signatureHex || '')) return false;
    // Discord sends the timestamp as Unix epoch seconds. Reject anything that is
    // not numeric or is outside the tolerance window so a genuinely-signed but
    // replayed request cannot be accepted (Discord's replay-defense guidance).
    if (typeof timestamp !== 'string' || !/^\d+$/.test(timestamp)) return false;
    const sentSeconds = Number(timestamp);
    const nowSeconds = Math.floor((now instanceof Date ? now.getTime() : now) / 1000);
    if (!Number.isFinite(sentSeconds) || Math.abs(nowSeconds - sentSeconds) > toleranceSeconds) {
      return false;
    }
    const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '');
    const keyObject = createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: base64url(Buffer.from(publicKeyHex, 'hex'))
      },
      format: 'jwk'
    });
    return verify(
      null,
      Buffer.concat([Buffer.from(timestamp, 'utf8'), body]),
      keyObject,
      Buffer.from(signatureHex, 'hex')
    );
  } catch {
    return false;
  }
}

export function claimDiscordDecision({ interaction, requests, authorizedUserIds, now = new Date() }) {
  if (interaction?.type !== 3) return { outcome: 'ignored', reason: 'not a component interaction' };
  const match = /^breakglass:([0-9a-f-]{36}):(approve|deny)$/.exec(
    interaction.data?.custom_id || ''
  );
  if (!match) return { outcome: 'rejected', reason: 'invalid component identifier' };
  const [, requestId, action] = match;
  const user = interaction.member?.user || interaction.user;
  if (!user?.id) return { outcome: 'rejected', reason: 'Discord user identity is missing' };
  if (!authorizedUserIds.has(user.id)) {
    return { outcome: 'unauthorized', requestId, userId: user.id, username: user.username };
  }
  const request = requests[requestId];
  if (!request) return { outcome: 'rejected', reason: 'unknown request', requestId };
  const nowDate = now instanceof Date ? now : new Date(now);
  if (new Date(request.expiresAt) <= nowDate) {
    if (request.status === 'pending') request.status = 'expired';
    return { outcome: 'expired', requestId };
  }
  if (request.status !== 'pending') {
    return { outcome: 'duplicate', requestId, status: request.status };
  }

  request.status = 'processing';
  request.claim = {
    decision: action === 'approve' ? 'approved' : 'denied',
    userId: user.id,
    username: user.global_name || user.username,
    claimedAt: nowDate.toISOString()
  };
  return { outcome: 'claimed', requestId, request };
}
