import { parseApproverIds } from '../../security/scripts/slack-authorize.mjs';

// Break-glass is only offered for these BLOCK categories — the same allowlist the
// n8n notify node enforced. Never secrets, never malicious packages, never a
// report-integrity failure.
export const ELIGIBLE_POLICY_RULES = new Set([
  'sast.critical_new',
  'sast.high_new',
  'dependencies.critical_with_fix',
  'dependencies.high_with_fix'
]);

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value === '') {
    throw new Error(`${name} is not configured`);
  }
  return value;
}

// Read every secret and setting from this service's own environment (its own
// .env — never n8n's credential store). Values are the same ones already in use.
export function loadConfig(env = process.env) {
  return {
    port: Number.parseInt(env.PORT ?? '8080', 10),
    sharedSecret: required(env, 'BREAK_GLASS_SHARED_SECRET'),
    signingSecret: required(env, 'SLACK_SIGNING_SECRET'),
    botToken: required(env, 'SLACK_BOT_TOKEN'),
    githubToken: required(env, 'GITHUB_TOKEN'),
    slackChannelId: required(env, 'SLACK_CHANNEL_ID'),
    // Flat allowlist, ported exactly as it works today. Per-repo mapping is a
    // separate follow-up and deliberately not implemented here.
    approverIds: parseApproverIds(env.SLACK_APPROVER_IDS),
    defaultTimeoutSeconds: 900,
    minTimeoutSeconds: 60,
    maxTimeoutSeconds: 3600
  };
}
