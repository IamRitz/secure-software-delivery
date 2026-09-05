// Generator for the Slack break-glass n8n workflow. Code-node bodies are kept as
// arrays of source lines (joined with newlines) so JSON.stringify handles all
// escaping — hand-escaping multi-line JS inside JSON is error-prone. Run:
//   node n8n/build-slack-workflow.mjs
// It writes n8n/workflows/slack-break-glass-workflow.json.
//
// Mirrors the Discord workflow but Slack-specific: HMAC-SHA256 verification
// (signing secret from $env.SLACK_SIGNING_SECRET, never hardcoded), urlencoded
// `payload` parsing after raw-body verification, Block Kit buttons, and message
// updates via the interaction response_url. Finalize-before-side-effects order
// is preserved. Discord's workflow is untouched; this is a separate workflow
// with its own /dev/slack/* routes and its own request state.
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';

const SHARED = { httpHeaderAuth: { id: 'REPLACE_SHARED_SECRET_CREDENTIAL_ID', name: 'Break Glass Shared Secret' } };
const GITHUB = { httpHeaderAuth: { id: 'REPLACE_GITHUB_PAT_CREDENTIAL_ID', name: 'GitHub Break Glass PAT' } };
const SLACKBOT = { httpHeaderAuth: { id: 'REPLACE_SLACK_BOT_CREDENTIAL_ID', name: 'Slack Bot Token' } };

const validateStore = [
  "const crypto = require('crypto');",
  "const payload = $json.body;",
  "const allowed = new Set(['sast.critical_new','sast.high_new','dependencies.critical_with_fix','dependencies.high_with_fix']);",
  "if (!payload || payload.schemaVersion !== 1 || !Array.isArray(payload.findings) || payload.findings.length === 0) throw new Error('invalid or empty finding payload');",
  "if (!payload.findings.every(f => f.action === 'BLOCK' && allowed.has(f.policyRule))) throw new Error('payload contains a non-overridable finding');",
  "if (!/^[a-f0-9]{64}$/i.test(payload.gateDigest || '')) throw new Error('invalid gate digest');",
  "if (!payload.context || !payload.context.repository || !payload.context.repository.includes('/') || !/^\\d+$/.test(String(payload.context.pullRequest || ''))) throw new Error('repository and pull request are required');",
  "const timeout = Math.min(Math.max(Number(payload.timeoutSeconds) || 900, 60), 3600);",
  "const now = new Date();",
  "const requestId = crypto.randomUUID();",
  "const request = { requestId: requestId, gateDigest: payload.gateDigest, status: 'pending', createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + timeout * 1000).toISOString(), context: payload.context, findings: payload.findings };",
  "const state = $getWorkflowStaticData('global');",
  "if (!state.requests) state.requests = {};",
  "state.requests[requestId] = request;",
  "const lines = payload.findings.map(f => '- ' + f.policyRule + ': ' + f.id + ' - ' + f.reason);",
  "const channel = $env.SLACK_CHANNEL_ID;",
  "if (!channel) throw new Error('SLACK_CHANNEL_ID is not configured');",
  "const slackMessage = { channel: channel, text: 'Break-glass security exception requested', blocks: [",
  "  { type: 'header', text: { type: 'plain_text', text: 'Break-glass security exception requested' } },",
  "  { type: 'section', text: { type: 'mrkdwn', text: lines.join('\\n').slice(0, 2900) } },",
  "  { type: 'section', fields: [",
  "    { type: 'mrkdwn', text: '*Repository*\\n' + payload.context.repository },",
  "    { type: 'mrkdwn', text: '*Pull request*\\n#' + payload.context.pullRequest },",
  "    { type: 'mrkdwn', text: '*Commit*\\n' + String(payload.context.commitSha).slice(0, 12) },",
  "    { type: 'mrkdwn', text: '*Expires*\\n' + request.expiresAt }",
  "  ] },",
  "  { type: 'actions', block_id: 'breakglass:' + requestId, elements: [",
  "    { type: 'button', style: 'primary', text: { type: 'plain_text', text: 'Approve' }, action_id: 'breakglass:' + requestId + ':approve', value: 'breakglass:' + requestId + ':approve' },",
  "    { type: 'button', style: 'danger', text: { type: 'plain_text', text: 'Deny' }, action_id: 'breakglass:' + requestId + ':deny', value: 'breakglass:' + requestId + ':deny' }",
  "  ] }",
  "] };",
  "return [{ json: { request: request, slackMessage: slackMessage } }];"
].join('\n');

const storeRef = [
  "const prepared = $('Validate and Store Pending Request').first().json;",
  "const resp = $json;",
  "if (!resp || resp.ok !== true) throw new Error('Slack chat.postMessage failed: ' + ((resp && resp.error) || 'unknown'));",
  "const state = $getWorkflowStaticData('global');",
  "const request = state.requests && state.requests[prepared.request.requestId];",
  "if (!request || request.status !== 'pending') throw new Error('pending request disappeared');",
  "request.slack = { channel: resp.channel, ts: resp.ts };",
  "return [{ json: { requestId: request.requestId, status: request.status, createdAt: request.createdAt, expiresAt: request.expiresAt } }];"
].join('\n');

const readStatus = [
  "const requestId = String(($json.query && $json.query.requestId) || '');",
  "const state = $getWorkflowStaticData('global');",
  "const request = state.requests && state.requests[requestId];",
  "if (!request) return [{ json: { responseCode: 404, responseBody: { error: 'unknown_request' } } }];",
  "if (request.status === 'pending' && new Date(request.expiresAt) <= new Date()) request.status = 'expired';",
  "return [{ json: { responseCode: 200, responseBody: { requestId: request.requestId, gateDigest: request.gateDigest, status: request.status, createdAt: request.createdAt, expiresAt: request.expiresAt, decidedAt: request.decidedAt || null, approver: request.approver || null } } }];"
].join('\n');

const verify = [
  "const crypto = require('crypto');",
  "const item = $input.first();",
  "const headers = Object.fromEntries(Object.entries(item.json.headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)]));",
  "let rawBody;",
  "const encoded = item.binary && item.binary.data && item.binary.data.data;",
  "if (typeof encoded === 'string') rawBody = Buffer.from(encoded, 'base64');",
  "if (!rawBody) { try { rawBody = await this.helpers.getBinaryDataBuffer(0, 'data'); } catch (e) {} }",
  "const signature = headers['x-slack-signature'];",
  "const timestamp = headers['x-slack-request-timestamp'];",
  "const signingSecret = $env.SLACK_SIGNING_SECRET;",
  "let verified = false;",
  "try {",
  "  if (!rawBody || !signingSecret || !/^v0=[0-9a-f]{64}$/i.test(signature || '') || !/^\\d+$/.test(timestamp || '')) throw new Error('missing signature material');",
  "  if (Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > 300) throw new Error('stale timestamp');",
  "  const base = Buffer.concat([Buffer.from('v0:' + timestamp + ':', 'utf8'), rawBody]);",
  "  const expected = 'v0=' + crypto.createHmac('sha256', signingSecret).update(base).digest('hex');",
  "  const a = Buffer.from(expected, 'utf8');",
  "  const b = Buffer.from(signature, 'utf8');",
  "  verified = a.length === b.length && crypto.timingSafeEqual(a, b);",
  "} catch (e) { verified = false; }",
  "if (!verified) return [{ json: { responseCode: 401, responseBody: { error: 'invalid_request_signature' }, processComponent: false } }];",
  "let interaction;",
  "try {",
  "  const params = new URLSearchParams(rawBody.toString('utf8'));",
  "  const payloadField = params.get('payload');",
  "  if (!payloadField) throw new Error('no payload');",
  "  interaction = JSON.parse(payloadField);",
  "} catch (e) { return [{ json: { responseCode: 400, responseBody: { error: 'invalid_payload' }, processComponent: false } }]; }",
  "if (interaction.type === 'block_actions') return [{ json: { responseCode: 200, responseBody: {}, processComponent: true, interaction: interaction } }];",
  "return [{ json: { responseCode: 200, responseBody: {}, processComponent: false } }];"
].join('\n');

const claim = [
  "const interaction = $json.interaction;",
  "const control = interaction.actions && interaction.actions[0];",
  "const identifier = (control && (control.action_id || control.value)) || '';",
  "const match = /^breakglass:([0-9a-f-]{36}):(approve|deny)$/.exec(identifier);",
  "if (!match) return [{ json: { outcome: 'rejected', interaction: interaction, message: 'Invalid or stale approval control.' } }];",
  "const requestId = match[1];",
  "const action = match[2];",
  "const user = interaction.user;",
  "if (!user || !user.id) return [{ json: { outcome: 'rejected', interaction: interaction, requestId: requestId, message: 'Slack did not provide a user identity.' } }];",
  "const allowed = new Set(String($env.SLACK_APPROVER_IDS || '').split(',').map(v => v.trim()).filter(Boolean));",
  "if (!allowed.has(String(user.id))) return [{ json: { outcome: 'unauthorized', interaction: interaction, requestId: requestId, message: 'You are not an authorized break-glass approver.' } }];",
  "const state = $getWorkflowStaticData('global');",
  "const request = state.requests && state.requests[requestId];",
  "if (!request) return [{ json: { outcome: 'rejected', interaction: interaction, requestId: requestId, message: 'Unknown approval request.' } }];",
  "if (new Date(request.expiresAt) <= new Date()) { if (request.status === 'pending') request.status = 'expired'; return [{ json: { outcome: 'rejected', interaction: interaction, requestId: requestId, message: 'This approval request has expired.' } }]; }",
  "if (request.status !== 'pending') return [{ json: { outcome: 'duplicate', interaction: interaction, requestId: requestId, message: 'Request is already ' + request.status + '.' } }];",
  "request.status = 'processing';",
  "const decision = action === 'approve' ? 'approved' : 'denied';",
  "request.claim = { decision: decision, userId: String(user.id), username: user.username || user.name || String(user.id), claimedAt: new Date().toISOString() };",
  "const findingText = request.findings.map(f => f.policyRule + ': ' + f.id).join('; ');",
  "const comment = 'Break-glass decision: **' + decision.toUpperCase() + '**\\n\\nVerified Slack approver: **' + request.claim.username + '** (ID: `' + request.claim.userId + '`)\\n\\nTimestamp: ' + request.claim.claimedAt + '\\n\\nOverridden finding(s): ' + findingText + '\\n\\nGate digest: `' + request.gateDigest + '`';",
  "const slackUpdate = { replace_original: true, text: 'Break-glass ' + decision, blocks: [ { type: 'section', text: { type: 'mrkdwn', text: '*Break-glass ' + decision.toUpperCase() + '* by <@' + request.claim.userId + '>\\n' + findingText } }, { type: 'context', elements: [ { type: 'mrkdwn', text: 'Decided ' + request.claim.claimedAt + ' - gate `' + String(request.gateDigest).slice(0, 12) + '`' } ] } ] };",
  "return [{ json: { outcome: 'claimed', interaction: interaction, requestId: requestId, request: request, githubComment: comment, slackUpdate: slackUpdate, responseUrl: interaction.response_url } }];"
].join('\n');

const finalize = [
  "const claimed = $('Authorize and Claim Decision').first().json;",
  "const state = $getWorkflowStaticData('global');",
  "const request = state.requests && state.requests[claimed.requestId];",
  "if (!request || request.status !== 'processing' || !request.claim || request.claim.userId !== claimed.request.claim.userId) throw new Error('decision claim changed before finalization');",
  "request.status = request.claim.decision;",
  "request.decidedAt = new Date().toISOString();",
  "request.approver = { id: request.claim.userId, username: request.claim.username };",
  "delete request.claim;",
  "return [{ json: { requestId: request.requestId, status: request.status } }];"
].join('\n');

const codeNode = (id, name, jsCode, position) => ({
  parameters: { jsCode },
  id, name, type: 'n8n-nodes-base.code', typeVersion: 2, position
});
const respondNode = (id, name, position, responseCode = "={{ $json.responseCode }}", body = "={{ $json.responseBody }}") => ({
  parameters: { respondWith: 'json', responseBody: body, options: { responseCode } },
  id, name, type: 'n8n-nodes-base.respondToWebhook', typeVersion: 1.5, position
});

const workflow = {
  name: 'Sekure - Slack Break-Glass (DEV)',
  nodes: [
    { parameters: { httpMethod: 'POST', path: 'dev/slack/break-glass/notify', authentication: 'headerAuth', responseMode: 'responseNode', options: {} }, id: 'slack-notify-webhook', name: 'Webhook A - Slack Notify', type: 'n8n-nodes-base.webhook', typeVersion: 2.1, position: [-900, -360], webhookId: 'slack-break-glass-notify', credentials: SHARED },
    codeNode('slack-validate-store', 'Validate and Store Pending Request', validateStore, [-660, -360]),
    { parameters: { method: 'POST', url: 'https://slack.com/api/chat.postMessage', authentication: 'genericCredentialType', genericAuthType: 'httpHeaderAuth', sendBody: true, contentType: 'raw', rawContentType: 'application/json; charset=utf-8', body: '={{ JSON.stringify($json.slackMessage) }}', options: {} }, id: 'post-slack-message', name: 'Post Slack Approval Message', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [-420, -360], credentials: SLACKBOT },
    codeNode('slack-store-ref', 'Store Slack Message Reference', storeRef, [-180, -360]),
    respondNode('slack-respond-notify', 'Respond Notify', [60, -360], 201, '={{ $json }}'),

    { parameters: { path: 'dev/slack/break-glass/status', authentication: 'headerAuth', responseMode: 'responseNode', options: {} }, id: 'slack-status-webhook', name: 'Webhook C - Slack Status', type: 'n8n-nodes-base.webhook', typeVersion: 2.1, position: [-900, 360], webhookId: 'slack-break-glass-status', credentials: SHARED },
    codeNode('slack-read-status', 'Read Request Status', readStatus, [-660, 360]),
    respondNode('slack-respond-status', 'Respond Status', [-420, 360]),

    { parameters: { httpMethod: 'POST', path: 'dev/slack/interactions', responseMode: 'responseNode', options: { rawBody: true } }, id: 'slack-interaction-webhook', name: 'Webhook - Slack Interactions', type: 'n8n-nodes-base.webhook', typeVersion: 2.1, position: [-900, 0], webhookId: 'slack-interactions' },
    codeNode('slack-verify', 'Verify Slack Signature', verify, [-660, 0]),
    respondNode('slack-respond-interaction', 'Respond to Slack Immediately', [-420, 0]),
    { parameters: { conditions: { options: { caseSensitive: true, typeValidation: 'strict', version: 2 }, conditions: [{ leftValue: '={{ $json.processComponent }}', rightValue: true, operator: { type: 'boolean', operation: 'true', singleValue: true } }], combinator: 'and' }, options: {} }, id: 'slack-is-component', name: 'Is Verified Component', type: 'n8n-nodes-base.if', typeVersion: 2.2, position: [-180, 0] },
    codeNode('slack-claim', 'Authorize and Claim Decision', claim, [60, -80]),
    { parameters: { conditions: { options: { caseSensitive: true, typeValidation: 'strict', version: 2 }, conditions: [{ leftValue: '={{ $json.outcome }}', rightValue: 'claimed', operator: { type: 'string', operation: 'equals' } }], combinator: 'and' }, options: {} }, id: 'slack-decision-claimed', name: 'Decision Claimed', type: 'n8n-nodes-base.if', typeVersion: 2.2, position: [300, -80] },
    codeNode('slack-finalize', 'Finalize Request State', finalize, [540, -160]),
    { parameters: { method: 'POST', url: "={{ $('Authorize and Claim Decision').first().json.responseUrl }}", sendBody: true, contentType: 'raw', rawContentType: 'application/json', body: "={{ JSON.stringify($('Authorize and Claim Decision').first().json.slackUpdate) }}", options: {} }, id: 'slack-update-message', name: 'Update Slack Message', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [780, -160], continueOnFail: true },
    { parameters: { method: 'POST', url: "={{ 'https://api.github.com/repos/' + $('Authorize and Claim Decision').first().json.request.context.repository + '/issues/' + $('Authorize and Claim Decision').first().json.request.context.pullRequest + '/comments' }}", authentication: 'genericCredentialType', genericAuthType: 'httpHeaderAuth', sendHeaders: true, headerParameters: { parameters: [{ name: 'X-GitHub-Api-Version', value: '2022-11-28' }, { name: 'Accept', value: 'application/vnd.github+json' }] }, sendBody: true, contentType: 'raw', rawContentType: 'application/json', body: "={{ JSON.stringify({body: $('Authorize and Claim Decision').first().json.githubComment}) }}", options: {} }, id: 'slack-post-github', name: 'Post GitHub Audit Comment', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [1020, -160], continueOnFail: true, credentials: GITHUB },
    { parameters: { method: 'POST', url: '={{ $json.interaction.response_url }}', sendBody: true, contentType: 'raw', rawContentType: 'application/json', body: "={{ JSON.stringify({ response_type: 'ephemeral', replace_original: false, text: $json.message }) }}", options: {} }, id: 'slack-ack-reject', name: 'Acknowledge Rejected Click', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [540, 40] }
  ],
  connections: {
    'Webhook A - Slack Notify': { main: [[{ node: 'Validate and Store Pending Request', type: 'main', index: 0 }]] },
    'Validate and Store Pending Request': { main: [[{ node: 'Post Slack Approval Message', type: 'main', index: 0 }]] },
    'Post Slack Approval Message': { main: [[{ node: 'Store Slack Message Reference', type: 'main', index: 0 }]] },
    'Store Slack Message Reference': { main: [[{ node: 'Respond Notify', type: 'main', index: 0 }]] },
    'Webhook C - Slack Status': { main: [[{ node: 'Read Request Status', type: 'main', index: 0 }]] },
    'Read Request Status': { main: [[{ node: 'Respond Status', type: 'main', index: 0 }]] },
    'Webhook - Slack Interactions': { main: [[{ node: 'Verify Slack Signature', type: 'main', index: 0 }]] },
    'Verify Slack Signature': { main: [[{ node: 'Respond to Slack Immediately', type: 'main', index: 0 }]] },
    'Respond to Slack Immediately': { main: [[{ node: 'Is Verified Component', type: 'main', index: 0 }]] },
    'Is Verified Component': { main: [[{ node: 'Authorize and Claim Decision', type: 'main', index: 0 }], []] },
    'Authorize and Claim Decision': { main: [[{ node: 'Decision Claimed', type: 'main', index: 0 }]] },
    'Decision Claimed': { main: [[{ node: 'Finalize Request State', type: 'main', index: 0 }], [{ node: 'Acknowledge Rejected Click', type: 'main', index: 0 }]] },
    'Finalize Request State': { main: [[{ node: 'Update Slack Message', type: 'main', index: 0 }]] },
    'Update Slack Message': { main: [[{ node: 'Post GitHub Audit Comment', type: 'main', index: 0 }]] }
  },
  pinData: {},
  settings: { executionOrder: 'v1', saveManualExecutions: true, callerPolicy: 'workflowsFromSameOwner', errorWorkflow: '' },
  active: false,
  versionId: '00000000-0000-4000-8000-000000000021',
  meta: {
    templateCredsSetupCompleted: false,
    phase: '11-slack',
    note: 'Requires n8n env: SLACK_SIGNING_SECRET (HMAC key, NEVER hardcode), SLACK_APPROVER_IDS (comma-separated Slack member IDs), SLACK_CHANNEL_ID (bot-invited channel). Reuses the Break Glass Shared Secret and GitHub PAT header-auth credentials; add a Slack Bot Token header-auth credential (Authorization: Bearer xoxb-...). Set N8N_BLOCK_ENV_ACCESS_IN_NODE=false. Discord workflow is separate and untouched.'
  },
  tags: []
};

const out = resolve('n8n/workflows/slack-break-glass-workflow.json');
await mkdir(dirname(out), { recursive: true });
await writeFile(out, `${JSON.stringify(workflow, null, 2)}\n`);
console.log('wrote', out, 'nodes:', workflow.nodes.length);
