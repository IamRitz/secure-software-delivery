// Slack Block Kit builders — the same message shape the n8n workflow produced,
// so the channel experience is unchanged after the migration.

// Internal policy category -> plain-language summary shown first.
const SUMMARY_LABELS = {
  'sast.critical_new': 'New critical code security issue',
  'sast.high_new': 'New high-severity code security issue',
  'dependencies.critical_with_fix': 'Critical vulnerable dependency (fix available)',
  'dependencies.high_with_fix': 'High-severity vulnerable dependency (fix available)'
};

const friendlySummary = (policyRule) => SUMMARY_LABELS[policyRule] || policyRule;

// Slack mrkdwn link.
const mdLink = (url, label) => `<${url}|${label}>`;

// A "View finding" blob link for SAST findings only, and only when the gate
// actually captured `location` ("path:line"). If it's absent we describe the
// finding in text — never a link that might 404.
function findingLink(finding, repo, sha) {
  if (finding.source !== 'semgrep' || typeof finding.location !== 'string') return '';
  const idx = finding.location.lastIndexOf(':');
  if (idx < 1) return '';
  const path = finding.location.slice(0, idx);
  const line = finding.location.slice(idx + 1);
  if (!path || !/^\d+$/.test(line)) return '';
  return `  ${mdLink(`https://github.com/${repo}/blob/${sha}/${path}#L${line}`, 'View finding')}`;
}

export function buildApprovalMessage(request, channel) {
  const repo = request.context.repository;
  const pr = request.context.pullRequest;
  const sha = String(request.context.commitSha);

  // Render the expiry in each viewer's local timezone via Slack's date token,
  // with the ISO string as fallback for clients that can't format it.
  const expiresTs = Math.floor(new Date(request.expiresAt).getTime() / 1000);
  const expires = Number.isFinite(expiresTs)
    ? `<!date^${expiresTs}^{date_short_pretty} {time}|${request.expiresAt}>`
    : request.expiresAt;

  // Plain-language summary (deduped categories), then the exact technical lines.
  const summary = [...new Set(request.findings.map((f) => friendlySummary(f.policyRule)))]
    .map((s) => `*${s}*`)
    .join('\n');
  const detail = request.findings
    .map((f) => `${f.policyRule}: ${f.id} — ${f.reason}${findingLink(f, repo, sha)}`)
    .join('\n')
    .slice(0, 2900);

  return {
    channel,
    text: 'Break-glass security exception requested',
    // Keep the message compact — don't let Slack expand the GitHub links into
    // large preview cards below it.
    unfurl_links: false,
    unfurl_media: false,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: 'Break-glass security exception requested' } },
      { type: 'section', text: { type: 'mrkdwn', text: summary } },
      { type: 'context', elements: [{ type: 'mrkdwn', text: detail }] },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Repository*\n${repo}` },
          { type: 'mrkdwn', text: `*Pull request*\n${mdLink(`https://github.com/${repo}/pull/${pr}`, `#${pr}`)}` },
          { type: 'mrkdwn', text: `*Commit*\n${mdLink(`https://github.com/${repo}/commit/${sha}`, sha.slice(0, 12))}` },
          { type: 'mrkdwn', text: `*Expires*\n${expires}` }
        ]
      },
      {
        type: 'actions',
        block_id: `breakglass:${request.requestId}`,
        elements: [
          {
            type: 'button',
            style: 'primary',
            text: { type: 'plain_text', text: 'Approve' },
            action_id: `breakglass:${request.requestId}:approve`,
            value: `breakglass:${request.requestId}:approve`
          },
          {
            type: 'button',
            style: 'danger',
            text: { type: 'plain_text', text: 'Deny' },
            action_id: `breakglass:${request.requestId}:deny`,
            value: `breakglass:${request.requestId}:deny`
          }
        ]
      }
    ]
  };
}

// The replacement message posted via chat.update once a decision is finalized —
// the buttons are gone (the message is rendered read-only).
export function buildDecisionUpdate(request) {
  const decision = request.status;
  const findingText = request.findings.map((finding) => `${finding.policyRule}: ${finding.id}`).join('; ');
  const approver = request.approver || {};
  return {
    channel: request.slack.channel,
    ts: request.slack.ts,
    text: `Break-glass ${decision}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Break-glass ${decision.toUpperCase()}* by <@${approver.id}>\n${findingText}`
        }
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `Decided ${request.decidedAt} - gate \`${String(request.gateDigest).slice(0, 12)}\``
          }
        ]
      }
    ]
  };
}

export function ephemeral(text) {
  return { response_type: 'ephemeral', replace_original: false, text };
}
