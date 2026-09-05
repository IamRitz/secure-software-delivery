// Slack authorization: check the clicking user's Slack ID against a SEPARATE
// allowlist (SLACK_APPROVER_IDS). A person's Slack ID and Discord ID are
// unrelated values from different namespaces — never conflate the two lists.
// Only reached after verifySlackSignature has passed; it never trusts a
// self-reported name, only the verified `payload.user.id`.
export function authorizeSlackInteraction({ interaction, authorizedUserIds }) {
  const user = interaction?.user;
  const userId = user?.id;
  const username = user?.username || user?.name || userId;
  if (!userId) return { authorized: false, reason: 'missing Slack user identity' };
  if (!authorizedUserIds.has(userId)) {
    return { authorized: false, userId, username, reason: 'not an authorized break-glass approver' };
  }
  return { authorized: true, userId, username };
}

// Parse the comma-separated SLACK_APPROVER_IDS env value into a Set, matching
// how the Discord workflow reads DISCORD_APPROVER_IDS.
export function parseApproverIds(raw) {
  return new Set(
    String(raw || '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
  );
}
