// Allowlisted advisory payload. Shared by the CI client (which builds it) and
// the Lambda (which re-validates it — the client runs PR-controlled code, so
// the Lambda cannot trust that the client was honest).
//
// The payload is constructed field by field from a decided gate finding. It is
// never a serialized report: scanner free text (Semgrep messages, advisory
// descriptions, CVE titles) is excluded, and every string that a PR author can
// influence (file paths, package names, rule ids) is charset-restricted and
// length-capped before it can reach a model context.

export const ALLOWED_FIELDS = [
  'scanner',
  'advisoryId',
  'package',
  'version',
  'severity',
  'fixAvailable',
  'fixedVersion',
  'policyKey',
  'reason',
  'file',
  'line'
];

export const MAX_FINDINGS = 5;

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const ADVISABLE_ACTIONS = new Set(['BLOCK', 'BLOCK_DEPLOY', 'EXCEPTION']);

// Identifier-like strings: package names, advisory/rule ids, paths, versions.
// Anything outside this set (spaces, quotes, newlines, angle brackets) is how
// instructions get smuggled in, so a non-matching value is dropped, not escaped.
const IDENTIFIER = /^[A-Za-z0-9._@/+:-]{1,160}$/;
const POLICY_KEY = /^[a-z_]+\.[a-z_]+$/;
// `reason` is gate-generated, not scanner text; still bound it.
const REASON = /^[A-Za-z0-9 .,;:()_/'-]{1,200}$/;

// Tier 0 only, never a model call:
//   secrets.* / image.secret — the remedy is fixed (rotate, then purge), and a
//     live credential near an external API call is avoidable risk.
//   *.report_integrity — not a vulnerability; the reason carries raw error text.
export function isTier0Only(policyKey) {
  return (
    typeof policyKey !== 'string' ||
    policyKey.startsWith('secrets.') ||
    policyKey === 'image.secret' ||
    policyKey.endsWith('.report_integrity')
  );
}

function identifier(value) {
  return typeof value === 'string' && IDENTIFIER.test(value) ? value : null;
}

function splitLocation(location) {
  if (typeof location !== 'string') return { file: null, line: null };
  const index = location.lastIndexOf(':');
  const path = index === -1 ? location : location.slice(0, index);
  const rawLine = index === -1 ? '' : location.slice(index + 1);
  return {
    file: identifier(path),
    line: /^\d{1,7}$/.test(rawLine) ? Number(rawLine) : null
  };
}

// One gate finding -> one allowlisted payload entry, or null when the finding
// must not leave CI (Tier 0 only, non-blocking, or unidentifiable).
export function toAdvisoryFinding(finding) {
  if (!finding || typeof finding !== 'object') return null;
  if (!ADVISABLE_ACTIONS.has(finding.action)) return null;
  const policyKey = typeof finding.policyRule === 'string' && POLICY_KEY.test(finding.policyRule)
    ? finding.policyRule
    : null;
  if (!policyKey || isTier0Only(policyKey)) return null;

  const advisoryId = identifier(finding.id);
  const severity = typeof finding.severity === 'string' && SEVERITIES.has(finding.severity)
    ? finding.severity
    : null;
  if (!advisoryId || !severity) return null;

  const { file, line } = splitLocation(finding.location);
  return {
    scanner: identifier(finding.source),
    advisoryId,
    package: identifier(finding.package),
    // The gates do not carry the installed version today; kept in the schema so
    // a later gate field has a reviewed place to land.
    version: identifier(finding.version),
    severity,
    fixAvailable: typeof finding.fixAvailable === 'boolean' ? finding.fixAvailable : null,
    fixedVersion: identifier(finding.fixedVersion),
    policyKey,
    reason: typeof finding.reason === 'string' && REASON.test(finding.reason) ? finding.reason : null,
    file,
    line
  };
}

export function buildAdvisoryPayload(gate) {
  const findings = Array.isArray(gate?.findings) ? gate.findings : [];
  const seen = new Set();
  const entries = [];
  for (const finding of findings) {
    const entry = toAdvisoryFinding(finding);
    if (!entry) continue;
    const key = `${entry.policyKey}\0${entry.advisoryId}\0${entry.package ?? ''}\0${entry.file ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push(entry);
    if (entries.length === MAX_FINDINGS) break;
  }
  return { findings: entries };
}

// Lambda-side re-validation. Rejects (rather than repairs) anything that is not
// exactly what buildAdvisoryPayload would have produced.
export function validateAdvisoryPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, error: 'payload must be an object' };
  }
  if (Object.keys(payload).some((key) => key !== 'findings')) {
    return { ok: false, error: 'payload has fields outside the allowlist' };
  }
  const { findings } = payload;
  if (!Array.isArray(findings) || findings.length === 0 || findings.length > MAX_FINDINGS) {
    return { ok: false, error: `findings must be an array of 1-${MAX_FINDINGS}` };
  }
  for (const [index, entry] of findings.entries()) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { ok: false, error: `finding ${index} is not an object` };
    }
    const keys = Object.keys(entry);
    if (keys.length !== ALLOWED_FIELDS.length || !ALLOWED_FIELDS.every((field) => keys.includes(field))) {
      return { ok: false, error: `finding ${index} fields do not match the allowlist` };
    }
    if (typeof entry.policyKey !== 'string' || !POLICY_KEY.test(entry.policyKey) || isTier0Only(entry.policyKey)) {
      return { ok: false, error: `finding ${index} policy key is not advisable` };
    }
    if (!identifier(entry.advisoryId) || !SEVERITIES.has(entry.severity)) {
      return { ok: false, error: `finding ${index} lacks a valid advisoryId or severity` };
    }
    for (const field of ['scanner', 'package', 'version', 'fixedVersion', 'file']) {
      if (entry[field] !== null && !identifier(entry[field])) {
        return { ok: false, error: `finding ${index} ${field} is not a plain identifier` };
      }
    }
    if (entry.reason !== null && !(typeof entry.reason === 'string' && REASON.test(entry.reason))) {
      return { ok: false, error: `finding ${index} reason is not plain text` };
    }
    if (entry.fixAvailable !== null && typeof entry.fixAvailable !== 'boolean') {
      return { ok: false, error: `finding ${index} fixAvailable is not boolean` };
    }
    if (entry.line !== null && !(Number.isInteger(entry.line) && entry.line > 0)) {
      return { ok: false, error: `finding ${index} line is not a positive integer` };
    }
  }
  return { ok: true };
}
