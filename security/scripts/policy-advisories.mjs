// Tier 0 policy guide: fixed, reviewed, deterministic text per policy key.
//
// format-findings.mjs already explains each FINDING (what it is, where, how to
// fix it). This table explains each policy CLASS: what the key means, why the
// policy treats it that way, and whether break-glass can override it. It is
// the part of the developer comment that is guaranteed — nothing here is
// generated, and nothing here decides policy (the gate does).
//
// `breakGlass` must agree with the gate's real eligibility logic, and every
// policy key the gates can emit must have an entry. Both are asserted in
// test/policy-advisories.test.js, so a new key cannot silently render without
// its explanation.
//
//   eligible    — a BLOCK that may enter the Slack break-glass approval flow
//   never       — a BLOCK with no override path, by design
//   not-offered — a deploy BLOCK; break-glass exists only for the source gate
//   not-needed  — does not block (LOG or EXCEPTION), so there is nothing to override

const FIXABLE_DEPENDENCY_WHY =
  'A fix exists upstream, so the risk is removable by upgrading. Severity alone does not decide the ' +
  'outcome — fix availability does: the same severity with no fix is a tracked EXCEPTION instead, because ' +
  'blocking on something nobody can act on only teaches people to bypass the gate.';

const NO_FIX_DEPENDENCY_WHY =
  'No fixed version exists yet, so blocking would stop work without giving anyone a way to resolve it. ' +
  'It passes deliberately but is written to the exceptions report and stays visible on every run until a ' +
  'fix ships — at which point the same finding becomes a BLOCK.';

const NEW_SAST_WHY =
  'The pattern is new in this change (not in the committed baseline), so it is the cheapest moment to fix ' +
  'it. Pre-existing backlog is logged rather than blocked so the gate judges your change, not history.';

const EXISTING_SAST_WHY =
  'The finding matches the committed Semgrep baseline, so it existed before this change. Backlog is logged, ' +
  'not blocked, so an unrelated PR is never held hostage by old code — it still needs fixing on its own track.';

const IMAGE_FIXABLE_WHY =
  'A fixed package exists, so a base-image bump or package upgrade removes the risk before anything ships. ' +
  'The same severity with no fix is a tracked EXCEPTION instead.';

const IMAGE_NO_FIX_WHY =
  'No fixed package exists yet for this image layer, so blocking the deploy would not make it safer. It ' +
  'deploys as a tracked exception and becomes a BLOCK_DEPLOY once a fix ships.';

const LOW_SIGNAL_WHY =
  'Below the blocking threshold. It is recorded so it is not lost, but it does not stop a merge or deploy.';

export const POLICY_ADVISORIES = {
  'secrets.verified': {
    meaning: 'A secret scanner confirmed this credential is live with its provider.',
    why:
      'A verified credential in git history must be treated as already compromised: anyone with read access ' +
      'to the repository, forks, or clones may hold it. Removing the line does not un-leak it.',
    breakGlass: 'never',
    remedy: 'Rotate or revoke the credential first, then purge it from history.'
  },
  'secrets.unverified': {
    meaning: 'Something matched a secret pattern, but no provider confirmed it is a live credential.',
    why:
      'Pattern matches are frequently test values or look-alikes, so they are logged rather than blocked. ' +
      'A match that is real should still be rotated.',
    breakGlass: 'not-needed'
  },
  'secrets.demo_dummy': {
    meaning: 'The dedicated, non-credential demo marker was activated (a never-merged demo branch).',
    why:
      'It exercises the secret-block path without claiming a real credential leaked. It blocks exactly like ' +
      'a verified secret so the demo proves the hard-block behavior.',
    breakGlass: 'never'
  },
  'dependencies.critical_with_fix': {
    meaning: 'A Critical-severity advisory affects a dependency, and a fixed version exists.',
    why: FIXABLE_DEPENDENCY_WHY,
    breakGlass: 'eligible'
  },
  'dependencies.high_with_fix': {
    meaning: 'A High-severity advisory affects a dependency, and a fixed version exists.',
    why: FIXABLE_DEPENDENCY_WHY,
    breakGlass: 'eligible'
  },
  'dependencies.critical_no_fix': {
    meaning: 'A Critical-severity advisory affects a dependency, and no fixed version exists yet.',
    why: NO_FIX_DEPENDENCY_WHY,
    breakGlass: 'not-needed'
  },
  'dependencies.high_no_fix': {
    meaning: 'A High-severity advisory affects a dependency, and no fixed version exists yet.',
    why: NO_FIX_DEPENDENCY_WHY,
    breakGlass: 'not-needed'
  },
  'dependencies.medium': {
    meaning: 'A Medium-severity advisory affects a dependency.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'dependencies.low': {
    meaning: 'A Low-severity advisory affects a dependency.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'dependencies.malicious_package': {
    meaning: 'The package is listed in a malicious-package (MAL-) advisory.',
    why:
      'The package itself is the attack — typically it runs code at install time. There is no safe version ' +
      'to wait for and no severity to weigh, so it blocks regardless of score.',
    breakGlass: 'never',
    remedy: 'Remove the package, and treat any machine that installed it as potentially compromised.'
  },
  'sast.critical_new': {
    meaning: 'Semgrep flagged a Critical-severity code pattern that this change introduced.',
    why: NEW_SAST_WHY,
    breakGlass: 'eligible'
  },
  'sast.high_new': {
    meaning: 'Semgrep flagged a High-severity code pattern that this change introduced.',
    why: NEW_SAST_WHY,
    breakGlass: 'eligible'
  },
  'sast.critical_existing': {
    meaning: 'Semgrep flagged a Critical-severity pattern that is already in the accepted baseline.',
    why: EXISTING_SAST_WHY,
    breakGlass: 'not-needed'
  },
  'sast.high_existing': {
    meaning: 'Semgrep flagged a High-severity pattern that is already in the accepted baseline.',
    why: EXISTING_SAST_WHY,
    breakGlass: 'not-needed'
  },
  'sast.medium': {
    meaning: 'Semgrep flagged a Medium-severity code pattern.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'sast.low': {
    meaning: 'Semgrep flagged a Low-severity code pattern.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'gate.report_integrity': {
    meaning: 'A scanner report was missing, malformed, or in a shape the gate could not interpret.',
    why:
      'An unreadable report proves nothing about the code, so it fails closed. Passing it would turn every ' +
      'scanner outage into a silent "clean" result.',
    breakGlass: 'never'
  },
  'image.critical_with_fix': {
    meaning: 'A Critical-severity vulnerability is in an image package, and a fixed package exists.',
    why: IMAGE_FIXABLE_WHY,
    breakGlass: 'not-offered'
  },
  'image.high_with_fix': {
    meaning: 'A High-severity vulnerability is in an image package, and a fixed package exists.',
    why: IMAGE_FIXABLE_WHY,
    breakGlass: 'not-offered'
  },
  'image.critical_no_fix': {
    meaning: 'A Critical-severity vulnerability is in an image package, and no fixed package exists yet.',
    why: IMAGE_NO_FIX_WHY,
    breakGlass: 'not-needed'
  },
  'image.high_no_fix': {
    meaning: 'A High-severity vulnerability is in an image package, and no fixed package exists yet.',
    why: IMAGE_NO_FIX_WHY,
    breakGlass: 'not-needed'
  },
  'image.critical': {
    meaning: 'ECR basic scanning reported a Critical-severity vulnerability in the pushed image.',
    why:
      'ECR basic scanning does not report whether a fix exists, so the gate cannot tell an actionable finding ' +
      'from an unfixable one and conservatively blocks both. This is a scanner limitation, not a stricter policy.',
    breakGlass: 'not-offered'
  },
  'image.high': {
    meaning: 'ECR basic scanning reported a High-severity vulnerability in the pushed image.',
    why:
      'ECR basic scanning does not report whether a fix exists, so the gate cannot tell an actionable finding ' +
      'from an unfixable one and conservatively blocks both. This is a scanner limitation, not a stricter policy.',
    breakGlass: 'not-offered'
  },
  'image.medium': {
    meaning: 'A Medium-severity vulnerability is in an image package.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'image.low': {
    meaning: 'A Low-severity vulnerability is in an image package.',
    why: LOW_SIGNAL_WHY,
    breakGlass: 'not-needed'
  },
  'image.secret': {
    meaning: 'A secret was found baked into a built image layer.',
    why:
      'Anyone who can pull the image can extract every layer, including ones later "deleted" by a subsequent ' +
      'layer. The credential is exposed the moment the image is pushed.',
    breakGlass: 'never',
    remedy: 'Rotate the credential, then rebuild without copying it into any layer.'
  },
  'image.report_integrity': {
    meaning: 'The image scan could not be trusted: no OS detected, an end-of-life OS, or an unreadable report.',
    why:
      'A scan that did not understand the image reports zero findings, which looks identical to a clean ' +
      'image. It fails closed so "could not scan" is never mistaken for "nothing found".',
    breakGlass: 'never'
  }
};

export const BREAK_GLASS_TEXT = {
  eligible:
    'Break-glass: available. An authorized approver can override this BLOCK through the audited Slack approval flow.',
  never: 'Break-glass: never available for this class — there is no override path.',
  'not-offered':
    'Break-glass: not offered. Break-glass covers the source security gate only; deploy-time image blocks must be fixed.',
  'not-needed': 'Break-glass: not needed — this class does not block.'
};

export function policyAdvisory(policyKey) {
  return Object.hasOwn(POLICY_ADVISORIES, policyKey ?? '') ? POLICY_ADVISORIES[policyKey] : null;
}
