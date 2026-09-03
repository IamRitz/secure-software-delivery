# Security gating

The gate is the only component that translates scanner findings into pipeline
policy. GitHub Actions and Jenkins both call
`security/scripts/security-gate.mjs` with the same `security/policy.yaml`,
reports, and Semgrep baseline.

## Outcomes

- **PASS** means every required report parsed successfully and no blocking or
  exception finding was present.
- **PASS-WITH-EXCEPTIONS** means no blocking finding was present, but one or
  more High/Critical dependencies have no available fix. These findings are
  written separately to `reports/gate-exceptions.json` for follow-up.
- **BLOCK** means policy rejected a finding or input integrity could not be
  established. The script exits non-zero only for this outcome.

Every finding in `reports/security-gate.json` includes its scanner, identifier,
action, policy key, and plain-language reason. Reports never include raw secret
values.

## Fail-closed input handling

The gate requires Gitleaks, TruffleHog, npm audit, OSV-Scanner, and Semgrep
reports plus the Semgrep baseline. A missing file, malformed JSON, missing
field needed for policy, Semgrep scan error, unsupported severity, invalid
policy, or inconsistent npm finding count produces a synthetic
`gate.report_integrity` finding and `BLOCK`. Only validated empty finding
collections count as clean.

GitHub's gate job uses `if: always()` and tolerates artifact-download step
errors only long enough to invoke the evaluator. This ensures a missing
upstream artifact becomes the gate's non-zero `BLOCK` result rather than being
mistaken for zero findings. Jenkins evaluates the files in the shared
workspace immediately after all three scanner stages.

## Finding interpretation

- TruffleHog `Verified: true` blocks; Gitleaks and unverified TruffleHog
  matches are logged.
- npm audit supplies severity and `fixAvailable`. OSV severity is calculated
  from CVSS v3 and fix availability comes from `fixed` events in the matching
  affected package ranges.
- OSV advisory IDs beginning `MAL-` take the malicious-package path and block
  before severity evaluation.
- Semgrep severity uses the mapping in the policy. A SHA-256 fingerprint of
  rule ID, repository path, and matched text identifies baseline-known
  findings. New High/Critical findings block; known backlog is logged.

The thresholds are intentionally adjustable POC defaults, not a general policy
language.

## GitHub branch protection

Branch protection is a GitHub repository setting, not workflow YAML. After the
Phase 8 workflow has produced the `security-gate` check once, configure it as
follows using a repository administrator account:

1. Open **Settings → Branches**.
2. Add or edit the branch protection rule whose branch name pattern is
   `main`.
3. Enable **Require status checks to pass before merging**.
4. Search for and select the exact `security-gate` status check.
5. Save the branch protection rule.

Confirm the saved setting in the UI by reopening the rule and verifying
`security-gate` remains selected. API-capable administrators can independently
check the configured context with:

```sh
gh api repos/IamRitz/secure-software-delivery/branches/main/protection/required_status_checks
```

The response's `contexts` or `checks` list must contain `security-gate`.

### Phase 8 enforced configuration

The repository was changed from private to public so GitHub Free could enforce
branch protection; leaving a visible but unenforced private-repository rule was
not accepted as verification. The saved `main` rule has:

- pull requests required, with zero approving reviews for this solo POC;
- the exact `security-gate` status check required before merge;
- administrator bypass disabled;
- force pushes disabled; and
- branch deletion disabled.

The setting was confirmed in GitHub after the Phase 8 pull-request workflow
registered a successful `security-gate` check. If the repository becomes
private again, its account plan must support enforcement on private
repositories; otherwise this control stops being an enforcement boundary.
