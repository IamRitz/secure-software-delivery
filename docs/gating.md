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

- TruffleHog `Verified: true` blocks; ordinary Gitleaks and unverified
  TruffleHog matches are logged. The exact Gitleaks rule
  `phase10-demo-dummy-secret` is a documented demo-only exception that blocks
  safely generated marker text without claiming provider verification.
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

## Deploy gate

The post-push deploy gate is deliberately separate from the pre-build security
gate. `security/scripts/image-gate.mjs` evaluates the normalized ECR basic-scan
report against the `image` policy section:

- Critical or High produces `BLOCK_DEPLOY` and a non-zero exit.
- Medium or Low is logged and deployment may continue.
- A validated, complete report with zero blocking findings produces `DEPLOY`.
- A missing, malformed, incomplete, unsupported, or internally inconsistent
  report produces `BLOCK_DEPLOY`.

Both GitHub Actions and Jenkins call this same script. They do not translate
its decision in YAML or Groovy, preventing policy and exit behavior from
drifting apart.

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

## Break-glass exceptions

The gate offers a narrow, audited exception path only when **every** blocking
finding is either a new high/critical Semgrep finding or a fixable
high/critical dependency finding. The gate report includes `breakGlass` with
the eligible and ineligible BLOCK findings. A mixed set containing any hard
block is not eligible.

Verified secrets, malicious-package (`MAL-`) advisories, report-integrity
failures, and the safe dummy-secret demo marker have no override path. The CI
client checks eligibility before its n8n shared-secret credential is loaded,
so hard blocks never invoke the notification endpoint.

For an eligible BLOCK, CI authenticates to n8n Webhook A, then polls Webhook C.
Only an `approved` decision makes the existing `security-gate` job successful.
Denied, expired, malformed, unreachable, or timed-out decisions remain failed.

### Discord and n8n setup

1. In the Discord Developer Portal, create the application and bot, invite it
   with permission to send/edit messages in the approval channel, and record
   the application public key separately from the secret bot token.
2. Import `n8n/workflows/break-glass-workflow.json` into n8n 2.36.x. Attach the
   three credentials described in `n8n/README.md`, configure the authorized
   Discord user-ID allowlist, and set workflow concurrency to one.
3. Publish the workflow. Keep Discord's Interactions Endpoint URL at the
   already-validated production route
   `https://n8n.iamritesh.in/webhook/discord/interactions`; never use the
   `/webhook-test/` URL.
4. In GitHub, create `BREAK_GLASS_SHARED_SECRET` as an Actions secret. Create
   repository variables `BREAK_GLASS_NOTIFY_URL`, `BREAK_GLASS_STATUS_URL`,
   and optionally `BREAK_GLASS_TIMEOUT_SECONDS`. In Jenkins, create a Secret
   Text credential named `break-glass-shared-secret`.

Discord signs the timestamp concatenated with the exact raw request body.
Webhook B retains the raw binary body, wraps the 32-byte public key as an
Ed25519 JWK, and calls Node `crypto.verify`. Invalid signatures return HTTP
401 before parsing or state access. A signed type-1 PING receives type-1 PONG;
a signed component interaction receives type-6 deferred acknowledgement
within Discord's response window.

Authorization uses `member.user.id` (or `user.id` for a DM) against the
configured Discord-ID allowlist. Usernames are audit display data only.
Pending requests transition through `processing` before external GitHub and
Discord updates; duplicate, expired, stale, and unauthorized clicks cannot
claim a decision. The GitHub PAT is stored only as an n8n credential and posts
the decision, verified Discord identity, timestamp, findings, and gate digest
to the affected PR.

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
