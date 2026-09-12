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

`security/scripts/image-gate.mjs` runs in two places against the `image` policy:
a **pre-push** scan on every PR (Trivy, `--source trivy`) and the **post-push**
ECR basic scan on `main`. Both are separate from the pre-build security gate.

- **Trivy pre-push (fix availability known)** mirrors the dependency model:
  fixable Critical/High → `BLOCK_DEPLOY`; unfixable Critical/High → `EXCEPTION`
  (verdict `DEPLOY-WITH-EXCEPTIONS`, exit 0) so an unpatchable upstream CVE does
  not permanently block; Medium/Low → `LOG`. A secret baked into a layer, an
  end-of-life OS, or an undetectable OS ("false clean") are **hard** BLOCKs —
  integrity/credential issues, never "no fix available yet".
- **ECR basic (no fix data reported)** falls back to severity-only: Critical or
  High → `BLOCK_DEPLOY`; Medium/Low → `LOG`.
- A missing, malformed, incomplete, unsupported, or internally inconsistent
  report produces `BLOCK_DEPLOY` in both.

Both GitHub Actions and Jenkins call this same script. They do not translate
its decision in YAML or Groovy, preventing policy and exit behavior from
drifting apart. (An expiry/VEX suppression path for accepted `no_fix`
exceptions — review D2 — is a planned follow-up.)

## GitHub branch protection

Branch protection is a GitHub repository setting, not workflow YAML. After the
Phase 8 workflow has produced the `security-gate` check once, configure it as
follows using a repository administrator account:

1. Open **Settings → Branches**.
2. Add or edit the branch protection rule whose branch name pattern is
   `main`.
3. Enable **Require status checks to pass before merging**.
4. Search for and select two checks: `security-gate` (the security boundary)
   and `Application checks` (lint + tests). Requiring both means a PR cannot
   merge unless it is both secure *and* passing tests.
5. Save the branch protection rule.

Both checks are safe to require because each fires on **every** pull request to
`main`: `Application checks` (`ci.yml`) has no `paths` filter or conditional
job, and `security-gate` runs via `if: always()`. Since the workflow split,
`security-gate` is a thin job in `security.yml` that republishes the verdict of
`_source-security.yml`'s `source-gate` job — GitHub would otherwise report that
job as `source-security / source-gate` and the rule above would match nothing,
silently ceasing to gate merges. `test/workflow-contracts.test.js` asserts the
name still exists. A required check whose
workflow can be *skipped* for some PRs (for example a `paths`-filtered workflow
on a PR that touches no matching files) would leave those PRs permanently
blocked on "Waiting for status to be reported" — neither of these can, because
both always report.

Confirm the saved setting in the UI by reopening the rule and verifying both
checks remain selected. API-capable administrators can independently check the
configured context with:

```sh
gh api repos/IamRitz/secure-software-delivery/branches/main/protection/required_status_checks
```

The response's `contexts` or `checks` list must contain `security-gate` and
`Application checks`.

## Break-glass exceptions

The gate offers a narrow, audited exception path only when **every** blocking
finding is either a new high/critical Semgrep finding or a fixable
high/critical dependency finding. The gate report includes `breakGlass` with
the eligible and ineligible BLOCK findings. A mixed set containing any hard
block is not eligible. Dependency findings with **no fix available** are never
break-glass candidates because the gate already treats them as EXCEPTION rather
than BLOCK — there is nothing to override.

**Active platform: Slack.** The approval flow below was first built on Discord;
that Discord path remains in the repository, built and tested, but is
intentionally **frozen/dormant** — Slack is what is actually in use. The
Discord-specific details in the next subsection describe that frozen path; the
live per-repo Slack mechanism is in "Slack approvers" further down.

Verified secrets, malicious-package (`MAL-`) advisories, report-integrity
failures, and the safe dummy-secret demo marker have no override path. The CI
client checks eligibility before its n8n shared-secret credential is loaded,
so hard blocks never invoke the notification endpoint.

For an eligible BLOCK, CI authenticates to n8n Webhook A, then polls Webhook C.
Only an `approved` decision makes the `source-gate` job (and therefore the
`security-gate` check) successful.
Denied, expired, malformed, unreachable, or timed-out decisions remain failed.

### Slack path (active) — n8n webhooks and CI variables

The live Slack workflow is `Sekure - Slack Break-Glass (DEV)` (n8n id
`g74Plh4qiwhcEPiQ`). Its webhook paths are prefixed `dev/slack/`, so the exact
URLs CI must use are:

| Repository variable | Value |
| --- | --- |
| `BREAK_GLASS_NOTIFY_URL` | `https://n8n.iamritesh.in/webhook/dev/slack/break-glass/notify` |
| `BREAK_GLASS_STATUS_URL` | `https://n8n.iamritesh.in/webhook/dev/slack/break-glass/status` |
| `BREAK_GLASS_TIMEOUT_SECONDS` | `900` (optional) |

The Slack app's own **Interactivity Request URL** points at
`https://n8n.iamritesh.in/webhook/dev/slack/interactions` (that is Slack-app
config, not a CI variable). `BREAK_GLASS_SHARED_SECRET` is an Actions **secret**
(not a variable) matching the notify/status webhooks' shared-secret credential.

The path prefix matters: dropping `dev/slack/` (e.g. `.../webhook/break-glass/notify`)
is **not** a registered route and the notify step fails with
`BREAK-GLASS: DENIED (notification endpoint returned HTTP 404)` — the gate BLOCK
and eligibility check are correct; only the URL is wrong.

### Discord path (built, frozen) and n8n setup

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

### Slack approvers — per-repo allowlist

This resolves the earlier "shared vs per-repo" question: approvers are **per-repo,
explicit, and fail-closed**. The Slack interaction handler reads
`SLACK_APPROVER_IDS_BY_REPO`, a JSON object keyed by full repository name:

```
SLACK_APPROVER_IDS_BY_REPO={"IamRitz/secure-software-delivery":["U0BV6TWN60J"],"org/other-repo":["U111","U222"]}
```

Rules, all deliberate:

- A repository **not present as a key** authorizes **nobody** — there is no fallback
  to a shared default list. A repo is not onboarded to break-glass until it has an
  explicit entry.
- **Malformed JSON** in the variable is treated as an empty map (nobody authorized
  for anything), logged, never thrown — one bad edit cannot crash the handler for
  every repo at once.
- The repository identity is taken from the **stored pending request** (set when the
  notify webhook first received the finding payload, the same value used to post the
  GitHub audit comment), looked up by request ID when the click arrives — **never
  from the Slack interaction payload**, which has no notion of a GitHub repo and thus
  nothing to forge. The user ID is checked against that repo's set only.

**Onboarding a repo:** add its full name and its approvers' Slack member IDs to
`SLACK_APPROVER_IDS_BY_REPO`, then recreate the `n8n` container (env-var config
requires a process restart on any platform to take effect).

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
