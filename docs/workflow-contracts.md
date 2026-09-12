# Reusable security workflows — input/output contracts

These contracts are the onboarding interface another repository reads. Changing
one breaks every consumer, so treat them the way you would a published API: add
inputs with defaults, never rename or repurpose an existing one.

Everything currently lives in this repo and is referenced locally
(`uses: ./.github/workflows/_name.yml`). Extracting to a central repo changes
only the `uses:` line — see [Extraction notes](#extraction-notes).

## File map and trigger ownership

| File | Kind | Triggers | Cloud credentials |
| --- | --- | --- | --- |
| `security.yml` | caller | `pull_request` → `main`, `schedule` (Mon 06:00 UTC) | none |
| `deploy.yml` | caller | `push` → `main`, `workflow_dispatch` | ECR push+scan role, SSM deploy role |
| `_source-security.yml` | reusable | `workflow_call` | **none** |
| `_image-scan-prepush.yml` | reusable | `workflow_call` | **none** |
| `_artifact-gate.yml` | reusable | `workflow_call` | **none** |
| `_ecr-collect.yml` | reusable | `workflow_call` | ECR push+scan role |

**One workflow per trigger.** `security.yml` owns pull requests and the weekly
schedule; `deploy.yml` owns push-to-main and manual dispatch. Neither reacts to
the other's events, so the scanners run exactly once per event. `ci.yml` (lint +
tests) is unchanged and independent.

```
security.yml (PR / schedule)          deploy.yml (push to main / dispatch)
  source-security ──► security-gate     source-security ─┐
  container-build ──► image-security    container-build ─┴► image-security
                        └► image-gate              └► aws-configuration
                                                     └► ecr-collect
                                                        └► artifact-gate
                                                           └► deploy (SSM)
```

## `_source-security.yml`

Secret scan, dependency scan, SAST, and the source security gate. Assumes no
cloud role. Node is installed as a **tool** dependency for the `.mjs` gate
scripts, independent of the consumer repo's own language.

### Inputs

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `gate_mode` | string | `enforce` | `enforce`: a BLOCK fails the gate job. `log-only`: everything is reported, nothing fails, and no Slack alert is sent. |
| `node_version` | string | `22.23.2` | Node used to run the gate scripts. |
| `toolkit_path` | string | `security` | Directory holding `policy.yaml` and `scripts/` in the checkout. |
| `semgrep_configs` | string | `p/owasp-top-ten` | Whitespace/newline separated Semgrep configs. Add language packs and local rule files per repo. |
| `semgrep_paths` | string | `.` | Whitespace separated paths Semgrep scans. |
| `semgrep_baseline_path` | string | `security/baseline/semgrep-baseline.json` | Committed baseline that separates new findings from the existing backlog. |
| `gitleaks_config` | string | `.gitleaks.toml` | Skipped automatically when the file is absent. |
| `trufflehog_exclude_paths` | string | `.trufflehog-exclude-paths.txt` | Skipped automatically when the file is absent. |
| `reproduce_commands` | string (JSON) | `''` | Maps finding source → the local command a developer runs. Empty uses portable direct scanner invocations. |
| `slack_notify_url` | string | `''` | Slack incoming webhook for BLOCK alerts. Empty disables Slack. |
| `pr_number` | string | `''` | PR that receives the findings comment. Defaults to the PR of a `pull_request` run. |
| `break_glass_enabled` | boolean | `false` | Whether an eligible BLOCK may enter the interactive approval flow. |
| `break_glass_notify_url` | string | `''` | Approval-request endpoint. |
| `break_glass_status_url` | string | `''` | Decision-status endpoint. |
| `break_glass_timeout_seconds` | string | `''` | How long to wait for a verified decision. |
| `synthetic_block_fixture` | string | `none` | Demo only: `sast` or `dependency` injects a synthetic eligible BLOCK. Refuses to run unless **both** break-glass URLs are passed explicitly, so a synthetic BLOCK can never reach the production endpoints. |

### Secrets

| Secret | Required | Meaning |
| --- | --- | --- |
| `break_glass_shared_secret` | no | HMAC key for the break-glass request/decision channel. |

This is the **only** secret any security reusable workflow accepts, it is
declared explicitly, and it is not a cloud credential — it grants no AWS access
and cannot be used to reach any infrastructure. Callers must never use
`secrets: inherit`.

Both callers pass it, because break-glass has to work on a pull request (that is
its main use: an approver unblocking a PR) as well as on push. On a **fork** PR
GitHub withholds the secret entirely, so an eligible BLOCK fails closed rather
than reaching the approval channel. A consumer repo that does not use
break-glass sets `break_glass_enabled: false` (the default) and passes no
`secrets:` block at all, in which case `_source-security.yml` runs with zero
secrets.

`_image-scan-prepush.yml` and `_artifact-gate.yml` declare no `secrets:` block
whatsoever — they cannot receive one.

### Outputs

| Output | Values |
| --- | --- |
| `verdict` | `PASS` \| `PASS-WITH-EXCEPTIONS` \| `BLOCK` |
| `break_glass_eligible` | `true` when the BLOCK consists only of break-glass-eligible findings |

The calling job **fails** when the verdict is `BLOCK` in `enforce` mode and no
verified break-glass approval overrode it.

## `_image-scan-prepush.yml`

Trivy scan plus the pre-push image gate, over an image tarball artifact the
caller already built. Assumes no cloud role, accepts no secrets, touches no
registry.

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `image_artifact` | string | **required** | Artifact holding the image tarball. |
| `image_tarball` | string | `application-image.tar` | File name inside that artifact. |
| `gate_mode` | string | `enforce` | As above. |
| `node_version` | string | `22.23.2` | |
| `toolkit_path` | string | `security` | |
| `reproduce_commands` | string (JSON) | `''` | |
| `slack_notify_url` | string | `''` | |
| `pr_number` | string | `''` | |

| Output | Values |
| --- | --- |
| `verdict` | `DEPLOY` \| `DEPLOY-WITH-EXCEPTIONS` \| `BLOCK_DEPLOY` |
| `image_id` | Trivy `Metadata.ImageID` — the image config digest that anchors the digest chain |

## `_artifact-gate.yml`

Policy evaluation over a **normalized** registry scan report. Registry-neutral:
it names no registry and calls no registry API. Assumes no cloud role, accepts
no secrets.

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `report_artifact` | string | **required** | Artifact holding the normalized report. |
| `report_path` | string | `reports/registry-image-scan.json` | Path of the report once downloaded into `reports/`. |
| `expected_digest` | string | **required** | Manifest digest the report must describe; a mismatch fails closed. |
| `gate_mode` | string | `enforce` | As above. |
| `node_version` | string | `22.23.2` | |
| `toolkit_path` | string | `security` | |
| `reproduce_commands` | string (JSON) | `''` | |
| `slack_notify_url` | string | `''` | |

| Output | Values |
| --- | --- |
| `verdict` | `DEPLOY` \| `DEPLOY-WITH-EXCEPTIONS` \| `BLOCK_DEPLOY` |

### Normalized report schema (the collector → gate contract)

Any collector must emit this shape; `image-gate.mjs` fails closed on anything
else.

```jsonc
{
  "schemaVersion": 1,
  "source": "aws-ecr-basic",     // see "known coupling" below
  "scanStatus": "COMPLETE",
  "image": { "repository": "...", "imageTag": "...", "imageDigest": "sha256:..." },
  "findings": [{ "id": "CVE-...", "severity": "critical|high|medium|low" }],
  "severityCounts": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
}
```

`severityCounts` must agree with `findings` exactly — a mismatch is a
report-integrity `BLOCK_DEPLOY`, not a warning.

## `_ecr-collect.yml`

The ECR adapter, and the only workflow on this side of the boundary that holds
cloud credentials. It pushes, polls the ECR scan **by digest**, and normalizes
the result. It makes no policy decision.

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `image_artifact` | string | **required** | Artifact holding the image tarball. |
| `image_tarball` | string | `application-image.tar` | |
| `local_image_ref` | string | **required** | The `name:tag` the tarball loads as. |
| `expected_image_id` | string | **required** | Image config digest Trivy scanned pre-push; a mismatch fails closed. |
| `role_arn` | string | **required** | OIDC role with ECR push + scan-findings read. |
| `aws_region` | string | **required** | |
| `ecr_repository` | string | **required** | |
| `immutable_tag` | string | **required** | Conventionally the commit SHA. |
| `extra_tags` | string | `''` | Whitespace separated additional mutable tags. |
| `node_version` | string | `22.23.2` | |
| `toolkit_path` | string | `security` | |
| `report_artifact` | string | `registry-image-scan` | Artifact name for the normalized report. |

| Output | Meaning |
| --- | --- |
| `registry` | ECR registry host that was pushed to |
| `image_digest` | Immutable pushed manifest digest |
| `report_artifact` | Artifact name to hand to `_artifact-gate.yml` |
| `report_path` | `reports/registry-image-scan.json` |

Swapping registries means writing a sibling collector (`_gar-collect.yml`,
`_acr-collect.yml`, …) that emits the same normalized report. The gate and the
policy do not change.

## `gate_mode`

| Mode | BLOCK verdict | Slack | Use |
| --- | --- | --- | --- |
| `enforce` (default) | fails the job | on BLOCK | Steady state |
| `log-only` | reported, job passes | never | Onboarding (the LOG phase) |

`log-only` suppresses **every** failure, including a fail-closed
report-integrity BLOCK — that is the point of the onboarding phase, and it is
why each gate job emits a loud `::warning::` saying the gate is not blocking.
Do not leave a repo in `log-only` after it has been tuned.

Set repo variable `GATE_MODE` to switch; both callers read
`${{ vars.GATE_MODE || 'enforce' }}`, so an unset variable enforces.

## Portability rules for consumers

- **Semgrep rulesets are an input.** A hardcoded `p/javascript` on a Python repo
  reports near-zero findings, which reads as a clean pass rather than a
  misconfiguration — the same false-clean failure mode as Trivy not identifying a
  base-image OS. The default (`p/owasp-top-ten`) is language-agnostic; add your
  language pack. The workflow refuses to run with an empty ruleset or an empty
  scan path rather than reporting a scan of nothing.
- **Ecosystem detection is inside the reusable workflow.** npm audit runs only
  with a `package-lock.json`, pip-audit only with a `requirements.txt`. Neither
  present is a clean skip; OSV-Scanner always runs and covers every ecosystem's
  lockfiles, so a Go/Rust/Java repo is still scanned rather than silently
  unscanned. Verified by running the gate against a Python-only and a
  manifest-free checkout.
- **Node is a tool dependency, not an assumption about the repo.** Every job that
  runs a `.mjs` script sets up Node explicitly; a pure-Python consumer needs none
  of its own.
- **A Semgrep baseline is a required onboarding artifact.** A missing baseline is
  a fail-closed report-integrity `BLOCK`, not a pass — you cannot distinguish new
  findings from the existing backlog without one. Generate and commit it first
  (see `docs/onboarding.md`), then point `semgrep_baseline_path` at it.
- **Artifact scanning is genuinely optional.** A repo that ships a library, a
  static site, or a Lambda zip deletes `container-build` and `image-security`
  from its caller and calls nothing else. `_source-security.yml` references no
  image artifact and has no downstream image dependency in either direction.
- **Developer guidance carries no repo-specific tooling.** The notifier's
  "Reproduce locally" line defaults to a direct scanner invocation
  (`semgrep scan --config p/owasp-top-ten .`), never `make sast`. This repo
  overrides it to its own `make` targets through `reproduce_commands`; a consumer
  with no Makefile gets the portable default. Malformed override JSON falls back
  to the defaults rather than failing a run — this is guidance, never a gate
  input.

## Branch protection

`main` requires the contexts `security-gate` and `Application checks`.

Moving the gate into a reusable workflow renames its own check to
`source-security / source-gate`. To keep the required context resolving — a
mismatch would silently stop enforcing merges with *nothing visibly failing* —
`security.yml` publishes a thin `security-gate` job that republishes the source
verdict under the original name. **The branch protection rule needs no change.**

`security.yml` also publishes an `image-gate` job carrying the pre-push image
verdict. It is **not** currently a required context (it wasn't before this split
either); adding it to branch protection would make a pre-push image BLOCK_DEPLOY
also block merge. That is a deliberate policy choice, not a default.

`test/workflow-contracts.test.js` asserts the `security-gate` name, the trigger
split, the registry-neutrality of `_artifact-gate.yml`, and the absence of
`secrets: inherit` and `id-token` in every credential-free workflow.

## Extraction notes

Known couplings to resolve when these move to a central repo:

1. **The toolkit travels with the workflow, not the consumer.** Every reusable
   workflow runs `node <toolkit_path>/scripts/*.mjs` from the checkout of the
   *calling* repo. Centralized, each reusable workflow needs a second
   `actions/checkout` of the security repo at a pinned SHA into a subdirectory,
   with `toolkit_path` pointing there. The path is already an input, so this is a
   one-line change per workflow rather than a rewrite.
2. **`image-gate.mjs` still asserts `report.source === 'aws-ecr-basic'`.** The
   *workflow* `_artifact-gate.yml` is registry-neutral, but the script it calls
   recognizes exactly one normalized source string. A second collector needs that
   assertion widened to a set of accepted normalized sources. Left strict rather
   than speculatively loosened, since a wrong source string today should still
   fail closed.
3. `security/policy.yaml`, `security/semgrep-rules.yml`, and the Semgrep baseline
   are consumer-owned or toolkit-owned depending on how much policy you want
   central. `policy.yaml` is currently resolved from `toolkit_path`, i.e. it
   travels with the toolkit.
