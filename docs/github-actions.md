# GitHub Actions

The application workflow runs for pull requests targeting `main`, pushes to
`main`, and manual dispatches. It has no schedule.

The workflow has only `contents: read` permission. It installs the committed
lockfile with `npm ci`, then runs ESLint and the offline test suite. It has no
cloud credentials and performs no image build or deployment.

Security is split into **reusable workflows plus thin callers**. The full
input/output contracts, the trigger-ownership table, and the portability rules
for a consumer repo live in **`docs/workflow-contracts.md`**; this page describes
how the pieces behave at runtime.

- `_source-security.yml` — secret scan, dependency scan, SAST, source gate.
- `_image-scan-prepush.yml` — Trivy plus the pre-push image gate.
- `_artifact-gate.yml` — policy over a normalized registry scan report.
- `_ecr-collect.yml` — the ECR adapter (push, poll by digest, normalize).
- `security.yml` — caller for `pull_request` and the weekly `schedule`.
- `deploy.yml` — caller for `push` to `main` and `workflow_dispatch`.

One workflow per trigger: neither caller reacts to the other's events, so the
scanners run exactly once per event.

Inside `_source-security.yml` the `secret-scanning`, `dependency-scanning`, and
`sast` jobs run in parallel with no job credentials and do not persist checkout
credentials. They collect reports without making independent policy decisions.
The dependent `source-gate` job downloads every artifact and calls the shared
gate script; its verdict determines the required check result, republished by
`security.yml`'s `security-gate` job under the name branch protection expects.
Redacted secret reports, native dependency reports, Semgrep JSON, and gate
decisions are retained as workflow artifacts for 14 days.

## Build layer caching

Each scanner runs in its pinned (`@sha256:`) container, pulled by digest on every
run. Caching the scanner images was tried and dropped: on GitHub-hosted runners
the small/medium images (Gitleaks, TruffleHog, OSV-Scanner) pull fast enough that
an `actions/cache` round-trip saved no measurable wall-clock, and Semgrep's ~1 GB
image is too large to cache usefully. The images stay digest-pinned, so this is a
simplicity choice with no effect on what runs.

`security.yml`'s `container-build` job (PRs only) caches Docker **layers** with
buildx `cache-from/cache-to: type=gha`, so an unchanged `npm ci` layer is
restored rather than rebuilt. `deploy.yml`'s `container-build` — the build that
actually ships — uses `no-cache: true`, so a potentially poisoned Actions cache
entry can never be baked into the released image.

Layer caching is a caching change only — the same Dockerfile and
context produce identical image content (verified: cached and uncached builds
yield the same rootfs layer digests). The one layer to keep in mind is
`RUN apk --no-cache upgrade`: while its cache is warm it will not re-pull newly
published Alpine patches, but the shipped image is still scanned by the
ECR scan-on-push artifact gate regardless of build cache, and the
weekly scheduled run rebuilds — so a stale patch layer cannot slip a new CVE
past delivery.

Only `security.yml` has a Monday weekly schedule. This catches
advisories published for already-locked dependencies and refreshes the SAST
report without pointlessly scheduling the standalone application workflow.

`container-build` runs on **every** event except the weekly schedule — including
pull requests, where it lives in `security.yml`. Each caller owns its own build
job, because the build is the repo-specific part a consumer brings. It has only
`contents: read`, holds no AWS credentials, builds the Dockerfile, `docker
save`s a tarball, and uploads it as an artifact.
The Trivy scan is a **separate, visibly-named job**, `image-scan-prepush`, so it
appears as its own node in the Actions graph rather than hiding inside the build.
That job (also no credentials) lives in `_image-scan-prepush.yml`: it downloads
the tarball, scans it with a digest-pinned Trivy (`--input`, no Docker socket
mounted; see `security/trivy-provenance.md`), and runs
`image-gate.mjs --source trivy` as the **pre-push image gate**: a
Critical/High-with-fix CVE, a baked-in secret, an undetectable OS ("false clean")
or an end-of-life OS fails the check on the PR, not after merge. Trivy runs with `--exit-code 0` — the reviewed gate decides.

A PR can assume no AWS role at all, now enforced three ways: `pull_request` is
not a trigger of `deploy.yml` (the only workflow with any AWS job);
`aws-configuration` and `ecr-collect` still carry an explicit
`ref == refs/heads/main` guard; and the OIDC trust policies pin `sub` to
`refs/heads/main`. `workflow_dispatch` remains allowed because it is manually
triggered and sits in the same trust tier as merge access. On a BLOCK the image
is still built and scanned but never pushed or deployed — a wasted build, never
an unsafe one.

Delivery is three visibly-named jobs holding **two** OIDC roles:

`ecr-collect` → `artifact-gate` → `deploy`

- `ecr-collect` (`_ecr-collect.yml`) assumes the **push+scan** role (ECR write +
  scan-findings read on this repo — both are registry operations). It asserts the
  loaded artifact's config digest equals what Trivy scanned, pushes the immutable
  + `demo` tags, then polls the ECR scan-on-push result by digest and normalizes
  it. It is the **only** place registry-specific logic lives, and it makes no
  policy decision. It also `needs` `image-security`, so a failed pre-push gate
  skips the push.
- `artifact-gate` (`_artifact-gate.yml`) holds **no cloud credentials** (no
  `id-token`, no role) and names no registry: it runs `image-gate.mjs` against
  the normalized report. A Critical/High finding, a digest mismatch, or a
  missing/malformed report makes the job **fail**.
- `deploy` assumes the **deploy** role (SSM only, no ECR) and runs the EC2/SSM
  deploy (`ssm-deploy.mjs` — no SSH, no inbound port).

Each job `needs` the previous, so a failed `artifact-gate` **skips** the `deploy`
job entirely — it never starts, a stronger guarantee than an in-job early exit.
No workflow-level AWS permission or static AWS access key is used. Two scoped
OIDC roles (push+scan, deploy) keep the registry credentials separate from the
credentials that reach the instance (see `docs/aws-setup.md`).

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

The `security-gate` job is the security enforcement status. `main` branch
protection requires this exact check before merge; scanner jobs remain report
producers rather than three separate policy implementations. The repository
setting and its manual verification procedure are documented in
`docs/gating.md`.

The gate itself now runs inside `_source-security.yml` as `source-gate`, which
GitHub reports as `source-security / source-gate`. To keep the required context
resolving, `security.yml` publishes a thin job literally named `security-gate`
that republishes the source verdict. **No branch protection change is needed.**
`security.yml` also publishes an `image-gate` job carrying the pre-push image
verdict; it is not a required context today (nor was it before the split).

When the gate emits an eligible BLOCK, the job checks eligibility before
loading `BREAK_GLASS_SHARED_SECRET`, sends the normalized findings to the break-
glass service, and polls for a verified decision. Slack is the active approval
platform (the Discord path is built but frozen); the CI side is
platform-agnostic — it only calls the `BREAK_GLASS_NOTIFY_URL`/`STATUS_URL`
endpoints. Approval preserves the same
`security-gate` check name and lets that job succeed; denial, timeout, endpoint
failure, or malformed status fails it. Verified-secret and malicious-package
hard blocks fail during the credential-free eligibility step and never invoke
n8n.

For the controlled interaction demo, `deploy.yml`'s `workflow_dispatch` accepts
`break_glass_demo` (`sast` or `dependency`) and `break_glass_pr_number`. It
copies an existing synthetic Phase 8 report into the gate job only; no live
vulnerable content is activated or installed.

## Commit-range scan scope

Secret (Gitleaks, TruffleHog) and SAST (Semgrep) scans are scoped by trigger to
keep PR feedback fast without weakening the weekly sweep:

- **`pull_request`** — only the branch's commits since the merge-base with the
  target branch (`git merge-base origin/$GITHUB_BASE_REF HEAD`). Gitleaks uses
  `--log-opts=<base>..HEAD`, TruffleHog `--since-commit=<base>`, Semgrep
  `--baseline-commit=<base>`.
- **`push` to `main`** — only commits since the previous `main` tip
  (`github.event.before`); falls back to a full scan if that commit is missing.
- **`schedule` (weekly) / `workflow_dispatch`** — full history / full tree,
  unchanged.

npm audit and OSV-Scanner are unaffected: they inspect current lockfile state,
not commit history. Semgrep's `--baseline-commit` (what is *scanned*) is
independent of `semgrep-baseline.json`'s new-vs-existing reporting (what is
*reported*); both remain in effect.
