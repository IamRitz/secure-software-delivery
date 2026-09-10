# GitHub Actions

The application workflow runs for pull requests targeting `main`, pushes to
`main`, and manual dispatches. It has no schedule.

The workflow has only `contents: read` permission. It installs the committed
lockfile with `npm ci`, then runs ESLint and the offline test suite. It has no
cloud credentials and performs no image build or deployment.

Security checks live together in `.github/workflows/security.yml`. Its
`secret-scanning`, `dependency-scanning`, and `sast` jobs run in parallel with
no job credentials and do not persist checkout credentials. They collect
reports without making independent policy decisions. The dependent
`security-gate` job downloads every artifact and calls the shared gate script;
its exit code directly determines the required check result. Redacted secret
reports, native dependency reports, Semgrep JSON, and gate decisions are
retained as workflow artifacts for 14 days.

## Build layer caching

Each scanner runs in its pinned (`@sha256:`) container, pulled by digest on every
run. Caching the scanner images was tried and dropped: on GitHub-hosted runners
the small/medium images (Gitleaks, TruffleHog, OSV-Scanner) pull fast enough that
an `actions/cache` round-trip saved no measurable wall-clock, and Semgrep's ~1 GB
image is too large to cache usefully. The images stay digest-pinned, so this is a
simplicity choice with no effect on what runs.

The `container-build` job caches Docker **layers** with buildx
`cache-from/cache-to: type=gha`, so an unchanged `npm ci` layer is restored
rather than rebuilt. This is a caching change only — the same Dockerfile and
context produce identical image content (verified: cached and uncached builds
yield the same rootfs layer digests). The one layer to keep in mind is
`RUN apk --no-cache upgrade`: while its cache is warm it will not re-pull newly
published Alpine patches, but the shipped image is still scanned by the
ECR scan-on-push deploy gate (`image-gate`) regardless of build cache, and the
weekly scheduled run rebuilds — so a stale patch layer cannot slip a new CVE
past delivery.

Only the security workflow has a Monday weekly schedule. This catches
advisories published for already-locked dependencies and refreshes the SAST
report without pointlessly scheduling the standalone application workflow.

`container-build` runs on **every** event except the weekly schedule —
including pull requests — because it also **scans the built image with Trivy
before merge**. It has only `contents: read`, holds no AWS credentials, builds
the Dockerfile, `docker save`s a tarball, and scans it with a digest-pinned Trivy
(`--input`, no Docker socket mounted; see `security/trivy-provenance.md`). A
digest-pinned Trivy plus `image-gate.mjs --source trivy` is the **pre-push image
gate**: a Critical/High CVE, a baked-in secret, an undetectable OS ("false
clean") or an end-of-life OS fails the check on the PR, not after merge. Trivy
runs with `--exit-code 0` — the reviewed gate decides, never the scanner.

Because container-build now runs on PRs, it no longer implicitly keeps the AWS
jobs off PRs. `aws-configuration` and `ecr-push` therefore carry an **explicit** guard —
`(push || workflow_dispatch) && ref == refs/heads/main` — and the OIDC trust
policies pin `sub` to `refs/heads/main`. `workflow_dispatch` is included because
it is manually triggered and sits in the same trust tier as merge access; the
security property that matters is that **`pull_request` is excluded**, so a PR
assumes no AWS role and reaches no delivery job (they `need` `ecr-push`, which is
skipped on a PR). The image artifact is uploaded only on `main`. On a BLOCK the image is
still built and scanned but never pushed or deployed — a wasted build, never an
unsafe one.

Delivery is split into four visibly-named jobs so the two-gate architecture is
legible in the Actions graph and each holds least-privilege credentials, rather
than one broad role for the whole sequence:

`ecr-push` → `image-scan` → `deploy-gate` → `deploy`

- `ecr-push` assumes the **push** role (ECR write only), loads the credential-free
  image artifact, and pushes the immutable + `demo` tags.
- `image-scan` assumes the **scan** role (`ecr:DescribeImageScanFindings` only),
  polls the scan-on-push result, and always uploads a report artifact.
- `deploy-gate` holds **no cloud credentials** (no `id-token`, no role): it only
  runs `image-gate.mjs` against the scan report. A Critical/High finding, or a
  missing/malformed report, makes it exit non-zero and the job **fails**.
- `deploy` assumes the **deploy** role (SSM only, no ECR) and runs the EC2/SSM
  deploy (`ssm-deploy.mjs` — no SSH, no inbound port).

Each job `needs` the previous, so a failed `deploy-gate` **skips** the `deploy`
job entirely — it never starts, which is a stronger guarantee than an in-job
early exit. No workflow-level AWS permission or static AWS access key is used;
three scoped OIDC roles replace the former single role (see `docs/aws-setup.md`).

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

The `security-gate` job is the security enforcement status. `main` branch
protection requires this exact check before merge; scanner jobs remain report
producers rather than three separate policy implementations. The repository
setting and its manual verification procedure are documented in
`docs/gating.md`.

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

For the controlled interaction demo, `workflow_dispatch` accepts
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
