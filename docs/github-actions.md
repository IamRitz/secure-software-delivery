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

## Scanner image caching

Ephemeral runners start with an empty Docker store, so each scanner job would
otherwise pull its pinned container image over the network on every run. The
secret and dependency jobs instead restore their images (Gitleaks, TruffleHog,
OSV-Scanner) from an `actions/cache`, via `security/scripts/cache-scanner-image.sh`:

- **Keyed on the digest, never on "latest".** The cache key is
  `hashFiles('.github/workflows/security.yml')` — the workflow file that holds the
  `@sha256:` pins. Bumping a pin changes the hash, so the next run is a cache
  **miss** that pulls the new digest fresh and repopulates the cache. The cache
  can therefore never keep you on a stale image: to update a scanner you bump
  its digest exactly as before, and the cache follows automatically.
- **Exact key only, no `restore-keys`.** A near-miss prefix is never loaded, so
  a stale tarball can never masquerade as the pin. A miss always pulls
  **by digest** (content-verified), then tags and saves it. The local tag exists
  only because `docker load` does not restore a manifest digest reference, so the
  scanner is run by that tag; the content is still exactly the pinned image.

**Semgrep is deliberately not cached.** Its image is ~1 GB (~423 MB compressed),
about the same size as the registry pull it would replace — restoring it from the
GitHub cache is no faster than pulling it, and it would consume a large share of
the 10 GB per-repo cache budget. Caching pays off only where the stored tarball
is much smaller than a fresh pull, which holds for the small/medium scanners
(Gitleaks ~25 MB, TruffleHog ~46 MB, OSV-Scanner ~105 MB compressed) but not for
Semgrep. Semgrep is pulled by its pinned digest on every run.

The `container-build` job caches Docker **layers** separately with buildx
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

For pull requests, the security workflow ends at `security-gate`: no image is
built and no AWS job is eligible. For a push or manual dispatch on `main`,
`container-build` runs **in parallel** with the scanners and the gate rather
than after them. It has only `contents: read`, holds no AWS credentials, builds
the Dockerfile (with a `type=gha` layer cache so an unchanged `npm ci` layer is
restored instead of rebuilt), and uploads the image as a one-day artifact.
Because it holds no credentials it does not wait for the gate; the credential
boundary is enforced on the jobs that follow. `aws-configuration` and
`aws-delivery` both require `needs.security-gate.result == 'success'`, so on a
BLOCK the parallel image is built but never pushed or deployed — a wasted
build, never an unsafe one. `aws-configuration` checks the required repository
variables; if any are absent, it emits an explicit notice and `aws-delivery`
shows as skipped.

`aws-delivery` is the only job with `id-token: write`. It downloads the
already-built image before obtaining a short-lived AWS identity through OIDC,
then performs ECR push, image scan, the fail-closed deploy gate, and the EC2
deploy over AWS Systems Manager (`ssm-deploy.mjs` — no SSH, no inbound port).
This artifact handoff is intentional: Docker's `npm ci` build
layer never runs while AWS credentials are present. No workflow-level AWS
permission or static AWS access key is used. See `docs/aws-setup.md`.

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
