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

Only the security workflow has a Monday weekly schedule. This catches
advisories published for already-locked dependencies and refreshes the SAST
report without pointlessly scheduling the standalone application workflow.

For pull requests, the security workflow ends at `security-gate`: no image is
built and no AWS job is eligible. For a push or manual dispatch on `main`, a
passing gate starts `container-build`. That job has only `contents: read`,
builds the Dockerfile without AWS credentials, and uploads the image as a
one-day artifact. `aws-configuration` then checks the required repository
variables. If any are absent, it emits an explicit notice and `aws-delivery`
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
