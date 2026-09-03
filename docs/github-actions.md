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

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

The `security-gate` job is the security enforcement status. `main` branch
protection requires this exact check before merge; scanner jobs remain report
producers rather than three separate policy implementations. The repository
setting and its manual verification procedure are documented in
`docs/gating.md`.
