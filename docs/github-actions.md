# GitHub Actions

The application workflow runs for pull requests targeting `main`, pushes to
`main`, and manual dispatches. It has no schedule.

The workflow has only `contents: read` permission. It installs the committed
lockfile with `npm ci`, then runs ESLint and the offline test suite. It has no
cloud credentials and performs no image build or deployment.

Security checks live together in `.github/workflows/security.yml`. Its
`secret-scanning`, `dependency-scanning`, and `sast` jobs run in parallel with
no job credentials and do not persist checkout credentials. Findings remain
report-only. Redacted secret reports, native dependency reports, and Semgrep
JSON are retained as workflow artifacts for 14 days.

Only the security workflow has a Monday weekly schedule. This catches
advisories published for already-locked dependencies and refreshes the SAST
report without pointlessly scheduling the standalone application workflow.

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

Once `Application checks` is configured as a required status check for `main`
in GitHub branch protection, a failing `checks` job will block pull-request
merges. Branch protection is intentionally not configured yet: it is a
repository setting and should be finalized after the security gate exists.
