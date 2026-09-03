# GitHub Actions

The workflow runs for pull requests targeting `main`, pushes to `main`, and
manual dispatches. Phase 5 adds a Monday weekly schedule because security
scanning now exists; rerunning unchanged tests and lint alone would not have
justified a schedule.

The workflow has only `contents: read` permission. It installs the committed
lockfile with `npm ci`, then runs ESLint and the offline test suite. It has no
cloud credentials and performs no image build or deployment.

The parallel `secret-scanning` job checks full repository history with
digest-pinned Gitleaks and TruffleHog containers. Checkout credentials are not
persisted. Findings are report-only in Phase 5, and redacted JSON reports are
uploaded as the `secret-scan-reports` workflow artifact for 14 days.

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

Once `Application checks` is configured as a required status check for `main`
in GitHub branch protection, a failing `checks` job will block pull-request
merges. Branch protection is intentionally not configured yet: it is a
repository setting and should be finalized after the security gate exists.
