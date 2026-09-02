# GitHub Actions

Phase 3 introduces one application-quality job, `checks`, in
`.github/workflows/ci.yml`. It runs for pull requests targeting `main`, pushes
to `main`, and manual dispatches. A weekly schedule is intentionally deferred
until security scanning exists; rerunning unchanged tests and lint alone would
not detect newly published advisories.

The workflow has only `contents: read` permission. It installs the committed
lockfile with `npm ci`, then runs ESLint and the offline test suite. It has no
cloud credentials and performs no image build or deployment.

Third-party actions are pinned to full commit SHAs rather than movable tags.
The adjacent version comments retain readability while the immutable reference
prevents a release tag from silently resolving to different action code.

## Branch protection

Once `Application checks` is configured as a required status check for `main`
in GitHub branch protection, a failing `checks` job will block pull-request
merges. Branch protection is intentionally not configured yet: it is a
repository setting and should be finalized after the security gate exists.
