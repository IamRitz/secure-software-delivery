# Security controls

## Secret scanning

Gitleaks and TruffleHog overlap deliberately but answer different questions.

**Gitleaks** is the fast pattern-based scanner. It gives immediate feedback on
strings that look like credentials and scans full Git history in CI. For local
feedback, developers with Gitleaks installed can add a pre-commit hook that
runs `gitleaks git --pre-commit --staged --redact=100`; local hooks complement
CI but are not a trusted enforcement boundary.

**TruffleHog** combines pattern matching with live verification. For supported
credential types it contacts the credential provider and distinguishes a
working (`Verified: true`) credential from an unverified or unknown match.
That distinction will drive Phase 8's verified-secret blocking rule; Gitleaks
alone cannot establish whether a detected credential is live.

TruffleHog's outbound verifier calls are not uses of the pipeline's AWS, ECR,
or deployment identity. The secret-scanning job has none of those credentials;
the scanner is testing whether an unrelated value found in repository content
is accepted by its provider.

Phase 5 is intentionally **report-only**. Findings are logged and retained as
redacted JSON artifacts, but do not fail either CI system. This is the rollout
model's log-first phase; blocking policy is introduced only after findings can
be baselined and the Phase 8 gate exists.

GitHub Actions stores both reports in the `secret-scan-reports` artifact.
Jenkins archives `reports/gitleaks.json` and `reports/trufflehog.json` on their
respective build. TruffleHog's raw JSONL is normalized and deleted before
archival so raw credential fields are not retained.

## Dependency scanning

**npm audit** queries the GitHub Advisory Database for the npm dependency graph
recorded in `package-lock.json`. It is built into npm and provides a fast,
ecosystem-specific view without installing dependencies.

**OSV-Scanner** queries OSV.dev, which aggregates advisories across sources and
ecosystems. Its native JSON retains each advisory's `id`, including the
distinct `MAL-` prefix used for known-malicious package advisories. Phase 8 can
therefore treat malicious packages as a separate policy path that blocks
regardless of severity, rather than treating them as ordinary vulnerable
dependencies.

Both Phase 6 tools scan the committed lockfile directly. Their native JSON is
archived unchanged as `npm-audit.json` and `osv-scanner.json`; no advisory IDs,
fix information, or severity data are discarded. Findings are report-only in
this phase. GitHub Actions publishes them in `dependency-scan-reports`, while
Jenkins exposes both files under the build's archived artifacts.

The security workflow and Jenkins pipeline run weekly because advisory data
can change even when the lockfile does not. The standalone application checks
workflow remains event-driven and has no cron schedule.
