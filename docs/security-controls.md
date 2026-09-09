# Security controls

## Secret scanning

Gitleaks and TruffleHog overlap deliberately but answer different questions.

**Gitleaks** is the fast pattern-based scanner. It gives immediate feedback on
strings that look like credentials and scans Git history — the **full** history
on the weekly schedule, and the **incremental commit range** on pull-request and
push runs (`--log-opts=<base>..HEAD`; see `docs/github-actions.md`). For local
feedback, developers with Gitleaks installed can add a pre-commit hook that
runs `gitleaks git --pre-commit --staged --redact=100`; local hooks complement
CI but are not a trusted enforcement boundary.

**TruffleHog** combines pattern matching with live verification. For supported
credential types it contacts the credential provider and distinguishes a
working (`Verified: true`) credential from an unverified or unknown match.
That distinction drives the gate's verified-secret blocking rule; Gitleaks
alone cannot establish whether a detected credential is live.

TruffleHog's outbound verifier calls are not uses of the pipeline's AWS, ECR,
or deployment identity. The secret-scanning job has none of those credentials;
the scanner is testing whether an unrelated value found in repository content
is accepted by its provider.

Phase 10's secret fixture is deliberately **not** a provider credential, so it
cannot truthfully exercise `secrets.verified`. A narrowly named Gitleaks rule
detects the generated `DEMO_ONLY_SECRET_...` marker and routes only that rule ID
to `secrets.demo_dummy: BLOCK`. The demo therefore proves scanner-to-gate
blocking without manufacturing a working secret or mislabeling dummy data as
TruffleHog-verified. The synthetic Phase 8 unit test remains the safe proof of
the provider-verified policy path.

The scanner steps produce reports without interpreting policy. The shared
security gate now consumes those reports and blocks verified secrets while
logging unverified pattern matches. Keeping collection separate from policy
ensures GitHub Actions and Jenkins make the same decision.

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
distinct `MAL-` prefix used for known-malicious package advisories. The gate
therefore treats malicious packages as a separate policy path that blocks
regardless of severity, rather than treating them as ordinary vulnerable
dependencies.

Both Phase 6 tools scan the committed lockfile directly. Their native JSON is
archived unchanged as `npm-audit.json` and `osv-scanner.json`; no advisory IDs,
fix information, or severity data are discarded. GitHub Actions publishes them
in `dependency-scan-reports`, while Jenkins exposes both files under the
build's archived artifacts. The gate uses npm's `fixAvailable` and OSV's
affected-range `fixed` events to separate blocking fixable High/Critical
findings from visible non-blocking exceptions.

The security workflow and Jenkins pipeline run weekly because advisory data
can change even when the lockfile does not. The standalone application checks
workflow remains event-driven and has no cron schedule.

### Supply-chain install controls

Scanning finds *known* advisories; it does nothing against a brand-new
compromised release that has no advisory yet. Two complementary controls guard
that window, both built on the same 7-day rule:

- **`min-release-age=7` (`.npmrc`) — install-time, fail-closed.** npm refuses to
  install any dependency version published fewer than 7 days ago. This is now
  *implemented*, not deferred: the base image ships npm 10.x, which silently
  ignores the setting, so every install point pins npm to **12.0.2** first — the
  `ci.yml` application checks, the Jenkins `Install` stage, and the Dockerfile
  (which also copies `.npmrc`, so the image build honours the same floor). The
  self-upgrade runs under the old npm, which ignores `.npmrc`, so it is not
  itself blocked; the subsequent `npm ci` runs under npm 12 and enforces the
  floor. Verified: under npm 12.0.2 + `min-release-age=7`, both production and
  full `npm ci` install every currently-locked version, and the image builds
  clean. Older toolchains (npm 10.x) degrade gracefully — the setting is ignored,
  not an error — so a developer on stock npm is never blocked, just unprotected.
  The correct value is a bare number of days (`7`); the earlier `"7 days"` string
  form never shipped in npm.
- **Dependabot `cooldown: 7` (`.github/dependabot.yml`) — proposal-time,
  preventive.** Dependabot delays opening a version-bump PR until the release is
  at least 7 days old, so a too-fresh version is never proposed into the lockfile
  to begin with.

The distinction matters: the **cooldown delays PR creation** (upstream, before a
version can enter the lockfile), while **`min-release-age` blocks installation**
(downstream, refusing a too-fresh version even if it reached the lockfile another
way). Preventive plus fail-closed, one 7-day principle. Dependabot also advances
the repo's SHA-pinned GitHub Actions so those pins do not silently go stale.

Minor and patch Dependabot PRs are auto-merged once the required checks pass
(`.github/workflows/dependabot-auto-merge.yml`): the checks still gate the
merge, so a bump that fails dependency scanning, SAST, or tests never lands,
and — thanks to the cooldown and `min-release-age` — an auto-merged version is
already at least a week old. Major-version PRs are never auto-merged; they stay
open for manual review because they can carry breaking changes.

## Static application security testing

Semgrep OSS scans the application with two explicit Registry rulesets and one
repository-versioned rule file:

- `p/owasp-top-ten` provides a concise, recognizable set of checks mapped to
  common web-application risk categories.
- `p/javascript` adds JavaScript-specific correctness and security checks that
  are relevant to this Node.js service.
- `security/semgrep-rules.yml` is a repository-versioned high-confidence rule
  for request-data-to-command-shell injection. Unlike Registry content, its
  exact behavior changes only through code review in this repository.

The pipeline deliberately does not use `--config=auto`. Automatic selection
can alter the chosen rules without a repository change, making a live demo
harder to reproduce and explain. The named configurations make rule selection
intentional and allow the same command to be run locally. The Semgrep runtime
itself is pinned to the immutable digest for Semgrep OSS 1.176.0. Registry
rules can still evolve upstream; a production-grade control would vendor or
otherwise version the resolved rules as a further reproducibility measure.

Semgrep writes native JSON to `reports/semgrep.json`. The report validator
requires the expected result, error, and scanned-path structures and rejects
any scan errors, so malformed, truncated, or operationally failed output
cannot masquerade as a clean scan. GitHub Actions retains the report in
`sast-reports`; Jenkins archives the same file on the build. The security gate
then blocks new High/Critical matches and logs baseline-known backlog.

### Known-finding baseline

`security/baseline/semgrep-baseline.json` records findings formally accepted
as pre-existing. The current baseline was generated from the clean Phase 7
scan and is empty. Its fingerprints hash the rule ID, repository path, and
matched source text, allowing Phase 8 to distinguish a known match from a new
or changed one without storing vulnerable source snippets in the baseline.

When the team intentionally accepts a future finding during the rollout's
Tune phase, rerun the exact pinned Semgrep command, review every result, and
generate a candidate baseline with:

```sh
node security/scripts/generate-semgrep-baseline.mjs reports/semgrep.json
```

Review the candidate before replacing the checked-in baseline. Baseline
updates are policy decisions made through code review; CI must never update it
automatically.

An AI-based checker alongside Semgrep is a potential complementary control,
but it is deliberately deferred beyond the core 12-phase POC, as is broader
OWASP-style benchmarking. It is a future extension, not a missing Phase 7
requirement.

## Local reproduction

The root `Makefile` is the canonical local wrapper for the same commands used
by both CI systems:

```sh
make secrets
make dependencies
make sast
make security
make gate
make image-gate
make demo-malicious-package
make demo-dependency-no-fix
```

Scanner output is written beneath the ignored `reports/` directory. `make
gate` never scans implicitly; it evaluates exactly the reports present, so a
security engineer can download CI artifacts and reproduce the policy decision
without rerunning a scanner. Missing or malformed reports produce `BLOCK`, not
an apparent clean result. See `docs/gating.md` for the complete decision model.

## Safe live-demo fixtures

`security/fixtures/` is excluded by `.gitleaks.toml`,
`.trufflehog-exclude-paths.txt`, and `.semgrepignore`. Its dependency manifest
is standalone and absent from the application lockfile. The activation scripts
refuse to run unless the current branch is exactly the corresponding
`demo/phase-10-*` branch; activated snippets are never imported by the app.

Only three findings are activated live: a non-credential secret marker, an
isolated SAST pattern, and harmless historical `minimist` 1.2.5. OSV's official
record identifies that version as affected by GHSA-xvch-5gv4-984h
(CVE-2021-44906) and version 1.2.6 as fixed. Known-malicious packages are never
downloaded; their `MAL-` path and the unpredictable no-fix path use synthetic
gate reports through the two dedicated `make demo-*` targets.

## Container image scanning

ECR basic scan-on-push inspects operating-system packages in the built image.
This must remain separate from lockfile dependency scanning: the base image's
Alpine packages do not appear in `package-lock.json`, so npm audit and
OSV-Scanner cannot see them. Amazon Inspector enhanced continuous scanning is
a documented production upgrade; basic scanning is sufficient for this POC.

`poll-ecr-scan.mjs` polls `describe-image-scan-findings` and writes normalized
JSON without making the deploy decision. `image-gate.mjs` applies the shared
policy: Critical/High block deployment, Medium/Low log. Missing, malformed,
incomplete, or structurally inconsistent results also block deployment. The
decision is written to `reports/image-gate.json` and its process exit code is
used directly by both CI systems.

**This is not theater — it caught real vulnerabilities.** During the live AWS
delivery run, the scan-on-push of the `node:22.23.2-alpine3.24`-based image
returned **2 Critical + 7 High** findings, all real CVEs in the base image's
OpenSSL (`libcrypto3`/`libssl3` `3.5.7-r0`) — e.g. `CVE-2026-75803` and
`CVE-2026-63073`. The deploy gate **blocked** on them (`image-gate` verdict
`BLOCK_DEPLOY`, deploy stage skipped). Patching the base image
(`apk --no-cache upgrade` → OpenSSL `3.5.8-r0`, the version the advisories name
as the fix) produced a clean scan, the gate opened, and the EC2/SSM deploy ran.
None of these findings are visible to secret, dependency, or SAST scanning —
they live only in the built image, which is exactly why image scanning is a
distinct, post-push stage.
