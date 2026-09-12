# Secure Software Delivery

A deliberately small Node.js and Express REST API used to demonstrate a secure
CI/CD pipeline in GitHub Actions and Jenkins.

> `npm install` and `pip install` do not just download packages: they run
> someone else's code on the runner with whatever credentials that runner is
> holding. Therefore, untrusted install/build code must never run in a job that
> holds AWS, ECR, or deployment credentials.

That principle defines the pipeline boundary. GitHub Actions and Jenkins run
tests plus secret, dependency, and static-analysis scans without cloud or
deployment credentials. A shared fail-closed security gate evaluates their
reports before image build or deployment work can begin.

On a `main` push, a passing security gate permits a credential-free Docker
build. Only the subsequent AWS delivery job can request a short-lived AWS
identity. If AWS is not configured, that delivery path is visibly skipped.

## Requirements

- Node.js 22 or newer
- npm
- Docker (optional)

## Run locally

```sh
npm ci
npm test
npm run lint
npm start
```

The committed lockfile is authoritative. Local automation and all CI
jobs must use `npm ci`, never `npm install`, so dependency resolution cannot
silently rewrite it. `.npmrc` enables `min-release-age=7`, which refuses to
install any dependency version published in the last 7 days — a fail-closed
guard against freshly-compromised releases. Every install point (the `ci.yml`
checks, Jenkins, and the Dockerfile) pins npm to 12.0.2 to enforce it; work
locally with npm 11.10 or newer for the same protection (npm 10.x silently
ignores the setting, so it degrades gracefully rather than breaking). This is
the install-time twin of Dependabot's 7-day `cooldown`
(`.github/dependabot.yml`), which keeps too-fresh versions out of proposed
updates in the first place.

The service listens on `http://localhost:3000` by default. Set `PORT` to use a
different port.

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Return service health |
| `GET` | `/api/users` | List in-memory users |
| `GET` | `/api/products` | List sample products |
| `POST` | `/api/users` | Create an in-memory user |

Create a user with a JSON body containing `name` and `email`:

```sh
curl -X POST http://localhost:3000/api/users \
  -H 'content-type: application/json' \
  -d '{"name":"Katherine Johnson","email":"katherine@example.com"}'
```

Data is intentionally in memory and resets whenever the process restarts.

## Container

```sh
docker build -t secure-software-delivery:phase2 .
docker run --rm -p 3000:3000 secure-software-delivery:phase2
```

## Reproduce security checks locally

The Make targets use the same digest-pinned scanner images, named rulesets,
flags, report paths, policy, and gate script as CI:

```sh
make secrets       # Gitleaks and TruffleHog
make dependencies  # npm audit and OSV-Scanner
make sast          # Semgrep OSS
make security      # all scanner targets above
make gate          # evaluate the reports currently in reports/
make image-gate    # evaluate reports/ecr-image-scan.json before deployment
make demo-malicious-package  # synthetic gate-only BLOCK; installs nothing
make demo-dependency-no-fix  # synthetic PASS-WITH-EXCEPTIONS
```

Run the complete clean-repository path with `make security && make gate`.
The gate exits zero for `PASS` and `PASS-WITH-EXCEPTIONS`, and non-zero for
`BLOCK`. Its detailed decision and separately tracked exceptions are written
to `reports/security-gate.json` and `reports/gate-exceptions.json`.

Safe, inert fixtures for live BLOCK-then-PASS demonstrations live under
[`security/fixtures/`](security/fixtures/). Follow the copy-pasteable branch,
activation, cleanup, and synthetic-input commands in
[`docs/demo.md`](docs/demo.md). Activated demo branches must never be merged.

## Security stages and what each catches

| Stage | Tools | Catches | Runs |
| --- | --- | --- | --- |
| Secret scanning | Gitleaks, TruffleHog | credentials in git history (pattern + live verification) | pre-build |
| Dependency scanning | npm audit, OSV-Scanner | known-vulnerable and known-**malicious** (`MAL-`) packages | pre-build |
| SAST | Semgrep OSS (named rulesets) | dangerous patterns in the app's own source | pre-build |
| Image scanning | ECR basic scan-on-push | vulnerable OS packages in the built image | post-push |

Secret and SAST scans are **incremental** on `pull_request`/`push` (commit range
only) and full on the weekly schedule — see
[`docs/github-actions.md`](docs/github-actions.md).

The GitHub pipeline is **reusable security workflows plus thin callers**:
`_source-security.yml`, `_image-scan-prepush.yml`, `_artifact-gate.yml`, and the
`_ecr-collect.yml` registry adapter, called by `security.yml` (pull requests and
the weekly schedule) and `deploy.yml` (push to `main` and manual dispatch). The
onboarding interface — every input, output, and portability rule — is
[`docs/workflow-contracts.md`](docs/workflow-contracts.md).

## The gate — three states, fail-closed

The shared evaluator (`security/scripts/security-gate.mjs`) returns **PASS**,
**BLOCK**, or **EXCEPTION** (`PASS-WITH-EXCEPTIONS`). EXCEPTION exists for the
real middle case — a critical/high dependency finding with **no fix available**
is recorded visibly and allowed, rather than blocking indefinitely on an
upstream patch you don't control. A missing report, malformed JSON, or a
report-integrity failure all **block** — the safe outcome is always the default.

## Break-glass — a scoped human override

An eligible BLOCK can enter an authenticated approval flow. **Slack is the
active platform**; the Discord implementation is built and tested but
intentionally **frozen/dormant** (not deleted, not in active use). Only two
finding classes are eligible — **new SAST** and **fixable dependency** blocks.
**Verified secrets and known-malicious packages can never be overridden**, and
dependency-no-fix findings aren't eligible because they're already handled as
EXCEPTION (there's nothing to override). Approvers are **per-repo**
(`SLACK_APPROVER_IDS_BY_REPO`, fail-closed — a repo with no entry authorizes
nobody). Details in [`docs/gating.md`](docs/gating.md).

## Delivery (AWS)

On a `main` push with a passing gate, the credential-free image is pushed to
ECR (via GitHub OIDC — no stored keys), scanned on push, evaluated by the deploy
gate, and, if clean, deployed to an **EC2 Docker host over AWS Systems Manager**
(`aws ssm send-command` — no SSH, no inbound port 22). This has been run against
real AWS on GitHub Actions, and the ECR scan genuinely caught real Critical/High
OpenSSL CVEs in the base image, which the deploy gate blocked until a base-image
patch fixed them — see [`docs/aws-setup.md`](docs/aws-setup.md). The Jenkins
pipeline performs the same conversion but its SSM deploy stage is
structured-but-unverified (see [`docs/jenkins.md`](docs/jenkins.md)).

## Adopting this in another repo

See [`docs/workflow-contracts.md`](docs/workflow-contracts.md) for the contracts
and [`docs/onboarding.md`](docs/onboarding.md) for the rollout: reusable workflow / shared
library rather than copy-paste, generating a Semgrep baseline first, and the
LOG-before-BLOCK rollout.
