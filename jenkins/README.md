# Throwaway local Jenkins controller

This directory starts a disposable Jenkins controller for genuine development
verification of this repository's `Jenkinsfile`. It is not a production
Jenkins deployment and is separate from the CI/CD security controls being
demonstrated by the application pipeline.

The controller is deliberately bound to localhost, runs as root, has an
unsecured local UI/API, and can control the host Docker daemon. Those choices
make a short-lived local demonstration convenient and make persistent or
shared use unsafe. Start it only for verification and always tear it down with
its volume afterward.

## Prerequisites

- Docker with Compose support
- Host Docker client at `/usr/bin/docker`
- A GitHub PAT with read access to this repository if it is private

Export the token only in the shell that starts Compose. Never put it in this
repository or a Compose environment file:

```sh
export DEMO_GITHUB_TOKEN='<read-only GitHub PAT>'
```

Only `docker compose up` needs a real token for private-repository discovery.
Compose defaults the variable to the inert string `unset`, so this public
repository is discovered anonymously and read-only commands such as `config`
and `ps`, plus teardown with `down -v`, work after the shell variable has been
unset. If the repository becomes private, starting with that default cannot
authenticate and a read-only token must be exported first.

Anonymous public mode uses the generic Git branch source, avoiding GitHub's
very small unauthenticated API quota. Supplying a token switches JCasC to the
GitHub branch source. That authenticated mode is required if this demo needs
GitHub-specific pull-request head discovery; branch builds are sufficient for
the Phase 9 local verification.

The controller uses Jenkins' **Throttle at/near rate limit** strategy. This is
appropriate for one small, infrequently scanned demo repository and avoids the
multi-minute request spreading intended for busy shared controllers; GitHub's
real API limit is still enforced.

JCasC reads `${DEMO_GITHUB_TOKEN}` when the container starts, stores it as a
Jenkins username/password credential for branch discovery, and overrides the
same variable to an empty value in build-node environments. This keeps the
controller-start secret out of Docker agents and therefore out of `npm ci`.
Pull-request discovery is intentionally not enabled because the demo token
needs only repository-content read access. The
`Jenkinsfile` itself does not bind or expose that credential to install, lint,
test, or application code.

## Start and verify

```sh
docker compose -f jenkins/docker-compose.yml up -d
docker compose -f jenkins/docker-compose.yml logs -f controller
```

Wait until the log says Jenkins is fully up and running. The JCasC-managed
`secure-software-delivery` Multibranch Pipeline scans on creation and then once
per minute. Confirm job creation and inspect the discovered branch URLs:

```sh
curl -fsS 'http://127.0.0.1:8080/job/secure-software-delivery/api/json?tree=name,jobs[name,url,color]'
```

Use the returned URL for `feature/phase-4-jenkins` to inspect its last build:

```sh
curl -fsS '<branch-url>lastBuild/api/json?tree=number,result,building,url'
curl -fsS '<branch-url>lastBuild/consoleText'
```

On a feature branch, the successful console log must show Checkout, parallel
Gitleaks and TruffleHog scans, parallel npm audit and OSV-Scanner lockfile
scans, Semgrep SAST, Security Gate, Install, Lint, and Test; all post-gate
delivery stages are skipped because only `main` can build. After merging,
verify a non-scheduled `main` build also completes Docker Build. With the default
`ENABLE_AWS_DELIVERY=false`, it must print the explicit AWS-not-configured
message and show ECR Push, Image Scan, Deploy Gate, and Deploy as skipped.
Confirm the five scanner reports,
`security-gate.json`, and `gate-exceptions.json` appear under **Build
Artifacts**, then confirm the gate prints `SECURITY GATE: PASS`, `npm ci`,
ESLint, all tests, and the Docker build complete successfully. Local command
emulation is not a substitute for this controller result.

## Tear down

Always remove the controller and its Jenkins home after capturing the result:

```sh
docker compose -f jenkins/docker-compose.yml down -v
unset DEMO_GITHUB_TOKEN
```

Future verification can reuse this bring-up for real ECR and deployment runs
after AWS exists and the credentials documented in `docs/aws-setup.md` are
created. The configuration is reusable, but the controller is still ephemeral
and must not run constantly.
