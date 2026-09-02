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

The successful console log must show Checkout, Install, Lint, and Test, with
`npm ci`, ESLint, and all tests completing successfully. Local command
emulation is not a substitute for this controller result.

## Tear down

Always remove the controller and its Jenkins home after capturing the result:

```sh
docker compose -f jenkins/docker-compose.yml down -v
unset DEMO_GITHUB_TOKEN
```

Later phases can reuse this bring-up to verify Docker, ECR, and deployment
stages after those stages exist. The configuration is reusable, but the
controller is still ephemeral and must not run constantly.
