# Jenkins

The declarative pipeline provides the Jenkins equivalent of the GitHub Actions
checks. Application stages use the exact runtime image used by the application
container: `node:22.23.2-alpine3.24`.

## Pipeline stages

1. **Checkout** runs the standard `checkout scm` step. Automatic declarative
   checkout is disabled so this boundary remains explicit in the demo.
2. **Secret scanning** runs Gitleaks and TruffleHog in parallel, in
   digest-pinned containers, and archives their redacted JSON reports. Phase 5
   logs findings without failing the build.
3. **Dependency scanning** runs `npm audit` and OSV-Scanner in parallel against
   `package-lock.json`, preserves their native JSON, and archives both reports.
   Phase 6 logs findings without failing the build.
4. **SAST** runs digest-pinned Semgrep OSS with the named `p/owasp-top-ten` and
   `p/javascript` rulesets, validates its native JSON, and archives the report.
5. **Security Gate** calls the shared Node evaluator against all five scanner
   reports and the checked-in Semgrep baseline. Its process exit code directly
   fails the pipeline on `BLOCK`; Jenkins does not reimplement policy in
   Groovy. The decision and exception files are archived even on failure.
6. **Install** runs `npm ci` against the committed lockfile. It never uses
   `npm install`.
7. **Lint** runs `npm run lint`.
8. **Test** runs the offline test suite with `npm test`.
9. **Docker Build** builds the Phase 2 Dockerfile without AWS credentials on a
   non-scheduled `main` build.
10. **AWS Configuration** states whether delivery is enabled. The default is
    disabled and emits a visible skip explanation.
11. **ECR Push**, **Image Scan**, **Deploy Gate**, and **Deploy** run only when
    `ENABLE_AWS_DELIVERY` is explicitly enabled. The image gate calls the same
    fail-closed Node script used by GitHub Actions.

The image-scan polling helper runs in an exact-version, digest-pinned Node 22
slim container with the controller's Docker client and socket mounted so it
can invoke the digest-pinned AWS CLI container. This avoids installing tooling
while AWS credentials are present. Application execution remains on the exact
`node:22.23.2-alpine3.24` runtime used by the Dockerfile and GitHub checks.

The shell steps use Jenkins' default fail-fast behavior. A non-zero result from
the gate, install, lint, or test fails its stage and the build; there is no
`catchError`, `returnStatus`, or other mechanism that could turn a failure into
success.

## One-time Jenkins setup

The committed `Jenkinsfile` does not create a server-side job. An administrator
must perform this setup once:

1. Ensure the Jenkins instance has Pipeline, Docker Pipeline, Git, and the
   branch-source plugin appropriate for the repository host. Its agents must be
   able to run Docker containers.
2. Create a **Multibranch Pipeline** job (or an Organization Folder that
   creates equivalent jobs).
3. Add this repository as the branch source and configure repository access if
   the repository itself is private.
4. Keep the script path as `Jenkinsfile`, then scan the branch source so Jenkins
   discovers branches and pull requests containing the file.
5. Run the discovered branch and confirm Checkout, Install, Lint, and Test all
   complete successfully.

Pull-request discovery and build timing depend on the selected branch-source
plugin and Jenkins instance configuration. Configure either repository
webhooks or periodic branch-source polling; unlike GitHub Actions' built-in
`pull_request` event, the `Jenkinsfile` cannot choose that server-side trigger.

## Credentials

Checkout, scanning, the security gate, installation, linting, tests, and the
Docker build bind no AWS, ECR, registry, or deployment credentials. A private
repository may require a server-side SCM credential solely for Multibranch
discovery; JCasC prevents it from entering build environments.

When AWS delivery is enabled, ECR push and scan bind only the
`jenkins-aws-ecr` username/password credential, mapping the access-key ID to
the username and secret key to the password. Deploy binds a separate
`jenkins-aws-deploy` credential. Keeping these identities separate permits an
ECR-only policy for the former and an ECS-update-only policy for the latter.
The credentials exist only inside their `withCredentials` blocks.

Static IAM access keys are a deliberate Jenkins tradeoff because a controller
does not receive GitHub-hosted runner OIDC tokens. Prefer workload identity or
short-lived credentials when the Jenkins platform supports them. For this
throwaway POC, store keys only in Jenkins Credentials, rotate them, and grant
the minimal policies in `docs/aws-setup.md`; never add them to parameters,
JCasC, source files, or controller-start environment variables.

## Verification status

The stage commands can be reproduced locally in the pinned agent image:

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace \
  node:22.23.2-alpine3.24 npm ci
docker run --rm -v "$PWD:/workspace" -w /workspace \
  node:22.23.2-alpine3.24 npm run lint
docker run --rm -v "$PWD:/workspace" -w /workspace \
  node:22.23.2-alpine3.24 npm test
```

The Phase 4 baseline was executed by a JCasC-provisioned throwaway Jenkins
2.541.3 controller using the procedure in `jenkins/README.md`. Jenkins parsed
the declarative pipeline, automatically discovered the feature branch, and
reported `SUCCESS` after Checkout, Install, Lint, and Test. Repeat that
controller-backed check after changing the pipeline; local Docker execution
alone is not a substitute for Jenkins validation.

The demo uses a read-only GitHub PAT, so Jenkins may log that it cannot publish
a commit status. That expected 403 does not affect checkout or the build
result, and granting write access solely to remove the message would violate
the demo's least-privilege intent.

The Jenkinsfile has its own Monday `cron` trigger to rerun the pipeline and
refresh advisory results. This is separate from the JCasC Multibranch job's
one-minute folder scan, which discovers branch revisions but is not a periodic
pipeline security run. Scheduled and non-`main` builds stop before Docker, so
pull requests and weekly refreshes remain checks-and-gate only.

Phase 9 verification uses the default `ENABLE_AWS_DELIVERY=false`. A genuine
Jenkins run must show Docker Build succeeding, AWS Configuration printing the
not-configured message, and all four AWS-dependent stages as skipped. ECR,
image scan, and ECS deployment remain unverified until real AWS resources and
both documented Jenkins credentials exist.

For an eligible security BLOCK, Jenkins first runs the shared eligibility
check without credentials. Only then does it bind the Secret Text credential
`break-glass-shared-secret`, notify n8n, and poll for the Discord decision.
`CHANGE_ID` supplies the PR number for Multibranch PR builds;
`BREAK_GLASS_PR_NUMBER` is the manual fallback. A hard block, denied decision,
timeout, missing credential, or endpoint error propagates as a failed stage.
