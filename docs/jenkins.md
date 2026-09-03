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
4. **Install** runs `npm ci` against the committed lockfile. It never uses
   `npm install`.
5. **Lint** runs `npm run lint`.
6. **Test** runs the offline test suite with `npm test`.

The shell steps use Jenkins' default fail-fast behavior. A non-zero result from
install, lint, or test fails its stage and the build; there is no `catchError`,
`returnStatus`, or other mechanism that could turn a failure into success.

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

This pipeline binds no Jenkins credentials. Checkout, installation, linting,
and tests receive no AWS, ECR, Docker-registry, or deployment secrets. A
private repository may require a server-side SCM credential solely so the
Multibranch job can fetch the repository; it is branch-source configuration,
not a credential exposed by this pipeline to `npm ci` or application code.

Later phases may bind credentials only inside the specific image-push or
deployment stages that require them. No such stages exist in Phase 4.

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
pipeline security run.
