# Jenkins

The declarative pipeline provides the Jenkins equivalent of the GitHub Actions
checks. Application stages use the exact runtime image used by the application
container: `node:22.23.2-alpine3.24`.

## Pipeline stages

1. **Checkout** runs the standard `checkout scm` step. Automatic declarative
   checkout is disabled so this boundary remains explicit in the demo.
2. **Security scanning** runs all five scanners as a single `parallel` block —
   Gitleaks, TruffleHog, `npm audit`, and OSV-Scanner (all in digest-pinned
   containers), plus digest-pinned Semgrep OSS with the named `p/owasp-top-ten`
   and `p/javascript` rulesets. Each leaf stage validates and archives its
   native/redacted JSON. This matches the three parallel scanner jobs in GitHub
   Actions; because Declarative Pipeline does not allow nested `parallel`, the
   secret and dependency scanners are flattened into sibling leaf stages rather
   than grouped. None of these stages touch AWS credentials, so the gate and
   every delivery stage stay serialized after this block. Phases 5/6 log
   findings without failing the build.
3. **Security Gate** calls the shared Node evaluator against all five scanner
   reports and the checked-in Semgrep baseline. Its process exit code directly
   fails the pipeline on `BLOCK`; Jenkins does not reimplement policy in
   Groovy. The decision and exception files are archived even on failure.
4. **Install** runs `npm ci` against the committed lockfile. It never uses
   `npm install`.
5. **Lint** runs `npm run lint`.
6. **Test** runs the offline test suite with `npm test`.
7. **Docker Build** builds the Phase 2 Dockerfile without AWS credentials on a
   non-scheduled `main` build.
8. **AWS Configuration** states whether delivery is enabled. The default is
    disabled and emits a visible skip explanation.
9. **ECR Push**, **Image Scan**, **Deploy Gate**, and **Deploy** run only when
    `ENABLE_AWS_DELIVERY` is explicitly enabled. The image gate calls the same
    fail-closed Node script used by GitHub Actions, and **Deploy** runs the same
    shared `ssm-deploy.mjs` — an EC2 deploy over AWS Systems Manager
    (`aws ssm send-command`), not ECS and not SSH.

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
ECR-only policy for the former and an SSM-only policy for the latter
(`ssm:SendCommand` on the instance + `AWS-RunShellScript` document, and
`ssm:GetCommandInvocation`). The credentials exist only inside their
`withCredentials` blocks.

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

With the default `ENABLE_AWS_DELIVERY=false`, a Jenkins run shows Docker Build
succeeding, AWS Configuration printing the not-configured message, and all four
AWS-dependent stages skipped. The EC2/SSM conversion (detection on
`EC2_INSTANCE_ID`, the `ssm-deploy.mjs` Deploy stage) has been **confirmed
correct on a real controller run** — a parameterized `main` build reached the
AWS path and printed "EC2/SSM deploy stages will run". However, the SSM **Deploy
stage itself has not executed against real AWS**: the run stopped at ECR Push
because this controller lacks the `jenkins-aws-ecr` credential (deliberately
deferred). So the Jenkins EC2/SSM deploy is **structured-but-unverified** — do
not read it as proven. GitHub Actions is the platform where the full delivery
path ran for real.

For an eligible security BLOCK, Jenkins first runs the shared eligibility
check without credentials. Only then does it bind the Secret Text credential
`break-glass-shared-secret`, notify the break-glass service, and poll for the
decision (Slack is the active approval platform; Discord is frozen).
`CHANGE_ID` supplies the PR number for Multibranch PR builds;
`BREAK_GLASS_PR_NUMBER` is the manual fallback. A hard block, denied decision,
timeout, missing credential, or endpoint error propagates as a failed stage.

## Commit-range scan scope

The Checkout stage resolves an incremental base the same way as GitHub Actions:
PR builds (`CHANGE_ID`) diff against `git merge-base origin/$CHANGE_TARGET HEAD`;
`main` builds diff against the previously built commit (`GIT_PREVIOUS_COMMIT`);
the weekly `cron` build (a `TimerTrigger`) and first builds scan full history.
The resolved flags (`--log-opts`, `--since-commit`, `--baseline-commit`) are
exported as env vars and consumed by the Gitleaks, TruffleHog, and Semgrep
stages. npm audit and OSV-Scanner are unaffected (lockfile state, not history).
