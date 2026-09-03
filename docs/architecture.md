# Pipeline architecture

The architecture follows one fact: package installation and builds execute
third-party code. That code must not share a job or stage with cloud or deploy
credentials.

```text
checkout
  ├─ secret scan ───────┐
  ├─ dependency scan ───┼─> SECURITY GATE ─BLOCK─> stop
  └─ SAST ──────────────┘          │
                                  PASS
                                   │
                             Docker build
                                   │
                     AWS configuration detection
                         │                    │
                     absent                 present
                         │                    │
                 visible clean skip     ECR push → image scan
                                                  │
                                           DEPLOY GATE
                                           │          │
                                    BLOCK_DEPLOY     DEPLOY
                                           │          │
                                          stop      ECS deploy
```

Every component through the security gate has zero AWS/ECR/deployment
credentials. The Docker image is also built without them. GitHub Actions then
passes that built image as an artifact into the only OIDC-enabled job; Jenkins
binds narrowly scoped credentials only inside ECR or deploy stages. This is
the pipeline's credential boundary, not merely a naming convention.

Pull requests run through the security gate only. Pushes and manual dispatches
on `main` may build and deliver. Weekly runs refresh the security reports and
gate but do not build or deploy.

Application install, lint, and unit-test checks also run without credentials.
They remain in the standalone GitHub CI workflow and as explicit Jenkins
stages; they are omitted from the diagram to keep the security boundary clear.

Image scanning is post-build because an application lockfile cannot describe
operating-system packages inherited from the Node Alpine base image. ECR basic
scan-on-push covers that POC need. Amazon Inspector enhanced continuous
scanning is a production upgrade, not part of this small demonstration.

> **AWS-dependent stages: structured and unit-tested, not yet run against real
> infrastructure.** Local Docker build and deploy-gate decisions are verified;
> ECR push, ECR scanning, and ECS deployment are not claimed as successful.

AWS prerequisites and least-privilege policies are in `docs/aws-setup.md`.
