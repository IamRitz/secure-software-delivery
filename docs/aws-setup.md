# AWS setup for the Phase 9 delivery path

> **Status: delivery targets an EC2 Docker host over AWS Systems Manager** (ECR
> push + scan-on-push + `aws ssm send-command` running `docker pull`/`docker run`
> on the instance — no SSH, no inbound port 22). This has **run against real AWS
> on GitHub Actions**, verified end-to-end with the app responding on `/health`;
> the ECR scan caught real base-image OpenSSL CVEs that the deploy gate blocked
> until a base-image patch fixed them. The Jenkins equivalent is converted and
> confirmed correct on a real controller run but its SSM deploy stage is
> structured-but-unverified (see `docs/jenkins.md`).

The workflow remains safe and useful without AWS. It builds the container on a
`main` push, prints which configuration is missing, and marks `aws-delivery`
skipped. Configure the following only when a disposable demo AWS environment
is available.

## Digest chaining (scan == deploy)

The thing Trivy scanned, the thing ECR scanned, and the thing EC2 runs are bound
to a single immutable digest so a mutable tag can never be swapped in between:

1. **build → scan:** `_image-scan-prepush.yml` records Trivy's
   `Metadata.ImageID` (the image config digest) as a workflow output.
2. **scan → push:** `_ecr-collect.yml` asserts the loaded artifact's
   `docker inspect .Id` equals that ImageID (passed in as `expected_image_id`)
   before pushing, then records the pushed **manifest digest**.
3. **push → ECR scan:** the same collector polls ECR
   `--image-digest <that manifest digest>`; `poll-ecr-scan.mjs` asserts ECR
   scanned exactly that digest.
4. **scan → gate:** `_artifact-gate.yml` re-asserts the report's digest equals
   the `expected_digest` the collector pushed, before running `image-gate.mjs`.
5. **gate → deploy:** `deploy` runs `ssm-deploy.mjs --image-digest`, so the
   instance `docker pull`s `registry/repo@sha256:…`, never a tag.

## GitHub Actions: OIDC, not access keys

1. Add the GitHub OIDC provider in IAM with URL
   `https://token.actions.githubusercontent.com` and audience
   `sts.amazonaws.com`.
2. Create **two** IAM roles for this repository. ECR push and the ECR
   scan-findings read are both registry operations on the same repository, so
   they share one role (assumed in `_ecr-collect.yml`); the SSM **deploy** role — the
   credentials that can reach the instance — stays separate, which is the
   boundary that matters. No single role can both push an image and deploy it.
   `_image-scan-prepush.yml` and `_artifact-gate.yml` assume no role at all (they
   only scan a tarball / evaluate a report). Both roles share the **same trust
   policy** (audience above + the exact `main` subject); only their permission
   policies differ. This repository was created after GitHub introduced immutable
   OIDC subjects, so use its permanent owner and repository IDs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:IamRitz@26003726/secure-software-delivery@1354576659:ref:refs/heads/main"
      }
    }
  }]
}
```

Before relying on this example, inspect a real job's OIDC claims and confirm
the `sub` value; older repositories that have not opted into immutable
subjects use `repo:IamRitz/secure-software-delivery:ref:refs/heads/main`.
Never broaden this to all repositories or pull-request subjects.

3. Attach one **least-privilege** policy per role. Each is limited to this ECR
   repository / this EC2 instance, and each job gets only what it needs:

   **Push+scan role** — assumed by `_ecr-collect.yml`. ECR write **and**
   scan-findings read on this repo; no SSM:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*" },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
        "ecr:DescribeImageScanFindings"
      ],
      "Resource": "arn:aws:ecr:<REGION>:<ACCOUNT_ID>:repository/secure-software-delivery"
    }
  ]
}
```

   **Deploy role** — assumed by the `deploy` job. SSM only; **no ECR access at all**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ec2:<REGION>:<ACCOUNT_ID>:instance/<INSTANCE_ID>",
        "arn:aws:ssm:<REGION>::document/AWS-RunShellScript"
      ]
    },
    { "Effect": "Allow", "Action": "ssm:GetCommandInvocation", "Resource": "*" }
  ]
}
```

`ssm:SendCommand` needs **both** the instance ARN and the `AWS-RunShellScript`
document ARN. `ssm:GetCommandInvocation` cannot be scoped to the instance and
must be granted on `*` — a hard-won detail: scoping it to the instance ARN
silently denies the read-back and the deploy hangs then fails. The deploy role
holds **no ECR permissions** — the EC2 instance pulls the image with its **own**
role (`AmazonSSMManagedInstanceCore` + read-only ECR pull); no runner role,
push or otherwise, is ever shared with the box. The `artifact-gate` job holds no
AWS credentials whatsoever (it declares no `id-token` and assumes no role).

4. Add these GitHub **repository variables**, not static AWS secrets:

| Variable | Example |
| --- | --- |
| `AWS_PUSH_SCAN_ROLE_ARN` | `arn:aws:iam::123456789012:role/ssd-ecr-push-scan` |
| `AWS_DEPLOY_ROLE_ARN` | `arn:aws:iam::123456789012:role/ssd-deploy` |
| `AWS_REGION` | `us-east-1` |
| `ECR_REPOSITORY` | `secure-software-delivery` |
| `EC2_INSTANCE_ID` | `i-0123456789abcdef0` (the SSM deploy target) |
| `EC2_APP_PORT` (optional) | host port mapped to container `3000` (default `3000`) |

Delivery targets an **EC2 instance running Docker** (not ECS), driven over **AWS
Systems Manager**, not SSH: the runner pushes the image to ECR under the OIDC push
role, then `aws ssm send-command` runs `docker login`/`pull`/`run` on the instance
(polled via `ssm:GetCommandInvocation`). The image is pulled using the
**instance's own read-only ECR role**, so the runner's push credentials never
reach the box, and **no inbound port (22 or otherwise) is required**.

`aws-configuration` requires both role ARNs (`AWS_PUSH_SCAN_ROLE_ARN`,
`AWS_DEPLOY_ROLE_ARN`) plus `AWS_REGION`, `ECR_REPOSITORY`, and
`EC2_INSTANCE_ID`; otherwise the AWS stages are skipped. The instance needs
Docker, the AWS CLI, and the SSM agent, with `AmazonSSMManagedInstanceCore` on its
role; the deploy role needs `ssm:SendCommand` + `ssm:GetCommandInvocation` scoped
to the instance and holds no ECR access. The Jenkins pipeline uses the same
`ssm-deploy.mjs` script with an `EC2_INSTANCE_ID` parameter and the
`jenkins-aws-deploy` credential (Jenkins already splits ECR vs deploy into two
credentials — the GitHub roles now match that separation, and add a third
scan-only role).

> **Port 22 is not used by CI.** SSM needs no inbound SSH. The SSM path is
> verified, so the old `EC2_SSH_PRIVATE_KEY` secret has been deleted and port 22
> closed in the security group. Reopen it only, restricted to specific known IPs,
> for occasional manual human debugging — separate from CI, which no longer
> touches it.

Only `aws-delivery` declares `id-token: write`; workflow and pre-build jobs
remain `contents: read`. The workflow pins `configure-aws-credentials` and
`amazon-ecr-login` to immutable commits. AWS recommends OIDC-backed temporary
credentials; see the official
[action documentation](https://github.com/aws-actions/configure-aws-credentials#oidc-configuration).

## ECR and EC2 deployment

Create the repository with basic scan-on-push enabled:

```sh
aws ecr create-repository \
  --repository-name secure-software-delivery \
  --image-scanning-configuration scanOnPush=true \
  --region <REGION>
```

The pipeline polls the official
[`describe-image-scan-findings`](https://docs.aws.amazon.com/AmazonECR/latest/userguide/describe-scan-findings.html)
API for the immutable commit tag and fails closed at the deploy gate. Basic
scanning covers image OS packages; Amazon Inspector enhanced continuous
scanning can replace it in production.

The deploy runs a remote command on the EC2 instance via SSM: `docker login`
to ECR (using the instance's own role), `docker pull` the immutable
commit-SHA image, then `docker rm -f` + `docker run` the container mapped to
`EC2_APP_PORT`. It also tags `:demo` for convenience. This single-container
`docker run` keeps the POC small; production would front it with a process
manager or orchestrator and deploy by immutable digest.

## Jenkins credentials

Jenkins uses two username/password credentials because GitHub OIDC is not
available to a typical standalone controller:

- `jenkins-aws-ecr`: username is the IAM access-key ID and password is its
  secret. Grant only ECR authorization, push, and scan-findings permissions.
- `jenkins-aws-deploy`: the same field mapping for a separate IAM identity.
  Grant only `ssm:SendCommand` (on the instance + `AWS-RunShellScript` document)
  and `ssm:GetCommandInvocation` (on `*`).

Create them in **Manage Jenkins → Credentials**, never in this repository or
JCasC. Rotate them after the demo. Then set the Jenkins build parameters and
explicitly enable `ENABLE_AWS_DELIVERY`. With the default `false`, Docker build
runs on a non-scheduled `main` build but all AWS-dependent stages visibly skip.
