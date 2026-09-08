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

## GitHub Actions: OIDC, not access keys

1. Add the GitHub OIDC provider in IAM with URL
   `https://token.actions.githubusercontent.com` and audience
   `sts.amazonaws.com`.
2. Create an IAM role for this repository. Its trust policy must require the
   audience above and the exact `main` subject. This repository was created
   after GitHub introduced immutable OIDC subjects, so use its permanent owner
   and repository IDs:

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

3. Attach a policy limited to this ECR repository and this EC2 instance. The
   actions required by the current workflow are:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImageScanFindings",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart"
      ],
      "Resource": "arn:aws:ecr:<REGION>:<ACCOUNT_ID>:repository/secure-software-delivery"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ec2:<REGION>:<ACCOUNT_ID>:instance/<INSTANCE_ID>",
        "arn:aws:ssm:<REGION>::document/AWS-RunShellScript"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetCommandInvocation",
      "Resource": "*"
    }
  ]
}
```

`ssm:SendCommand` needs **both** the instance ARN and the `AWS-RunShellScript`
document ARN. `ssm:GetCommandInvocation` cannot be scoped to the instance and
must be granted on `*` — a hard-won detail: scoping it to the instance ARN
silently denies the read-back and the deploy hangs then fails. The EC2
instance's **own** role separately carries `AmazonSSMManagedInstanceCore` plus
read-only ECR pull; the runner's push role is never shared with the box.

4. Add these GitHub **repository variables**, not static AWS secrets:

| Variable | Example |
| --- | --- |
| `AWS_ROLE_ARN` | `arn:aws:iam::123456789012:role/ssd-main-delivery` |
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

`aws-configuration` requires `AWS_ROLE_ARN`, `AWS_REGION`, `ECR_REPOSITORY`, and
`EC2_INSTANCE_ID`; otherwise the AWS stages are skipped. The instance needs Docker,
the AWS CLI, and the SSM agent, with `AmazonSSMManagedInstanceCore` on its role;
the delivery/OIDC role needs `ssm:SendCommand` + `ssm:GetCommandInvocation` scoped
to the instance. The Jenkins pipeline uses the same `ssm-deploy.mjs` script with an
`EC2_INSTANCE_ID` parameter and the `jenkins-aws-deploy` credential.

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
