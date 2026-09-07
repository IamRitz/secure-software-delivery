# AWS setup for the Phase 9 delivery path

> **Status: delivery targets an EC2 Docker host over SSH (ECR push + scan-on-push
> + `docker pull`/`docker run` on the instance). Wired and pending a first real
> `main` run; do not interpret a skipped job as a deployment success.**
>
> The delivery OIDC role now needs only **ECR push** permissions — the
> `ecs:UpdateService` grant in the example policy below is no longer required;
> the image is pulled by the EC2 instance's own read-only ECR role. (The example
> IAM JSON below still shows the older ECS shape and is being kept for reference.)

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

3. Attach a policy limited to this ECR repository and ECS service. The actions
   required by the current workflow are:

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
      "Action": "ecs:UpdateService",
      "Resource": "arn:aws:ecs:<REGION>:<ACCOUNT_ID>:service/<CLUSTER>/<SERVICE>"
    }
  ]
}
```

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

> **Port 22 is not used by CI.** SSM needs no inbound SSH. Close port 22 in the
> security group, or restrict it to specific known IPs only for occasional manual
> human debugging — separate from CI, which no longer touches it. Once the SSM
> path is verified, the old `EC2_SSH_PRIVATE_KEY` secret can be deleted.

Only `aws-delivery` declares `id-token: write`; workflow and pre-build jobs
remain `contents: read`. The workflow pins `configure-aws-credentials` and
`amazon-ecr-login` to immutable commits. AWS recommends OIDC-backed temporary
credentials; see the official
[action documentation](https://github.com/aws-actions/configure-aws-credentials#oidc-configuration).

## ECR and ECS

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

The demo deploy command forces an existing ECS service to redeploy. Its task
definition must already reference this repository's `:demo` tag. This mutable
tag keeps the POC small; production should register a task-definition revision
that uses the pushed image digest and deploy that immutable revision.

## Jenkins credentials

Jenkins uses two username/password credentials because GitHub OIDC is not
available to a typical standalone controller:

- `jenkins-aws-ecr`: username is the IAM access-key ID and password is its
  secret. Grant only ECR authorization, push, and scan-findings permissions.
- `jenkins-aws-deploy`: the same field mapping for a separate IAM identity.
  Grant only `ecs:UpdateService` on the named service.

Create them in **Manage Jenkins → Credentials**, never in this repository or
JCasC. Rotate them after the demo. Then set the Jenkins build parameters and
explicitly enable `ENABLE_AWS_DELIVERY`. With the default `false`, Docker build
runs on a non-scheduled `main` build but all AWS-dependent stages visibly skip.
