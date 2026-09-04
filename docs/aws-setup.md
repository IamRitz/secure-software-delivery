# AWS setup for the Phase 9 delivery path

> **Status: ECR push, ECR scan, and ECS deployment are structured but have not
> been run against a real AWS account. Do not interpret a skipped job as an AWS
> deployment success.**

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
| `ECS_CLUSTER` | demo cluster name |
| `ECS_SERVICE` | demo service name |

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
