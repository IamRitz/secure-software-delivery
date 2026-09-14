#!/usr/bin/env bash
# Provision / update the break-glass Lambda broker. Run from AWS CloudShell with
# your console (admin) identity — never from CI, and not with ssd-operator, which
# deliberately cannot create Lambda functions, IAM roles, or DynamoDB tables.
#
#   git clone -b feature/break-glass-lambda https://github.com/IamRitz/secure-software-delivery
#   cd secure-software-delivery
#   REGION=us-east-1 \
#   SLACK_CHANNEL_ID=C0TESTCHANNEL \
#   SLACK_APPROVER_IDS_BY_REPO='{"IamRitz/secure-software-delivery":["U0BV6TWN60J"]}' \
#   ./server/break-glass/infra/deploy.sh
#
# Secrets are prompted for (hidden input) only when they don't exist yet, so they
# never touch argv, shell history, or this repo. Use the TEST Slack app's bot
# token and signing secret — this must not share the live app's identity.
#
# Idempotent: re-running updates code, configuration, and policies in place.
set -euo pipefail

: "${REGION:?set REGION (e.g. us-east-1)}"
: "${SLACK_CHANNEL_ID:?set SLACK_CHANNEL_ID (the test channel the test bot is invited to)}"
: "${SLACK_APPROVER_IDS_BY_REPO:?set SLACK_APPROVER_IDS_BY_REPO (JSON map owner/repo -> [Slack user IDs])}"
RUNTIME="${RUNTIME:-nodejs24.x}"
PREFIX="${PREFIX:-break-glass}"
# GitHub OIDC subjects allowed to invoke notify/status. This repo uses immutable
# subjects (owner@id/repo@id). PRs run gate jobs; main covers scheduled/pushed runs.
OIDC_SUBJECTS="${OIDC_SUBJECTS:-repo:IamRitz@26003726/secure-software-delivery@1354576659:pull_request,repo:IamRitz@26003726/secure-software-delivery@1354576659:ref:refs/heads/main}"

export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION" AWS_PAGER=""
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
TABLE="$PREFIX-requests"
CI_FN="$PREFIX-ci"
INT_FN="$PREFIX-interactions"
CI_ROLE="$PREFIX-ci-execution"
INT_ROLE="$PREFIX-interactions-execution"
INVOKER_ROLE="github-actions-$PREFIX-invoker"
OIDC_ARN="arn:aws:iam::$ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "$SLACK_APPROVER_IDS_BY_REPO" | jq -e 'type == "object" and all(.[]; type == "array")' >/dev/null \
  || { echo "SLACK_APPROVER_IDS_BY_REPO must be a JSON object of repo -> [ids]" >&2; exit 1; }

# 0. The GitHub OIDC provider must already exist (the ECR/SSM roles use it).
aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" >/dev/null \
  || { echo "GitHub OIDC provider $OIDC_ARN not found; create it first (docs/aws-setup.md)." >&2; exit 1; }

# 1. DynamoDB table: on-demand, encrypted at rest (AWS-owned key by default),
#    point-in-time recovery, TTL on `ttl` for physical cleanup.
if ! aws dynamodb describe-table --table-name "$TABLE" >/dev/null 2>&1; then
  aws dynamodb create-table --table-name "$TABLE" \
    --attribute-definitions AttributeName=requestId,AttributeType=S \
    --key-schema AttributeName=requestId,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null
  aws dynamodb wait table-exists --table-name "$TABLE"
fi
aws dynamodb update-continuous-backups --table-name "$TABLE" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true >/dev/null
if [ "$(aws dynamodb describe-time-to-live --table-name "$TABLE" --query TimeToLiveDescription.TimeToLiveStatus --output text)" = "DISABLED" ]; then
  aws dynamodb update-time-to-live --table-name "$TABLE" \
    --time-to-live-specification Enabled=true,AttributeName=ttl >/dev/null
fi
TABLE_ARN="$(aws dynamodb describe-table --table-name "$TABLE" --query Table.TableArn --output text)"

# 2. Secrets (Secrets Manager, encrypted with the account's aws/secretsmanager KMS key).
ensure_secret() { # name prompt -> prints ARN
  local name="$1" prompt="$2" arn value
  if arn="$(aws secretsmanager describe-secret --secret-id "$name" --query ARN --output text 2>/dev/null)"; then
    echo "$arn"; return
  fi
  read -rsp "$prompt: " value </dev/tty; echo >&2
  [ -n "$value" ] || { echo "empty value for $name" >&2; exit 1; }
  printf '%s' "$value" > "$WORK/secret"
  arn="$(aws secretsmanager create-secret --name "$name" --secret-string "file://$WORK/secret" --query ARN --output text)"
  rm -f "$WORK/secret"
  echo "$arn"
}
BOT_ARN="$(ensure_secret "$PREFIX/slack-bot-token" "TEST Slack app bot token (xoxb-...)")"
SIGNING_ARN="$(ensure_secret "$PREFIX/slack-signing-secret" "TEST Slack app signing secret")"
GITHUB_ARN="$(ensure_secret "$PREFIX/github-token" "GitHub fine-grained PAT (this repo, Pull requests: write)")"

# 3. Log groups created here, so execution roles need no logs:CreateLogGroup.
for fn in "$CI_FN" "$INT_FN"; do
  aws logs create-log-group --log-group-name "/aws/lambda/$fn" 2>/dev/null || true
  aws logs put-retention-policy --log-group-name "/aws/lambda/$fn" --retention-in-days 90
done

# 4. Execution roles — one per function, least privilege.
LAMBDA_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
ensure_role() { # name trust-json
  if aws iam get-role --role-name "$1" >/dev/null 2>&1; then
    aws iam update-assume-role-policy --role-name "$1" --policy-document "$2"
  else
    aws iam create-role --role-name "$1" --assume-role-policy-document "$2" >/dev/null
    CREATED_ROLE=1
  fi
}
logs_statement() {
  jq -n --arg arn "arn:aws:logs:$REGION:$ACCOUNT_ID:log-group:/aws/lambda/$1:*" \
    '{Effect:"Allow",Action:["logs:CreateLogStream","logs:PutLogEvents"],Resource:$arn}'
}
CREATED_ROLE=0
ensure_role "$CI_ROLE" "$LAMBDA_TRUST"
aws iam put-role-policy --role-name "$CI_ROLE" --policy-name "$PREFIX-ci" --policy-document "$(jq -n \
  --arg table "$TABLE_ARN" --arg bot "$BOT_ARN" --argjson logs "$(logs_statement "$CI_FN")" '{
  Version: "2012-10-17",
  Statement: [
    {Sid: "RequestState", Effect: "Allow", Action: ["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:DeleteItem"], Resource: $table},
    {Sid: "PostApprovalMessage", Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: $bot},
    $logs
  ]}')"

ensure_role "$INT_ROLE" "$LAMBDA_TRUST"
INT_FN_ARN="arn:aws:lambda:$REGION:$ACCOUNT_ID:function:$INT_FN"
aws iam put-role-policy --role-name "$INT_ROLE" --policy-name "$PREFIX-interactions" --policy-document "$(jq -n \
  --arg table "$TABLE_ARN" --arg bot "$BOT_ARN" --arg signing "$SIGNING_ARN" --arg github "$GITHUB_ARN" \
  --arg self "$INT_FN_ARN" --argjson logs "$(logs_statement "$INT_FN")" '{
  Version: "2012-10-17",
  Statement: [
    {Sid: "ClaimAndFinalize", Effect: "Allow", Action: ["dynamodb:GetItem","dynamodb:UpdateItem"], Resource: $table},
    {Sid: "VerifyUpdateAndAudit", Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: [$bot, $signing, $github]},
    {Sid: "DeferSideEffectsAfterSlackAck", Effect: "Allow", Action: "lambda:InvokeFunction", Resource: $self},
    $logs
  ]}')"
[ "$CREATED_ROLE" = 1 ] && sleep 10 # IAM propagation before Lambda can assume a new role

# 5. Package: only the modules the broker imports. The Node.js runtime provides
#    the AWS SDK v3 clients, so there are no dependencies to bundle.
mkdir -p "$WORK/pkg"
(cd "$ROOT" && cp --parents \
  security/scripts/slack-interaction-verify.mjs \
  security/scripts/slack-authorize.mjs \
  security/scripts/break-glass-decision.mjs \
  server/break-glass/config.mjs \
  server/break-glass/request.mjs \
  server/break-glass/messages.mjs \
  server/break-glass/slack.mjs \
  server/break-glass/github.mjs \
  server/break-glass/lambda/index.mjs \
  server/break-glass/lambda/handlers.mjs \
  server/break-glass/lambda/runtime.mjs \
  server/break-glass/lambda/broker.mjs \
  server/break-glass/lambda/dynamodb-store.mjs \
  "$WORK/pkg/")
(cd "$WORK/pkg" && zip -qr "$WORK/function.zip" .)

deploy_function() { # name role handler env-json timeout
  printf '%s' "$4" > "$WORK/env.json"
  if aws lambda get-function --function-name "$1" >/dev/null 2>&1; then
    aws lambda update-function-code --function-name "$1" --zip-file "fileb://$WORK/function.zip" >/dev/null
    aws lambda wait function-updated-v2 --function-name "$1"
    aws lambda update-function-configuration --function-name "$1" --runtime "$RUNTIME" \
      --role "arn:aws:iam::$ACCOUNT_ID:role/$2" --handler "$3" --timeout "$5" --memory-size 256 \
      --environment "file://$WORK/env.json" >/dev/null
    aws lambda wait function-updated-v2 --function-name "$1"
  else
    aws lambda create-function --function-name "$1" --runtime "$RUNTIME" --architectures arm64 \
      --role "arn:aws:iam::$ACCOUNT_ID:role/$2" --handler "$3" --timeout "$5" --memory-size 256 \
      --environment "file://$WORK/env.json" --zip-file "fileb://$WORK/function.zip" >/dev/null
    aws lambda wait function-active-v2 --function-name "$1"
  fi
}

deploy_function "$CI_FN" "$CI_ROLE" server/break-glass/lambda/index.ciHandler "$(jq -n \
  --arg t "$TABLE" --arg c "$SLACK_CHANNEL_ID" --arg b "$BOT_ARN" \
  '{Variables:{TABLE_NAME:$t,SLACK_CHANNEL_ID:$c,SLACK_BOT_TOKEN_SECRET_ARN:$b}}')" 20

deploy_function "$INT_FN" "$INT_ROLE" server/break-glass/lambda/index.interactionsHandler "$(jq -n \
  --arg t "$TABLE" --arg a "$SLACK_APPROVER_IDS_BY_REPO" --arg b "$BOT_ARN" --arg s "$SIGNING_ARN" --arg g "$GITHUB_ARN" \
  '{Variables:{TABLE_NAME:$t,SLACK_APPROVER_IDS_BY_REPO:$a,SLACK_BOT_TOKEN_SECRET_ARN:$b,SLACK_SIGNING_SECRET_ARN:$s,GITHUB_TOKEN_SECRET_ARN:$g}}')" 20

# Deferred side effects run at most once: no async retries (a retry could post a
# second audit comment; the one-shot DynamoDB guard is the backstop).
aws lambda put-function-event-invoke-config --function-name "$INT_FN" \
  --maximum-retry-attempts 0 --maximum-event-age-in-seconds 900 >/dev/null

# 6. The ONE public endpoint: a Function URL on the interactions function only.
#    Auth NONE at the AWS layer; the Slack HMAC signature is the authentication.
if ! INT_URL="$(aws lambda get-function-url-config --function-name "$INT_FN" --query FunctionUrl --output text 2>/dev/null)"; then
  INT_URL="$(aws lambda create-function-url-config --function-name "$INT_FN" --auth-type NONE --query FunctionUrl --output text)"
fi
add_permission() { # statement-id args...
  local sid="$1"; shift
  aws lambda remove-permission --function-name "$INT_FN" --statement-id "$sid" >/dev/null 2>&1 || true
  aws lambda add-permission --function-name "$INT_FN" --statement-id "$sid" "$@" >/dev/null
}
add_permission slack-function-url --action lambda:InvokeFunctionUrl --principal '*' --function-url-auth-type NONE
# Newer Function URLs additionally require InvokeFunction, restricted to URL calls.
add_permission slack-function-url-invoke --action lambda:InvokeFunction --principal '*' --invoked-via-function-url \
  || echo "WARNING: could not add InvokeFunction-via-URL permission (older CLI?). If the URL returns 403, update the AWS CLI and re-run." >&2
# break-glass-ci gets NO resource policy and NO URL: only IAM principals in this
# account holding lambda:InvokeFunction on it can reach it.
if aws lambda get-function-url-config --function-name "$CI_FN" >/dev/null 2>&1; then
  echo "ERROR: $CI_FN has a Function URL; it must not be public." >&2; exit 1
fi

# 7. Reserved concurrency (cost cap) where the account allows it.
UNRESERVED="$(aws lambda get-account-settings --query AccountLimit.UnreservedConcurrentExecutions --output text)"
if [ "$UNRESERVED" -ge 20 ]; then
  aws lambda put-function-concurrency --function-name "$INT_FN" --reserved-concurrent-executions 5 >/dev/null
  aws lambda put-function-concurrency --function-name "$CI_FN" --reserved-concurrent-executions 5 >/dev/null
else
  echo "WARNING: account unreserved concurrency is $UNRESERVED (<20); reserved-concurrency cap NOT applied." >&2
fi

# 8. GitHub OIDC invoker role: InvokeFunction on break-glass-ci ONLY. It cannot
#    reach the interactions function, the table, or any secret — so a same-repo
#    PR holding it can at most request an approval, never grant one.
TRUST="$(jq -n --arg oidc "$OIDC_ARN" --arg subs "$OIDC_SUBJECTS" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Principal: {Federated: $oidc},
    Action: "sts:AssumeRoleWithWebIdentity",
    Condition: {StringEquals: {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": ($subs | split(","))
    }}
  }]}')"
if aws iam get-role --role-name "$INVOKER_ROLE" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$INVOKER_ROLE" --policy-document "$TRUST"
else
  aws iam create-role --role-name "$INVOKER_ROLE" --max-session-duration 3600 --assume-role-policy-document "$TRUST" >/dev/null
fi
aws iam put-role-policy --role-name "$INVOKER_ROLE" --policy-name "invoke-$CI_FN" --policy-document "$(jq -n \
  --arg fn "arn:aws:lambda:$REGION:$ACCOUNT_ID:function:$CI_FN" \
  '{Version:"2012-10-17",Statement:[{Sid:"InvokeBreakGlassCiOnly",Effect:"Allow",Action:"lambda:InvokeFunction",Resource:$fn}]}')"

# 9. Reachability check: an unsigned request must be refused by OUR code (401),
#    not by AWS (403), which proves the URL is public and verification runs.
sleep 5
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'payload=%7B%7D' "$INT_URL")"
echo "Unsigned POST to Function URL -> HTTP $CODE (expected 401)"
[ "$CODE" = 401 ] || echo "WARNING: expected 401. 403 means the URL permissions are missing." >&2

cat <<EOF

Deployed.
  DynamoDB table        $TABLE
  CI function           $CI_FN   (no URL; IAM invoke only)
  Interactions function $INT_FN
  Slack Request URL     $INT_URL   <- set on the TEST Slack app only
  OIDC invoker role     arn:aws:iam::$ACCOUNT_ID:role/$INVOKER_ROLE

Enable the smoke workflow (repository variables, not secrets):
  gh variable set BREAK_GLASS_LAMBDA_ROLE_ARN --body arn:aws:iam::$ACCOUNT_ID:role/$INVOKER_ROLE
  gh variable set BREAK_GLASS_LAMBDA_FUNCTION --body $CI_FN
EOF
