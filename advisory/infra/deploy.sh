#!/usr/bin/env bash
# One-time / update deploy for the advisory explainer POC. Run with ADMIN AWS
# credentials from a workstation or CloudShell — never from CI. CI only ever
# holds the invoke-only role this script creates.
#
#   ACCOUNT_ID=157328692276 REGION=us-east-1 ./advisory/infra/deploy.sh
#
# The model API key is read from stdin the first time (so it never appears in
# argv, shell history, or this repo):
#
#   printf %s "$KEY" | ACCOUNT_ID=... REGION=... ./advisory/infra/deploy.sh
set -euo pipefail

: "${ACCOUNT_ID:?set ACCOUNT_ID}"
: "${REGION:?set REGION}"
FUNCTION=advisory-finding-explainer
SECRET_NAME=advisory-explainer/anthropic-api-key
EXEC_ROLE=advisory-explainer-execution
INVOKER_ROLE=github-actions-advisory-invoker
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
export AWS_REGION="$REGION"

render() { sed -e "s/<ACCOUNT_ID>/$ACCOUNT_ID/g" -e "s/<REGION>/$REGION/g" "$1"; }

# 1. Secret (created once; value from stdin).
if ! SECRET_ARN="$(aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --query ARN --output text 2>/dev/null)"; then
  if [ -t 0 ]; then
    echo "Secret $SECRET_NAME does not exist; pipe the model API key on stdin." >&2
    exit 1
  fi
  SECRET_ARN="$(aws secretsmanager create-secret --name "$SECRET_NAME" \
    --secret-string "$(cat)" --query ARN --output text)"
fi

# 2. Execution role: its own logs + that one secret.
if ! aws iam get-role --role-name "$EXEC_ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$EXEC_ROLE" --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  sleep 10 # IAM propagation before Lambda can assume it
fi
aws iam put-role-policy --role-name "$EXEC_ROLE" --policy-name advisory-explainer \
  --policy-document "$(render "$HERE/execution-permissions.json")"

# 3. Package: payload.mjs + lambda/ + production node_modules. The Lambda
#    runtime provides @aws-sdk/client-secrets-manager.
BUILD="$(mktemp -d)"
cp "$ROOT/package.json" "$ROOT/package-lock.json" "$ROOT/payload.mjs" "$BUILD/"
cp -r "$ROOT/lambda" "$BUILD/lambda"
(cd "$BUILD" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null && zip -qr function.zip .)

# 4. Function: bounded timeout, small memory, reserved concurrency caps cost
#    even if the invoker role is abused by a same-repo PR.
if aws lambda get-function --function-name "$FUNCTION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNCTION" --zip-file "fileb://$BUILD/function.zip" >/dev/null
  aws lambda wait function-updated --function-name "$FUNCTION"
else
  aws lambda create-function --function-name "$FUNCTION" \
    --runtime nodejs22.x --architectures arm64 --memory-size 256 --timeout 45 \
    --handler lambda/index.handler \
    --role "arn:aws:iam::$ACCOUNT_ID:role/$EXEC_ROLE" \
    --environment "Variables={ANTHROPIC_API_KEY_SECRET_ARN=$SECRET_ARN}" \
    --zip-file "fileb://$BUILD/function.zip" >/dev/null
  aws lambda wait function-active --function-name "$FUNCTION"
fi
aws lambda put-function-concurrency --function-name "$FUNCTION" --reserved-concurrent-executions 2 >/dev/null

# 5. Invoker role for GitHub OIDC: lambda:InvokeFunction on this function only.
if ! aws iam get-role --role-name "$INVOKER_ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$INVOKER_ROLE" --max-session-duration 3600 \
    --assume-role-policy-document "$(render "$HERE/invoker-trust-policy.json")" >/dev/null
else
  aws iam update-assume-role-policy --role-name "$INVOKER_ROLE" \
    --policy-document "$(render "$HERE/invoker-trust-policy.json")"
fi
aws iam put-role-policy --role-name "$INVOKER_ROLE" --policy-name invoke-advisory-explainer \
  --policy-document "$(render "$HERE/invoker-permissions.json")"

rm -rf "$BUILD"
echo "Deployed. Enable in CI with:"
echo "  gh variable set ADVISORY_EXPLAINER_ROLE_ARN --body arn:aws:iam::$ACCOUNT_ID:role/$INVOKER_ROLE"
