# Break-glass broker on AWS Lambda

Replaces the n8n Slack break-glass workflow. It handles orchestration only:
verifying Slack signatures, checking the per-repo approver allowlist,
claiming and finalizing decisions, updating the Slack message, and posting the
PR audit comment. No model API key, no AI calls.

## Architecture

| Path | Function | Invocation | Auth | Public |
|---|---|---|---|---|
| notify (CI → broker) | `break-glass-ci` | `lambda:InvokeFunction` | GitHub OIDC → `github-actions-break-glass-invoker` | No |
| status (CI poll) | `break-glass-ci` | `lambda:InvokeFunction` | same | No |
| Slack interaction | `break-glass-interactions` | Function URL | Slack HMAC signature | **Yes, the only public surface** |

- **State.** DynamoDB `break-glass-requests`, keyed by `requestId`. Each
  transition is a conditional write. The claim uses
  `attribute_exists(status) AND status = :pending AND expiresAt > :now`, and
  finalize uses `status = :processing AND claimUserId = :uid`. Concurrent
  clicks are therefore safe by construction, with no need to serialize
  executions. TTL (`ttl`) is only physical cleanup, 7 days after `expiresAt`.
  Logical expiry is always checked in code.
- **Shared logic, not re-implemented.** `broker.mjs` imports
  `slack-interaction-verify.mjs`, `slack-authorize.mjs`, and
  `break-glass-decision.mjs` as-is. It also reuses the Express service's
  `request.mjs`, `messages.mjs`, `slack.mjs`, and `github.mjs`. The modules
  decide each transition, and DynamoDB commits it.
- **Slack's 3-second ack.** Verify, authorize, claim, and finalize all run
  before the response, so state is final when Slack gets its 200. The Slack
  message update and the audit comment follow in an async self-invocation. A
  one-shot `sideEffectsAt` conditional write means a redelivery never posts
  twice. If enqueueing fails, the side effects run inline.
- **Secrets.** Three Secrets Manager secrets: bot token, signing secret, and a
  GitHub PAT that posts the audit comment. Each execution role can read only
  the secrets it needs. `break-glass-ci` gets just the bot token. **GitHub
  Actions holds no secret for this path.**
- **Separate identities.** The approver is the verified Slack user ID, checked
  against `SLACK_APPROVER_IDS_BY_REPO` for the repo stored at notify time. The
  poster of the audit record is the PAT owner.

## Blast radius of the OIDC role

The invoker role can invoke `break-glass-ci` and nothing else. The smoke
workflow asserts `AccessDenied` on the interactions function, the table, and
the secrets. Anyone holding the role, such as a same-repo PR, can at most
*request* an approval. They can never *grant* one: granting requires a signed
Slack click from an allowlisted user.

## Files

- `index.mjs`: Lambda entry points (`ciHandler`, `interactionsHandler`)
- `handlers.mjs`: event routing; URL events vs direct invokes
- `broker.mjs`: notify, status, interaction, and follow-up logic
- `dynamodb-store.mjs`: conditional-write store
- `runtime.mjs`: AWS SDK and Secrets Manager wiring (the SDK comes from the
  runtime; nothing is bundled)
- `../infra/deploy.sh`: idempotent provisioning, run in CloudShell with admin credentials
- `../infra/verify-live.mjs`: live evidence run, also in CloudShell
- `security/scripts/break-glass-lambda-invoke.mjs`: CI-side transport via the
  runner's AWS CLI, dependency-free

## Migration runbook

n8n stays live and untouched throughout. The gate workflows (`security.yml`,
`_source-security.yml`) keep calling n8n until step 6.

1. **Create a test Slack app.** Do not reuse the live app. Give it
   `chat:write`, invite it to a test channel, and copy its bot token and
   signing secret.
2. **Deploy from CloudShell** with your console identity:
   ```sh
   git clone -b feature/break-glass-lambda https://github.com/IamRitz/secure-software-delivery
   cd secure-software-delivery
   REGION=us-east-1 SLACK_CHANNEL_ID=<test channel> \
   SLACK_APPROVER_IDS_BY_REPO='{"IamRitz/secure-software-delivery":["<you>"],"IamRitz/verify-other-repo":["<a second user id>"]}' \
   ./server/break-glass/infra/deploy.sh
   ```
   Set the **test** app's Interactivity Request URL to the printed Function URL.
3. **Live evidence** (CloudShell):
   ```sh
   node server/break-glass/infra/verify-live.mjs --repo IamRitz/secure-software-delivery \
     --pr <this PR> --approver <you> --other-repo-approver <second user id>
   ```
   This covers signature accept/reject (tampered, stale, wrong secret,
   malformed), the unauthorized no-op, per-repo scoping, 25 concurrent claims
   producing exactly one winner, and timeout → expired.
4. **OIDC and human clicks.** Set `BREAK_GLASS_LAMBDA_ROLE_ARN` and
   `BREAK_GLASS_LAMBDA_FUNCTION` as repo **variables**, then push to the PR.
   `Break-glass Lambda smoke / OIDC invoke` requests an approval. Click
   Approve and the job goes green. Re-run and click Deny, or don't click, and
   the job goes red. Also click as a non-allowlisted user and double-click
   quickly.
5. **Parity.** Set `BREAK_GLASS_PARITY=true` and re-run. Click the same
   button on the n8n message and the Lambda message. Any divergence fails the
   job and blocks cutover.
6. **Cutover (needs explicit go-ahead).** Repoint the live Slack app to the
   Function URL and wire the gate for OIDC. That means `id-token: write` on the
   gate job plus a `configure-aws-credentials` step after the `--check-only`
   eligibility step, with `BREAK_GLASS_TRANSPORT=lambda`. Then retire the
   shared secret.
7. **Rollback window.** Keep n8n running but idle. Decommission only after
   the Lambda path has handled real decisions.
