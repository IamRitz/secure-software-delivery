# Discord break-glass workflow

`break-glass-workflow.json` is an importable n8n 2.36.x workflow containing
three production webhooks:

- `POST /webhook/break-glass/notify` — authenticated CI notification;
- `POST /webhook/discord/interactions` — the existing, validated public
  Discord interaction endpoint;
- `POST /webhook/break-glass/interactions` — equivalent compatibility alias;
- `GET /webhook/break-glass/status` — authenticated CI polling.

The JSON deliberately contains credential *references*, never credential
values. After importing it, select or create these n8n Header Auth credentials:

1. **Break Glass Shared Secret**: header `X-Break-Glass-Token`; use the same
   randomly generated value in GitHub/Jenkins.
2. **Discord Bot account**: the existing n8n Discord Bot credential is reused.
3. **GitHub Break Glass PAT**: header `Authorization`, value
   `Bearer <fine-grained-PAT>`. Restrict it to this repository and grant only
   pull-request/issues comment write access.

Configure these n8n environment values outside the repository:

```text
DISCORD_APPROVER_IDS=<comma-separated Discord user IDs>
NODE_FUNCTION_ALLOW_BUILTIN=crypto
N8N_BLOCK_ENV_ACCESS_IN_NODE=false
```

`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` is required: the "Authorize and Claim
Decision" Code node reads the approver allowlist from `$env.DISCORD_APPROVER_IDS`.
n8n blocks Code-node access to environment variables by default, so without this
the node fails with `access to env vars denied` and no decision is ever claimed.
Note this lifts the block instance-wide (every Code node can then read env vars).

n8n has **no per-workflow concurrency setting** — the workflow `settings` object
only exposes `executionOrder`/`binaryMode`. The POC uses workflow static data for
pending requests, and the `pending -> processing -> approved|denied` claim
transition is only race-free under serial execution. To serialize, set the
instance-wide `N8N_CONCURRENCY_PRODUCTION_LIMIT=1` (this affects **every**
workflow on the instance), or accept a small double-click race window for the
POC. For a production deployment, replace static data with a transactional
external store, which removes the need for global serialization.

The application public key and approval channel ID in the committed workflow
are public configuration copied from the already-validated live workflows.
They are not the Discord bot token. Publish/activate the workflow, then retain
the already-configured Discord
Interactions Endpoint URL:

```text
https://n8n.iamritesh.in/webhook/discord/interactions
```

Do not use `/webhook-test/` for Discord. The workflow responds to signed PINGs
with type `1`, component clicks with deferred update type `6`, and invalid
signatures with HTTP 401. Unauthorized users receive an ephemeral response and
cannot mutate request state.

`deploy-workflow.mjs` performs the guarded API update used for this POC. It
requires `N8N_URL`, `N8N_API_KEY`, `N8N_SHARED_SECRET_CREDENTIAL_ID`, and
`N8N_GITHUB_CREDENTIAL_ID`. It fetches the current workflow into the ignored
`n8n/backups/` directory before updating workflow
`pxM7aQXKFfa2bmWO`, replaces only credential-ID placeholders, and reactivates
the workflow. It never accepts or writes credential values.
