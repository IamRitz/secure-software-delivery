# Break-glass approval service

A small standalone Express service that replaces the n8n Slack workflow for the
break-glass approval flow. It imports the same pure modules the n8n Code nodes
mirrored (`security/scripts/slack-interaction-verify.mjs`, `slack-authorize.mjs`,
`break-glass-decision.mjs`) — the logic is identical, only the transport changed.

> Co-located in this repo for now at this scale. A multi-repo rollout would
> likely move it to shared infrastructure rather than one application's repo.

## Routes

- `POST /break-glass/notify` — shared-secret header (`X-Break-Glass-Token`) auth;
  validates the finding payload, stores a pending request, posts the Block Kit
  approval message to Slack via `chat.postMessage`. Returns `{ requestId, status,
  createdAt, expiresAt }`.
- `POST /slack/interactions` — Slack interactivity callback. Verifies the HMAC
  signature against the **raw** request body (no body parser runs before it),
  authorizes the clicker against `SLACK_APPROVER_IDS`, runs the shared
  claim/finalize logic, then `chat.update`s the message and posts the GitHub PR
  audit comment. Acks within Slack's 3-second window, then does side effects.
- `GET /break-glass/status` — shared-secret header auth; returns the request's
  status for the CI poll script.
- `GET /health` — liveness.

## State

`data/requests.json` (git-ignored), written atomically (temp file + rename).
Mutations are serialized in-process, so the pending -> processing claim guard is
race-free without any external "concurrency = 1" setting. Node 22's `node:sqlite`
would work too but is still experimental; the JSON file is the safer POC default.

## Run

```sh
cp server/break-glass/.env.example server/break-glass/.env   # fill in values
node --env-file=server/break-glass/.env server/break-glass/server.mjs
# or: npm run start:break-glass  (loads server/break-glass/.env)
```

Deploy behind the reverse proxy on its own subdomain (e.g.
`break-glass.iamritesh.in`), not under `n8n.iamritesh.in`. Point Slack's
Interactivity Request URL at `https://<host>/slack/interactions`.

## Cutover

No CI code changes. `break-glass-notify.mjs` / `break-glass-poll.mjs` already
read `BREAK_GLASS_NOTIFY_URL` / `BREAK_GLASS_STATUS_URL`; repoint those repo
Variables (or the `workflow_dispatch` override inputs) at this service once it is
verified. Keep n8n running untouched until then.
