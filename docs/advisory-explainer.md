# Advisory finding explainer

Gate output names a policy category (`BLOCK dependencies.critical_with_fix`),
not an explanation. This adds explanations in two tiers. Neither tier decides
policy; the gate already did.

## Tier 0 — deterministic policy guide (shipped)

`security/scripts/policy-advisories.mjs` maps every policy key the gates can
emit to fixed, reviewed text: what the class means, why policy treats it that
way, and whether break-glass applies. `format-findings.mjs` renders one entry
per distinct blocking or exception key under the heading **📘 Policy guide —
fixed, reviewed text (not AI-generated)**, in both the PR comment and the job
summary. LOG-only keys are omitted to keep noise down.

`test/policy-advisories.test.js` enforces:

- every action key in `policy.yaml` **and** every literal key the gates emit
  (`gate.report_integrity`, `image.report_integrity`, `image.secret`) has text,
  and no text exists for a key the gates cannot emit;
- each entry's break-glass statement matches the gate's real
  `markBreakGlassEligibility` result;
- the fixed text never contains a version number.

## Lambda transport POC (built, shadow mode, not yet deployed)

Additive and non-gating. The n8n break-glass flow is untouched and remains the
only approval path.

```
source-security ──(security-gate-results artifact)──▶ advisory-explainer job
                                                        │ OIDC token (id-token: write)
                                                        ▼
                                              STS: github-actions-advisory-invoker
                                              (lambda:InvokeFunction, one function)
                                                        │ aws lambda invoke
                                                        ▼
                                              advisory-finding-explainer Lambda
                                              ├─ re-validates allowlisted payload
                                              ├─ reads model key from Secrets Manager
                                              ├─ claude-opus-5, structured JSON, capped
                                              └─ output guard ─▶ job LOG only (shadow)
```

| Piece | Path |
| --- | --- |
| Allowlisted payload builder + Lambda re-validation | `advisory/payload.mjs` |
| Model call + output guard | `advisory/lambda/explain.mjs` |
| Lambda entry point | `advisory/lambda/index.mjs` |
| CI client (shadow log) | `advisory/client.mjs` |
| Reusable workflow | `.github/workflows/_advisory-explainer.yml` |
| IAM documents + deploy script | `advisory/infra/` |
| Guardrail tests | `test/advisory-explainer.test.js` |

### Guardrails and where each is enforced

| Guardrail | Enforcement |
| --- | --- |
| Cannot fail the run | Job and every fallible step `continue-on-error: true`; client always exits 0. Tested. |
| Nothing consumes its output | No `outputs:`, no job `needs:` it, no `needs.advisory-explainer` reference in any workflow, client never writes `GITHUB_OUTPUT` / step summary / PR comment. Tested. |
| Allowlisted payload, field by field | `toAdvisoryFinding` copies 11 named fields; scanner free text is excluded; PR-influenced strings must match an identifier charset or are dropped. The Lambda rejects any payload whose shape differs. Tested. |
| Model never states a version | System prompt forbids it; the guard rejects the **whole** explanation on any `N.N` token, including the scanner's own fixed version. Tested. |
| No invented file / line / CVE | Guard rejects advisory IDs, file names, and line numbers not present in that finding. Tested. |
| `secrets.*` get Tier 0 only | Builder returns no entry for `secrets.*`, `image.secret`, or `*.report_integrity`; Lambda rejects them too, before any model call. Tested. |
| Bounded | `max_tokens` 2000, 20 s model timeout, 1 SDK retry, effort `low`, ≤ 5 findings, CLI `AWS_MAX_ATTEMPTS=1`, 75 s client kill, 45 s Lambda timeout, reserved concurrency 2. |
| Prompt injection | Findings are wrapped as data with an instruction not to follow them; identifier charset drops most carriers. The real mitigation is structural: output gates nothing and is not shown to developers. Model output is printed inside `::stop-commands::` so it cannot emit workflow commands. Tested. |
| Least privilege | Job holds `contents: read` + `id-token: write` only (tighter than `pull-requests: write`, which shadow mode does not need). No deploy/push role, no break-glass input, no secrets. Tested. |

Refusals (`stop_reason: refusal`) and truncation (`max_tokens`) are treated as
failures. `fallbacks: "default"` is requested so a classifier decline can be
served by a fallback model. **Unverified:** that `fallbacks` combines with
`output_config.format` on this model. A 400 here would show up as
`explainer-error` in the metrics and degrade to Tier 0.

### Trust-policy decision to review

`docs/aws-setup.md` says never to trust pull-request subjects. That rule is for
roles that can push or deploy. The invoker role trusts
`repo:…/secure-software-delivery@…:pull_request` on purpose, because the job
runs on PRs. What that role can do:

- invoke one function, whose output lands only in the caller's own log;
- run up the model bill. A same-repo PR author can edit the workflow to invoke
  repeatedly. This is bounded by reserved concurrency 2, ≤ 5 findings, and the
  token cap, but not zero. Put a spend limit on the model key's workspace.

Fork PRs get no OIDC token and are skipped. Confirm the real `sub` claim from a
job before deploying (see `docs/aws-setup.md`).

### Enabling it

```sh
printf %s "$MODEL_API_KEY" | ACCOUNT_ID=157328692276 REGION=us-east-1 ./advisory/infra/deploy.sh
gh variable set ADVISORY_EXPLAINER_ROLE_ARN --body arn:aws:iam::157328692276:role/github-actions-advisory-invoker
```

Until the variable is set, the job logs a notice and does nothing.

Each run prints one `ADVISORY_METRICS {…}` line: outcome, wall/Lambda/model
latency, token usage, and ok/rejected/missing counts with rejection reasons.
Shadow review:
`gh run view <id> --log | grep -A40 'ADVISORY EXPLANATION'`. Grade each `ok`
explanation as correct, wrong, or hollow. Any hallucinated file, line, or CVE
that got past the guard disqualifies the approach.

## Transport comparison

| | n8n (existing break-glass) | Lambda via OIDC (this POC) |
| --- | --- | --- |
| Secrets stored in GitHub | `BREAK_GLASS_SHARED_SECRET`, long-lived, no expiry, copied into every onboarded repo | **None.** Role ARN is a non-secret variable |
| Credential CI holds at run time | Same static shared secret | STS session, ≤ 15 min, single-function invoke, issued per job |
| Secrets at the broker | n8n shared-secret credential, Slack bot token, Slack signing secret, GitHub PAT (all long-lived) | One model API key in Secrets Manager |
| Onboarding a repo | Distribute the shared secret + configure per-repo approvers | Add a `sub` to one trust policy |
| Revocation | Rotate the shared secret everywhere at once | Remove the `sub`; sessions expire in ≤ 15 min |
| Deploy / update | Import workflow JSON, restart container for env changes | `deploy.sh` (zip + `update-function-code`) |
| Failure visibility | n8n execution log (separate system) | CloudWatch + `ADVISORY_METRICS` line in the GitHub run |
| Cost | Existing host | Lambda: 256 MB arm64, well inside free tier. Model: **estimate** ≈ 1–1.5k input + ≤ 2k output tokens at $5/$25 per MTok ≈ $0.01–0.06 per invocation. Not measured. |
| Latency | Measured from a workstation, 6 samples: 0.23–0.43 s TLS + router round-trip to `n8n.iamritesh.in` (the dev route returned 404 to an unauthenticated probe, so no workflow ran). Not a break-glass end-to-end latency. | **Not measured.** Nothing has been deployed. |

## Status: what ran vs. what is structurally correct but unexercised

**Ran:**

- Full unit suite (`npm test`) and `eslint .`, both green.
- Workflow YAML parses; `deploy.sh` passes `bash -n`.
- One n8n transport probe (latency above).

**Built, never exercised:**

- `deploy.sh`, both IAM roles, the Secrets Manager secret, and the Lambda. No
  AWS admin credentials were available.
- The GitHub OIDC → STS exchange for the invoker role, and `aws lambda invoke`.
- Any real model call. No API key was used, so **shadow-mode quality counts
  are zero: none have been produced.**
- `fallbacks: "default"` together with structured output.
- Tier 0 in a real PR run. It is covered by unit tests on the branch but has
  not yet rendered on GitHub.
