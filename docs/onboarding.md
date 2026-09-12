# Onboarding another repository

This is the **ADOPT** phase of the rollout model (LOG → TUNE → BLOCK → ADOPT →
MATURE): taking the pipeline proven on this POC and bringing a second repository
onto it. The goal is that a new repo gets the same gate and delivery guarantees
without each repo growing its own drifting copy of the logic.

## 1. Reuse, don't copy-paste

Do **not** clone `.github/workflows/security.yml` or the `Jenkinsfile` into every
repo — that guarantees drift the moment one is fixed (exactly the drift this
project's Phase 12 had to reconcile).

- **GitHub Actions:** this split is already done. `_source-security.yml`,
  `_image-scan-prepush.yml`, `_artifact-gate.yml`, and `_ecr-collect.yml` are
  `workflow_call` reusable workflows; `security.yml` and `deploy.yml` are thin
  callers. Their inputs, outputs, and portability rules are documented in
  `docs/workflow-contracts.md`. To centralize, publish the four `_`-prefixed
  files in a central repo and change each caller's `uses: ./.github/workflows/_x.yml`
  to `uses: your-org/ci-security/.github/workflows/_x.yml@<pinned-sha>` — the
  structure and the contracts do not change. Pin to a SHA, not a moving tag.
  See "Extraction notes" in `docs/workflow-contracts.md` for the two couplings
  that still need resolving when the files leave this repo.
- **Jenkins:** move the pipeline body into a **Shared Library** and have each
  repo's `Jenkinsfile` be a thin call into it. The scanner/gate/deploy scripts
  (`security/scripts/*.mjs`) are already plain Node with no per-repo coupling and
  are the natural shared artifacts.

The shared scripts (`security-gate.mjs`, `image-gate.mjs`, `poll-ecr-scan.mjs`,
`ssm-deploy.mjs`, `slack-authorize.mjs`, `break-glass-decision.mjs`) are the unit
of reuse — GitHub and Jenkins already call the identical scripts, which is why
they can't diverge in policy.

## 2. Generate a Semgrep baseline for the existing code first

A repo that has never had SAST has a backlog. If you enable blocking SAST cold,
the first PR fails on hundreds of pre-existing findings the author didn't create.
Before turning the gate on, capture the current state as the baseline:

```sh
semgrep scan --config p/owasp-top-ten --config p/javascript \
  --config security/semgrep-rules.yml --json-output=semgrep-baseline.json src
```

Commit that `semgrep-baseline.json`. The gate then blocks only findings a change
**introduces** (`sast.high_new`) and logs pre-existing ones (`*_existing`). This
is separate from `--baseline-commit` (which controls *scan scope*, not *block
policy*) — keep both.

## 3. Sequence the rollout: LOG before BLOCK

Don't start at BLOCK. For a new repo:

1. **LOG** — run all scanners report-only, gate report-only. Learn the noise;
   tune false positives and severities.
2. **TUNE** — fix rule noise, establish the Semgrep baseline (step 2).
3. **BLOCK** — make `security-gate` fail the build, blocking only *new* findings.
4. **ADOPT** — teams treat green-gate as normal; wire required-check protection.
5. **MATURE** — add break-glass, image scanning, and delivery.

## 4. Per-repo break-glass approvers

Break-glass authorization is per-repo and fail-closed. Add the new repo's full
name and its approvers' Slack member IDs to `SLACK_APPROVER_IDS_BY_REPO` on the
interaction handler's host, then recreate the container:

```
SLACK_APPROVER_IDS_BY_REPO={"IamRitz/secure-software-delivery":["U0BV6TWN60J"],"your-org/new-repo":["Uxxx","Uyyy"]}
```

A repo **absent** from the map authorizes nobody — a repo is not onboarded to
break-glass until it has an explicit entry. See `docs/gating.md`.

## 5. Check whether the target repo can rely on branch protection

Confirm whether the new repo actually enforces "no direct push to `main`":

- On GitHub, required-status-check enforcement needs a plan that supports it for
  the repo's visibility (this POC went **public** because GitHub Free doesn't
  enforce branch protection on private repos — a visible-but-unenforced rule is
  not a control). Verify the `security-gate` check is *required*, admin bypass
  disabled, and direct pushes blocked.

- **Who can turn the gate off.** `gate_mode: log-only` makes the gate genuinely
  non-blocking — that is the point of the LOG phase, but it also means one line
  in the app-team-owned caller workflow turns a red required check green,
  including for report-integrity failures. A repo without CODEOWNERS on
  `.github/workflows/` therefore has an **unreviewed path to bypassing its own
  security gate**, reviewed by whoever normally reviews that repo's code.

  Onboarding checklist for this:

  1. Ship `.github/CODEOWNERS` covering `/.github/workflows/`,
     `/security/policy.yaml`, `/security/scripts/`, `/security/baseline/`, and
     the local Semgrep rules — owned by the security team, not the app team.
  2. Enable **Require review from Code Owners** (and at least one required
     approval) in branch protection. CODEOWNERS enforces nothing without it.
  3. Expect the `gate-mode: LOG-ONLY (gate NOT enforcing)` check on every PR
     while the repo is in the LOG phase. That check going away is how you know
     the repo reached BLOCK; it turning up again is how you notice a regression.

  See `docs/workflow-contracts.md` § "log-only is a merge bypass".

- **If branch protection can't be fully relied on**, the pipeline still has a
  fallback built into the **job dependency DAG**: the delivery jobs are gated on
  the gate job in-workflow, not only by branch protection. In `deploy.yml`,
  `aws-configuration` and `ecr-collect` carry
  `needs: [source-security, image-security]` **and**
  `if: github.ref == 'refs/heads/main' && needs.source-security.result == 'success' && …`,
  and they only run when the AWS configuration is present. So even on a repo where someone can push directly to
  `main`, a failing gate still prevents build and deploy from running — the
  `needs:`/`if:` chain is the enforcement of last resort. Jenkins does the same
  via stage `when { branch 'main'; expression { … } }` guards. Branch protection
  is the front door; the job DAG is the deadbolt behind it.
