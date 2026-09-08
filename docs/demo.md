# Live security-gate demonstrations

These commands assume Phase 10 is present on `main`, `origin` points at the
GitHub repository, and each demo branch is disposable. Never merge a demo
branch. Every activated file is dummy or deliberately vulnerable test content;
none is part of the running application.

## Demo 1 — clean PASS

```sh
git switch main
git pull --ff-only
make security
make gate
```

Expected verdict: `SECURITY GATE: PASS`.

## Demo 2 — dummy secret BLOCK, then PASS

```sh
git switch main
git pull --ff-only
git switch -c demo/phase-10-secret
node security/fixtures/activate.mjs secret
git add src/config/_demo_secret.js
git commit -m "demo: activate dummy secret fixture"
git push -u origin demo/phase-10-secret
```

Open a PR to `main`. Gitleaks reports rule
`phase10-demo-dummy-secret`; the gate reports `secrets.demo_dummy` and `BLOCK`.
The value is generated dummy text, not a TruffleHog-verified credential.

On a pull request, Gitleaks scans the branch's commit range
(`origin/main..HEAD`), which still includes the commit that introduced the
secret — so merely deleting the file in a later commit cannot remove that
earlier commit from the range. Deactivate it, record that reversal, then rewrite
the disposable demo branch to an empty commit with the same tree as `main`
(which empties the range):

```sh
node security/fixtures/deactivate.mjs secret
git add -A
git commit -m "demo: deactivate dummy secret fixture"
git reset --hard origin/main
git commit --allow-empty -m "demo: verify clean state after secret deactivation"
git push --force-with-lease origin demo/phase-10-secret
```

The same PR reruns with no reachable secret fixture commit and the gate reports
`PASS`. Close it without merging, then delete the branch:

```sh
git push origin --delete demo/phase-10-secret
git switch main
git branch -D demo/phase-10-secret
```

## Demo 3 — SAST BLOCK, then PASS

```sh
git switch main
git pull --ff-only
git switch -c demo/phase-10-sast
node security/fixtures/activate.mjs sast
git add src/_demo_sast.js
git commit -m "demo: activate isolated SAST fixture"
git push -u origin demo/phase-10-sast
```

Open a PR to `main`. Semgrep scans the isolated file under `src/`; the finding
is new relative to the checked-in baseline, so the security gate reports
`sast.high_new` and `BLOCK`. The file is never imported by the application.

```sh
node security/fixtures/deactivate.mjs sast
git add -A
git commit -m "demo: deactivate isolated SAST fixture"
git push
```

The same PR should report `PASS`. Close it without merging, then run:

```sh
git push origin --delete demo/phase-10-sast
git switch main
git branch -D demo/phase-10-sast
```

## Demo 4 — dependency BLOCK, then PASS

```sh
git switch main
git pull --ff-only
git switch -c demo/phase-10-dependency
node security/fixtures/activate.mjs dependency
git add package.json package-lock.json
git commit -m "demo: activate known-CVE dependency fixture"
git push -u origin demo/phase-10-dependency
```

Open a PR to `main`. npm audit and OSV-Scanner inspect the modified application
lockfile and report `minimist` 1.2.5. GHSA-xvch-5gv4-984h has a fix in 1.2.6,
so the gate reports a fixable High/Critical dependency and `BLOCK`.

```sh
node security/fixtures/deactivate.mjs dependency
git add package.json package-lock.json
git commit -m "demo: deactivate known-CVE dependency fixture"
git push
```

The same PR should report `PASS`. Close it without merging, then run:

```sh
git push origin --delete demo/phase-10-dependency
git switch main
git branch -D demo/phase-10-dependency
```

## Synthetic gate-only paths

These commands do not run scanners or install packages. They feed reviewed
synthetic Phase 8 reports directly to the real gate evaluator.

```sh
make demo-malicious-package
```

Expected: `dependencies.malicious_package`, then `SECURITY GATE: BLOCK`. A real
malicious package is never downloaded or installed.

```sh
make demo-dependency-no-fix
```

Expected: `dependencies.critical_no_fix`, then
`SECURITY GATE: PASS-WITH-EXCEPTIONS`, with a separate exceptions JSON report.

## Demo 5 — image deploy gate (run for real)

This has been exercised against real AWS on GitHub Actions, not just unit-tested.
On a `main` run the credential-free image is pushed to ECR via OIDC, scanned on
push, and evaluated by `image-gate.mjs`. The real scan of the
`node:22.23.2-alpine3.24` base returned **2 Critical + 7 High** OpenSSL CVEs
(`libcrypto3`/`libssl3` `3.5.7-r0`); the deploy gate **blocked** and the EC2/SSM
deploy was skipped. Patching the base image (`apk --no-cache upgrade` → OpenSSL
`3.5.8-r0`) produced a clean scan, the gate opened, and the container deployed to
EC2 over SSM with `/health` responding. See `docs/security-controls.md` and
`docs/aws-setup.md`. (The Jenkins equivalent is converted but its SSM deploy
stage is structured-but-unverified — see `docs/jenkins.md`.)

## Demo 6 — Jenkins equivalent

Create the same never-merged branches and use the same activation commands.
The Multibranch Pipeline discovers each branch and calls the shared scanners and
gate script. Capture the Jenkins console `BLOCK`, deactivate as above, and
capture the later `PASS`; no separate Groovy policy implementation exists.
