<!-- THIS IS A DELIBERATE TEST FIXTURE FOR A CI/CD SECURITY DEMO. NOT REAL. NOT PRODUCTION CODE. See security/fixtures/README.md. -->

# Safe security demo fixtures

Everything in this directory is test-only and inert on `main`. Normal scanner
configuration excludes this directory, the standalone dependency manifest is
not part of the application lockfile, and none of the snippets is imported by
the application.

- `secrets/demo-secret.js` contains a generated marker that is not a credential
  for any provider. A dedicated Gitleaks demo rule recognizes it.
- `sast/command-injection.js` contains an isolated command-injection pattern.
- `dependency/package.json` records harmless historical `minimist` 1.2.5,
  affected by GHSA-xvch-5gv4-984h/CVE-2021-44906 and fixed in 1.2.6.

Activation is deliberately restricted to exact `demo/phase-10-*` branch names:

```sh
node security/fixtures/activate.mjs secret
node security/fixtures/deactivate.mjs secret
```

Use `sast` or `dependency` in place of `secret`. Never merge an activated demo
branch. See [`docs/demo.md`](../../docs/demo.md) for the complete commands,
including the history-clean deactivation required by full-history secret scans.

The JSON dependency manifest uses `_fixtureNotice` as its first property because
JSON does not permit comments; it is the JSON-safe equivalent of the required
fixture header comment.
