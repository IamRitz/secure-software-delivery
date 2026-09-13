# ECR enhanced scanning (Amazon Inspector) response fixtures

Source: the `ecr-raw-response` artifact of Deploy run `34744609758` (commit
`f947250`), the first run with the push+scan role able to read Inspector. The AWS
account ID is redacted to `123456789012`; everything else is as the API returned
it. The image digest is real.

## Live-captured (verbatim apart from the account ID)

| File | What it is |
| --- | --- |
| `complete-mixed.json` | The `COMPLETE` body: `enhancedFindings[6]` (1 CRITICAL, 4 HIGH, 1 MEDIUM, all `fixAvailable: "YES"`) **and** `findings: []` |
| `pending.json` | The `PENDING` body: `findings: []`, **no** `findingSeverityCounts`, no `enhancedFindings` |
| `scan-not-found.stderr.txt` | Attempt 1 stderr, 2s after push: `ScanNotFoundException` — retryable |
| `failed-open-regression.json` | Same body as `complete-mixed.json`, named for the incident it pins: the basic-only normalizer read `findings: []` and reported a clean scan |

## Derived (one stated change from the live body each)

| File | Change | Why derived |
| --- | --- | --- |
| `with-fix.json` | Kept only the CRITICAL finding; counts `{CRITICAL: 1}` | Isolate one case |
| `no-fix.json` | `with-fix.json` with `fixAvailable: "NO"`, every `fixedInVersion: "NotAvailable"` | **Not observed live** — every real finding had a fix |
| `empty-complete.json` | `enhancedFindings: []`, counts `{}` | **Not observed live.** Whether a clean enhanced scan returns `enhancedFindings: []` or omits the key is unconfirmed; the count reconciliation makes either safe |
| `malformed.json` | Truncated JSON | Synthetic |

Values assumed but not yet seen from this API, all handled fail-closed: `fixAvailable`
`"NO"`/`"PARTIAL"`, finding `status` other than `ACTIVE`, severity `UNTRIAGED`,
`fixedInVersion: "NotAvailable"`.
