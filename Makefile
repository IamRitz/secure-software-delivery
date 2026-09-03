SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
TRUFFLEHOG_IMAGE := trufflesecurity/trufflehog@sha256:deb2af10659a488a14d262a323addcde099d99827a1cf1dc4e93c17915c39f08
OSV_SCANNER_IMAGE := ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475
SEMGREP_IMAGE := semgrep/semgrep@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e

.PHONY: secrets dependencies sast security gate

reports:
	mkdir -p reports

secrets: reports
	docker run --rm \
		-v "$(CURDIR):/repo:ro" \
		-v "$(CURDIR)/reports:/reports" \
		$(GITLEAKS_IMAGE) \
		git /repo --platform github --no-banner --redact=100 --report-format json \
		--report-path /reports/gitleaks.json --exit-code 0
	docker run --rm \
		-v "$(CURDIR):/repo:ro" \
		$(TRUFFLEHOG_IMAGE) \
		git file:///repo --json --no-update \
		--results=verified,unverified,unknown --no-fail --fail-on-scan-errors \
		> reports/trufflehog.raw.jsonl
	node security/scripts/normalize-trufflehog.mjs \
		reports/trufflehog.raw.jsonl reports/trufflehog.json

dependencies: reports
	set +e
	npm audit --json --package-lock-only > reports/npm-audit.json
	audit_status=$$?
	set -e
	node security/scripts/validate-dependency-report.mjs npm-audit reports/npm-audit.json
	echo "npm audit exit code: $$audit_status (gate evaluates findings)"
	set +e
	docker run --rm \
		-v "$(CURDIR):/repo:ro" \
		$(OSV_SCANNER_IMAGE) \
		scan source --lockfile=/repo/package-lock.json --format=json \
		> reports/osv-scanner.json
	osv_status=$$?
	set -e
	node security/scripts/validate-dependency-report.mjs osv-scanner reports/osv-scanner.json
	echo "OSV-Scanner exit code: $$osv_status (gate evaluates findings)"

sast: reports
	docker run --rm \
		-v "$(CURDIR):/src:ro" \
		-v "$(CURDIR)/reports:/reports" \
		-w /src \
		$(SEMGREP_IMAGE) \
		semgrep scan \
		--config p/owasp-top-ten \
		--config p/javascript \
		--json-output=/reports/semgrep.json \
		--metrics=off \
		--disable-version-check \
		src
	node security/scripts/validate-semgrep-report.mjs reports/semgrep.json

security: secrets dependencies sast

gate:
	node security/scripts/security-gate.mjs
