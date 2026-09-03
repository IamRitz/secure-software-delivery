import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const [reportPath] = process.argv.slice(2);

if (!reportPath) {
  throw new Error('usage: generate-semgrep-baseline.mjs <semgrep-report.json>');
}

const report = JSON.parse(await readFile(reportPath, 'utf8'));

if (!Array.isArray(report.results) || !Array.isArray(report.errors)) {
  throw new Error('Semgrep report does not have the expected JSON schema');
}

if (report.errors.length > 0) {
  throw new Error('refusing to baseline a Semgrep report that contains scan errors');
}

const findings = report.results
  .map((finding) => {
    const checkId = finding.check_id;
    const path = finding.path;
    const matchedCode = finding.extra?.lines?.trim();

    if (!checkId || !path || !matchedCode) {
      throw new Error('Semgrep finding lacks check_id, path, or matched source text');
    }

    return {
      fingerprint: createHash('sha256')
        .update(`${checkId}\0${path}\0${matchedCode}`)
        .digest('hex'),
      checkId,
      path
    };
  })
  .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));

const baseline = {
  schemaVersion: 1,
  generatedBy: `semgrep ${report.version}`,
  rulesets: ['p/owasp-top-ten', 'p/javascript'],
  findings
};

process.stdout.write(`${JSON.stringify(baseline, null, 2)}\n`);
