import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const VALID_ACTIONS = new Set(['BLOCK', 'BLOCK_DEPLOY', 'EXCEPTION', 'LOG']);

const DEFAULT_PATHS = {
  policy: 'security/policy.yaml',
  gitleaks: 'reports/gitleaks.json',
  trufflehog: 'reports/trufflehog.json',
  npmAudit: 'reports/npm-audit.json',
  osv: 'reports/osv-scanner.json',
  semgrep: 'reports/semgrep.json',
  baseline: 'security/baseline/semgrep-baseline.json',
  output: 'reports/security-gate.json',
  exceptions: 'reports/gate-exceptions.json'
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseScalar(value) {
  if (/^-?\d+(?:\.\d+)?$/.test(value)) {
    return Number(value);
  }

  return value.replace(/^(['"])(.*)\1$/, '$2');
}

export function parseSimplePolicy(source) {
  const policy = {};
  const stack = [{ indent: -1, value: policy }];

  for (const [index, rawLine] of source.split('\n').entries()) {
    assert(!rawLine.includes('\t'), `policy line ${index + 1} contains a tab`);
    const withoutComment = rawLine.split('#', 1)[0].trimEnd();

    if (withoutComment.trim() === '') {
      continue;
    }

    const indent = withoutComment.length - withoutComment.trimStart().length;
    const match = withoutComment.trim().match(/^([A-Za-z0-9_]+):(?:\s*(.*))?$/);
    assert(match, `policy line ${index + 1} is not a simple key/value mapping`);

    while (stack.at(-1).indent >= indent) {
      stack.pop();
    }

    const parent = stack.at(-1)?.value;
    assert(parent, `policy line ${index + 1} has invalid indentation`);
    const [, key, rawValue = ''] = match;

    if (rawValue === '') {
      parent[key] = {};
      stack.push({ indent, value: parent[key] });
    } else {
      parent[key] = parseScalar(rawValue.trim());
    }
  }

  return policy;
}

function policyValue(policy, path) {
  const value = path.split('.').reduce((current, key) => current?.[key], policy);
  assert(value !== undefined, `policy is missing ${path}`);
  return value;
}

export function policyAction(policy, path) {
  const action = policyValue(policy, path);
  assert(VALID_ACTIONS.has(action), `policy ${path} has invalid action ${action}`);
  return action;
}

function validatePolicy(policy) {
  for (const path of [
    'secrets.verified',
    'secrets.unverified',
    'secrets.demo_dummy',
    'dependencies.critical_with_fix',
    'dependencies.high_with_fix',
    'dependencies.critical_no_fix',
    'dependencies.high_no_fix',
    'dependencies.medium',
    'dependencies.low',
    'dependencies.malicious_package',
    'sast.critical_new',
    'sast.high_new',
    'sast.critical_existing',
    'sast.high_existing',
    'sast.medium',
    'sast.low'
  ]) {
    policyAction(policy, path);
  }

  const thresholds = policyValue(policy, 'severity_mapping.osv_cvss_thresholds');
  assert(
    Number.isFinite(thresholds.critical) &&
      Number.isFinite(thresholds.high) &&
      Number.isFinite(thresholds.medium) &&
      thresholds.critical > thresholds.high &&
      thresholds.high > thresholds.medium,
    'OSV CVSS thresholds must be descending finite numbers'
  );

  for (const severity of ['ERROR', 'WARNING', 'INFO']) {
    normalizeSeverity(policyValue(policy, `severity_mapping.semgrep_severity.${severity}`));
  }
}

async function readJson(path, label) {
  let source;

  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`${label}: missing report file ${path}`, { cause: error });
    }
    throw new Error(`${label}: cannot read ${path}: ${error.message}`, { cause: error });
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`${label}: malformed JSON in ${path}: ${error.message}`, { cause: error });
  }
}

function normalizeSeverity(value) {
  assert(typeof value === 'string', 'severity must be a string');
  const severity = value.toLowerCase();

  if (severity === 'moderate') {
    return 'medium';
  }
  if (severity === 'info') {
    return 'low';
  }

  assert(
    ['critical', 'high', 'medium', 'low'].includes(severity),
    `unsupported severity ${value}`
  );
  return severity;
}

function addFinding(findings, policy, finding) {
  findings.push({
    ...finding,
    action: policyAction(policy, finding.policyRule)
  });
}

function evaluateSecrets(policy, gitleaks, trufflehog, findings) {
  assert(Array.isArray(gitleaks), 'Gitleaks report must be an array');
  assert(Array.isArray(trufflehog), 'TruffleHog report must be an array');

  for (const finding of gitleaks) {
    assert(typeof finding.RuleID === 'string', 'Gitleaks finding is missing RuleID');
    assert(typeof finding.File === 'string', 'Gitleaks finding is missing File');
    const isDemoDummy = finding.RuleID === 'phase10-demo-dummy-secret';
    addFinding(findings, policy, {
      source: 'gitleaks',
      id: finding.RuleID,
      location: `${finding.File}:${finding.StartLine ?? '?'}`,
      policyRule: isDemoDummy ? 'secrets.demo_dummy' : 'secrets.unverified',
      reason: isDemoDummy
        ? 'Dedicated non-credential marker activated on a never-merged demo branch'
        : 'Gitleaks pattern match is not provider-verified'
    });
  }

  for (const finding of trufflehog) {
    assert(
      typeof finding.DetectorName === 'string',
      'TruffleHog finding is missing DetectorName'
    );
    assert(typeof finding.Verified === 'boolean', 'TruffleHog finding is missing Verified');
    const state = finding.Verified ? 'verified' : 'unverified';
    addFinding(findings, policy, {
      source: 'trufflehog',
      id: finding.DetectorName,
      policyRule: `secrets.${state}`,
      reason: finding.Verified
        ? 'TruffleHog verified the credential with its provider'
        : 'TruffleHog did not verify the credential'
    });
  }
}

function evaluateNpmAudit(policy, report, findings) {
  assert(report && typeof report === 'object', 'npm audit report must be an object');
  assert(report.auditReportVersion, 'npm audit report is missing auditReportVersion');
  assert(
    report.metadata?.vulnerabilities &&
      typeof report.metadata.vulnerabilities.total === 'number',
    'npm audit report is missing metadata.vulnerabilities.total'
  );
  assert(
    report.vulnerabilities && !Array.isArray(report.vulnerabilities),
    'npm audit report is missing vulnerabilities object'
  );

  const entries = Object.entries(report.vulnerabilities);
  assert(
    entries.length === report.metadata.vulnerabilities.total,
    'npm audit vulnerability total does not match its findings object'
  );

  for (const [packageName, vulnerability] of entries) {
    const severity = normalizeSeverity(vulnerability.severity);
    assert(
      Object.hasOwn(vulnerability, 'fixAvailable'),
      `npm audit finding ${packageName} is missing fixAvailable`
    );
    const fixAvailable = vulnerability.fixAvailable !== false;
    const suffix = ['critical', 'high'].includes(severity)
      ? `_${fixAvailable ? 'with_fix' : 'no_fix'}`
      : '';
    const policyRule = `dependencies.${severity}${suffix}`;

    addFinding(findings, policy, {
      source: 'npm-audit',
      id: packageName,
      severity,
      fixAvailable,
      policyRule,
      reason: `${severity} npm advisory; fix ${fixAvailable ? 'available' : 'not available'}`
    });
  }
}

const CVSS_VALUES = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 }
};

function roundUpOneDecimal(value) {
  return Math.ceil((value - 1e-10) * 10) / 10;
}

function cvssV3Score(vector) {
  const metrics = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((part) => part.split(':'))
  );
  assert(['U', 'C'].includes(metrics.S), `unsupported CVSS scope in ${vector}`);

  const value = (metric) => {
    const result = CVSS_VALUES[metric]?.[metrics[metric]];
    assert(result !== undefined, `invalid CVSS ${metric} metric in ${vector}`);
    return result;
  };
  const privilegeRequired = {
    N: 0.85,
    L: metrics.S === 'C' ? 0.68 : 0.62,
    H: metrics.S === 'C' ? 0.5 : 0.27
  }[metrics.PR];
  assert(privilegeRequired !== undefined, `invalid CVSS PR metric in ${vector}`);

  const impactBase = 1 - (1 - value('C')) * (1 - value('I')) * (1 - value('A'));
  const impact =
    metrics.S === 'U'
      ? 6.42 * impactBase
      : 7.52 * (impactBase - 0.029) - 3.25 * (impactBase - 0.02) ** 15;

  if (impact <= 0) {
    return 0;
  }

  const exploitability =
    8.22 * value('AV') * value('AC') * privilegeRequired * value('UI');
  const base =
    metrics.S === 'U'
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUpOneDecimal(base);
}

function osvScore(vulnerability) {
  assert(Array.isArray(vulnerability.severity), `OSV ${vulnerability.id} is missing severity`);
  const scores = vulnerability.severity
    .filter((entry) => entry.type === 'CVSS_V3')
    .map((entry) => {
      const numeric = Number(entry.score);
      return Number.isFinite(numeric) ? numeric : cvssV3Score(entry.score);
    });
  assert(scores.length > 0, `OSV ${vulnerability.id} has no usable CVSS v3 score`);
  return Math.max(...scores);
}

function osvSeverity(policy, score) {
  const thresholds = policyValue(policy, 'severity_mapping.osv_cvss_thresholds');
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  return 'low';
}

function osvHasFix(vulnerability, scannedPackage) {
  assert(Array.isArray(vulnerability.affected), `OSV ${vulnerability.id} is missing affected`);
  const affected = vulnerability.affected.filter(
    (entry) =>
      entry.package?.name === scannedPackage.name &&
      (!scannedPackage.ecosystem || entry.package.ecosystem === scannedPackage.ecosystem)
  );
  assert(
    affected.length > 0,
    `OSV ${vulnerability.id} has no affected range for ${scannedPackage.name}`
  );

  return affected.some((entry) => {
    assert(Array.isArray(entry.ranges), `OSV ${vulnerability.id} affected entry lacks ranges`);
    return entry.ranges.some((range) => {
      assert(Array.isArray(range.events), `OSV ${vulnerability.id} range lacks events`);
      return range.events.some((event) => typeof event.fixed === 'string' && event.fixed !== '');
    });
  });
}

function evaluateOsv(policy, report, findings) {
  assert(report && typeof report === 'object', 'OSV-Scanner report must be an object');
  assert(Array.isArray(report.results), 'OSV-Scanner report is missing results array');

  for (const result of report.results) {
    assert(Array.isArray(result.packages), 'OSV-Scanner result is missing packages array');
    for (const dependency of result.packages) {
      assert(
        typeof dependency.package?.name === 'string',
        'OSV-Scanner package is missing package.name'
      );
      assert(
        typeof dependency.package?.version === 'string',
        `OSV-Scanner package ${dependency.package.name} is missing version`
      );
      assert(
        Array.isArray(dependency.vulnerabilities),
        `OSV-Scanner package ${dependency.package.name} is missing vulnerabilities`
      );

      for (const vulnerability of dependency.vulnerabilities) {
        assert(typeof vulnerability.id === 'string', 'OSV finding is missing id');

        if (vulnerability.id.startsWith('MAL-')) {
          addFinding(findings, policy, {
            source: 'osv-scanner',
            id: vulnerability.id,
            package: dependency.package.name,
            policyRule: 'dependencies.malicious_package',
            reason: 'OSV malicious-package advisory blocks regardless of severity'
          });
          continue;
        }

        const score = osvScore(vulnerability);
        const severity = osvSeverity(policy, score);
        const fixAvailable = osvHasFix(vulnerability, dependency.package);
        const suffix = ['critical', 'high'].includes(severity)
          ? `_${fixAvailable ? 'with_fix' : 'no_fix'}`
          : '';
        addFinding(findings, policy, {
          source: 'osv-scanner',
          id: vulnerability.id,
          package: dependency.package.name,
          severity,
          cvssScore: score,
          fixAvailable,
          policyRule: `dependencies.${severity}${suffix}`,
          reason: `${severity} OSV advisory (CVSS ${score}); fix ${
            fixAvailable ? 'available' : 'not available'
          }`
        });
      }
    }
  }
}

function semgrepFingerprint(finding) {
  assert(typeof finding.check_id === 'string', 'Semgrep finding is missing check_id');
  assert(typeof finding.path === 'string', `Semgrep ${finding.check_id} is missing path`);
  assert(
    typeof finding.extra?.lines === 'string',
    `Semgrep ${finding.check_id} is missing matched source text`
  );
  return createHash('sha256')
    .update(`${finding.check_id}\0${finding.path}\0${finding.extra.lines.trim()}`)
    .digest('hex');
}

function semgrepSeverity(policy, finding) {
  const raw = finding.extra?.severity;
  assert(typeof raw === 'string', `Semgrep ${finding.check_id} is missing severity`);

  if (['critical', 'high', 'medium', 'low'].includes(raw.toLowerCase())) {
    return raw.toLowerCase();
  }

  return normalizeSeverity(policyValue(policy, `severity_mapping.semgrep_severity.${raw}`));
}

function evaluateSemgrep(policy, report, baseline, findings) {
  assert(report && typeof report === 'object', 'Semgrep report must be an object');
  assert(typeof report.version === 'string', 'Semgrep report is missing version');
  assert(Array.isArray(report.results), 'Semgrep report is missing results array');
  assert(Array.isArray(report.errors), 'Semgrep report is missing errors array');
  assert(Array.isArray(report.paths?.scanned), 'Semgrep report is missing paths.scanned array');
  assert(report.errors.length === 0, `Semgrep report contains ${report.errors.length} errors`);
  assert(baseline?.schemaVersion === 1, 'Semgrep baseline has unsupported schemaVersion');
  assert(Array.isArray(baseline.findings), 'Semgrep baseline is missing findings array');

  const knownFingerprints = new Set(
    baseline.findings.map((finding) => {
      assert(typeof finding.fingerprint === 'string', 'baseline finding is missing fingerprint');
      assert(typeof finding.checkId === 'string', 'baseline finding is missing checkId');
      assert(typeof finding.path === 'string', 'baseline finding is missing path');
      return finding.fingerprint;
    })
  );

  for (const finding of report.results) {
    const fingerprint = semgrepFingerprint(finding);
    const severity = semgrepSeverity(policy, finding);
    const existing = knownFingerprints.has(fingerprint);
    const suffix = ['critical', 'high'].includes(severity)
      ? `_${existing ? 'existing' : 'new'}`
      : '';
    addFinding(findings, policy, {
      source: 'semgrep',
      id: finding.check_id,
      location: `${finding.path}:${finding.start?.line ?? '?'}`,
      fingerprint,
      severity,
      baselineState: existing ? 'existing' : 'new',
      policyRule: `sast.${severity}${suffix}`,
      reason: `${severity} Semgrep finding is ${existing ? 'baseline-known' : 'new'}`
    });
  }
}

function summarize(findings) {
  return Object.fromEntries(
    ['BLOCK', 'EXCEPTION', 'LOG'].map((action) => [
      action.toLowerCase(),
      findings.filter((finding) => finding.action === action).length
    ])
  );
}

async function writeResults(paths, result) {
  const exceptions = result.findings.filter((finding) => finding.action === 'EXCEPTION');
  await mkdir(dirname(paths.output), { recursive: true });
  await mkdir(dirname(paths.exceptions), { recursive: true });
  await writeFile(paths.output, `${JSON.stringify(result, null, 2)}\n`);
  await writeFile(
    paths.exceptions,
    `${JSON.stringify({ verdict: result.verdict, exceptions }, null, 2)}\n`
  );
}

export async function runSecurityGate(customPaths = {}) {
  const paths = { ...DEFAULT_PATHS, ...customPaths };
  let result;

  try {
    const policy = parseSimplePolicy(await readFile(paths.policy, 'utf8'));
    validatePolicy(policy);
    const [gitleaks, trufflehog, npmAudit, osv, semgrep, baseline] = await Promise.all([
      readJson(paths.gitleaks, 'Gitleaks'),
      readJson(paths.trufflehog, 'TruffleHog'),
      readJson(paths.npmAudit, 'npm audit'),
      readJson(paths.osv, 'OSV-Scanner'),
      readJson(paths.semgrep, 'Semgrep'),
      readJson(paths.baseline, 'Semgrep baseline')
    ]);
    const findings = [];

    evaluateSecrets(policy, gitleaks, trufflehog, findings);
    evaluateNpmAudit(policy, npmAudit, findings);
    evaluateOsv(policy, osv, findings);
    evaluateSemgrep(policy, semgrep, baseline, findings);

    const summary = summarize(findings);
    const verdict =
      summary.block > 0
        ? 'BLOCK'
        : summary.exception > 0
          ? 'PASS-WITH-EXCEPTIONS'
          : 'PASS';
    result = { verdict, summary, findings };
  } catch (error) {
    const finding = {
      source: 'security-gate',
      id: 'report-integrity',
      action: 'BLOCK',
      policyRule: 'gate.report_integrity',
      reason: error.message
    };
    result = {
      verdict: 'BLOCK',
      summary: { block: 1, exception: 0, log: 0 },
      findings: [finding]
    };
  }

  await writeResults(paths, result);
  return result;
}

function parseArguments(arguments_) {
  const aliases = {
    '--policy': 'policy',
    '--gitleaks': 'gitleaks',
    '--trufflehog': 'trufflehog',
    '--npm-audit': 'npmAudit',
    '--osv': 'osv',
    '--semgrep': 'semgrep',
    '--baseline': 'baseline',
    '--output': 'output',
    '--exceptions': 'exceptions'
  };
  const paths = {};

  for (let index = 0; index < arguments_.length; index += 2) {
    const key = aliases[arguments_[index]];
    const value = arguments_[index + 1];
    assert(key && value, `unknown or incomplete argument ${arguments_[index]}`);
    paths[key] = value;
  }

  return paths;
}

async function main() {
  let paths;

  try {
    paths = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`SECURITY GATE: BLOCK\nBLOCK security-gate report-integrity: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const result = await runSecurityGate(paths);

  for (const finding of result.findings) {
    console.log(
      `${finding.action} ${finding.source} ${finding.id} (${finding.policyRule}): ${finding.reason}`
    );
  }
  console.log(`SECURITY GATE: ${result.verdict}`);
  process.exitCode = result.verdict === 'BLOCK' ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
