import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

import { runSecurityGate } from '../security/scripts/security-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__');
const CLEAN = join(FIXTURES, 'clean');
const GATE_SCRIPT = resolve('security/scripts/security-gate.mjs');

async function evaluate(overrides = {}) {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'security-gate-test-'));
  const paths = {
    policy: resolve('security/policy.yaml'),
    gitleaks: join(CLEAN, 'gitleaks.json'),
    trufflehog: join(CLEAN, 'trufflehog.json'),
    npmAudit: join(CLEAN, 'npm-audit.json'),
    osv: join(CLEAN, 'osv-scanner.json'),
    semgrep: join(CLEAN, 'semgrep.json'),
    baseline: join(CLEAN, 'semgrep-baseline.json'),
    output: join(outputDirectory, 'security-gate.json'),
    exceptions: join(outputDirectory, 'gate-exceptions.json'),
    ...overrides
  };

  try {
    const result = await runSecurityGate(paths);
    const exceptions = JSON.parse(await readFile(paths.exceptions, 'utf8'));
    return { result, exceptions };
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
}

function onlyFinding(result) {
  assert.equal(result.findings.length, 1);
  return result.findings[0];
}

describe('security gate', () => {
  it('passes genuinely clean reports', async () => {
    const { result, exceptions } = await evaluate();

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(result.summary, { block: 0, exception: 0, log: 0 });
    assert.deepEqual(exceptions.exceptions, []);
  });

  it('blocks a verified secret', async () => {
    const { result } = await evaluate({
      trufflehog: join(FIXTURES, 'verified-secret/trufflehog.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'secrets.verified');
    assert.equal(result.breakGlass.eligible, false);
  });

  it('blocks the dedicated non-credential demo marker without calling it verified', async () => {
    const { result } = await evaluate({
      gitleaks: join(FIXTURES, 'demo-dummy-secret/gitleaks.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'secrets.demo_dummy');
    assert.match(onlyFinding(result).reason, /non-credential marker/);
  });

  it('blocks a critical dependency with a fix', async () => {
    const { result } = await evaluate({
      npmAudit: join(FIXTURES, 'critical-with-fix/npm-audit.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_with_fix');
    assert.equal(result.breakGlass.eligible, true);
  });

  it('passes with a visible exception for an unfixed critical dependency', async () => {
    const { result, exceptions } = await evaluate({
      npmAudit: join(FIXTURES, 'critical-no-fix/npm-audit.json')
    });

    assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_no_fix');
    assert.equal(exceptions.exceptions.length, 1);
  });

  it('blocks an OSV malicious-package advisory regardless of severity', async () => {
    const { result } = await evaluate({
      osv: join(FIXTURES, 'malicious-package/osv-scanner.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.malicious_package');
    assert.equal(result.breakGlass.eligible, false);
  });

  it('blocks a critical OSV advisory when its range contains a fix', async () => {
    const { result } = await evaluate({
      osv: join(FIXTURES, 'osv-critical-with-fix/osv-scanner.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).cvssScore, 9.8);
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_with_fix');
  });

  it('excepts a critical OSV advisory when its range contains no fix', async () => {
    const { result, exceptions } = await evaluate({
      osv: join(FIXTURES, 'osv-critical-no-fix/osv-scanner.json')
    });

    assert.equal(result.verdict, 'PASS-WITH-EXCEPTIONS');
    assert.equal(onlyFinding(result).policyRule, 'dependencies.critical_no_fix');
    assert.equal(exceptions.exceptions.length, 1);
  });

  it('blocks a new high-severity Semgrep finding', async () => {
    const { result } = await evaluate({
      semgrep: join(FIXTURES, 'new-high-sast/semgrep.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.equal(onlyFinding(result).policyRule, 'sast.high_new');
    assert.equal(result.breakGlass.eligible, true);
  });

  it('logs an existing critical Semgrep finding without blocking', async () => {
    const { result } = await evaluate({
      semgrep: join(FIXTURES, 'existing-critical-sast/semgrep.json'),
      baseline: join(FIXTURES, 'existing-critical-sast/semgrep-baseline.json')
    });

    assert.equal(result.verdict, 'PASS');
    assert.equal(onlyFinding(result).policyRule, 'sast.critical_existing');
    assert.equal(onlyFinding(result).action, 'LOG');
  });

  it('fails closed when a report is missing', async () => {
    const { result } = await evaluate({ npmAudit: join(FIXTURES, 'does-not-exist.json') });

    assert.equal(result.verdict, 'BLOCK');
    assert.match(onlyFinding(result).reason, /missing report file/);
  });

  it('fails closed when a report contains malformed JSON', async () => {
    const { result } = await evaluate({
      npmAudit: join(FIXTURES, 'malformed/npm-audit.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.match(onlyFinding(result).reason, /malformed JSON/);
  });

  it('fails closed when a finding omits a field required by policy', async () => {
    const { result } = await evaluate({
      trufflehog: join(FIXTURES, 'missing-field/trufflehog.json')
    });

    assert.equal(result.verdict, 'BLOCK');
    assert.match(onlyFinding(result).reason, /missing Verified/);
  });

  it('maps PASS, exception, and BLOCK verdicts directly to process exit codes', async () => {
    const outputDirectory = await mkdtemp(join(tmpdir(), 'security-gate-cli-test-'));
    const commonArguments = [
      '--policy',
      resolve('security/policy.yaml'),
      '--gitleaks',
      join(CLEAN, 'gitleaks.json'),
      '--trufflehog',
      join(CLEAN, 'trufflehog.json'),
      '--osv',
      join(CLEAN, 'osv-scanner.json'),
      '--semgrep',
      join(CLEAN, 'semgrep.json'),
      '--baseline',
      join(CLEAN, 'semgrep-baseline.json'),
      '--output',
      join(outputDirectory, 'security-gate.json'),
      '--exceptions',
      join(outputDirectory, 'gate-exceptions.json')
    ];

    try {
      const pass = spawnSync(
        process.execPath,
        [GATE_SCRIPT, ...commonArguments, '--npm-audit', join(CLEAN, 'npm-audit.json')],
        { encoding: 'utf8' }
      );
      const block = spawnSync(
        process.execPath,
        [GATE_SCRIPT, ...commonArguments, '--npm-audit', join(FIXTURES, 'does-not-exist.json')],
        { encoding: 'utf8' }
      );
      const exception = spawnSync(
        process.execPath,
        [
          GATE_SCRIPT,
          ...commonArguments,
          '--npm-audit',
          join(FIXTURES, 'critical-no-fix/npm-audit.json')
        ],
        { encoding: 'utf8' }
      );

      assert.equal(pass.status, 0);
      assert.match(pass.stdout, /SECURITY GATE: PASS/);
      assert.equal(exception.status, 0);
      assert.match(exception.stdout, /SECURITY GATE: PASS-WITH-EXCEPTIONS/);
      assert.notEqual(block.status, 0);
      assert.match(block.stdout, /SECURITY GATE: BLOCK/);
    } finally {
      await rm(outputDirectory, { recursive: true, force: true });
    }
  });
});
