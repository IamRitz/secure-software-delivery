// Structural guards on the workflow split. These properties are invisible at
// runtime when they regress — a `secrets: inherit` added "to make it work", or a
// renamed job that quietly stops satisfying branch protection, fails nothing and
// looks green. So they are asserted here instead.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const WORKFLOW_DIR = '.github/workflows';

const read = (file) => readFileSync(join(WORKFLOW_DIR, file), 'utf8');
// Comments explain these rules ("never use `secrets: inherit`"); only the
// executable body is asserted against them.
const readExecutable = (file) =>
  read(file)
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
const allWorkflows = readdirSync(WORKFLOW_DIR).filter((name) => name.endsWith('.yml'));

// Reusable workflows that must never hold cloud credentials.
// `_ecr-collect.yml` is excluded because it is the registry adapter.
// `_source-security.yml` is excluded because its source-gate job may assume
// the narrowly scoped break-glass Lambda invoker role after eligibility checks.

const CREDENTIAL_FREE = [
  '_image-scan-prepush.yml',
  '_artifact-gate.yml'
];

// Extracts the top-level `on:` block, i.e. everything up to the next unindented key.
function triggerBlock(source) {
  const lines = source.split('\n');
  const start = lines.findIndex((line) => line === 'on:');
  assert.notEqual(start, -1, 'workflow has no top-level `on:` block');
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => /^\S/.test(line));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

// Top-level job keys, i.e. two-space-indented keys under `jobs:`.
function jobIds(source) {
  const lines = source.split('\n');
  const start = lines.indexOf('jobs:');
  assert.notEqual(start, -1, 'workflow has no `jobs:` block');
  return lines
    .slice(start + 1)
    .map((line) => /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line))
    .filter(Boolean)
    .map((match) => match[1]);
}

describe('workflow split: the credential boundary', () => {
  it('production source-security callers use Lambda OIDC without the legacy shared secret', () => {
    for (const file of ['security.yml', 'deploy.yml']) {
      const source = readExecutable(file);

      assert.ok(
        source.includes('break_glass_transport: lambda'),
        `${file} must select the Lambda break-glass transport`
      );

      assert.ok(
        source.includes(
          'break_glass_lambda_role_arn: ${{ vars.BREAK_GLASS_LAMBDA_ROLE_ARN }}'
        ),
        `${file} must use the dedicated break-glass OIDC role`
      );

      assert.ok(
        source.includes(
          'break_glass_lambda_function: ${{ vars.BREAK_GLASS_LAMBDA_FUNCTION }}'
        ),
        `${file} must use the configured break-glass Lambda`
      );

      assert.ok(
        !source.includes('break_glass_notify_url:'),
        `${file} production path must not configure the legacy notify URL`
      );

      assert.ok(
        !source.includes('break_glass_status_url:'),
        `${file} production path must not configure the legacy status URL`
      );

      assert.ok(
        !source.includes('break_glass_shared_secret:'),
        `${file} production path must not pass the legacy shared secret`
      );
    }
  });
  for (const file of CREDENTIAL_FREE) {
    it(`${file} can assume no cloud role`, () => {
      const source = readExecutable(file);
      // `id-token: write` is what makes OIDC role assumption possible at all.
      assert.ok(!/id-token\s*:/.test(source), 'must not request an id-token');
      assert.ok(!/aws-actions\//.test(source), 'must not use an aws-actions action');
      assert.ok(
        !/role-to-assume/.test(source),
        'must not assume a role'
      );
    });
  }

  it('only approved workflows assume cloud roles', () => {
    const assuming = allWorkflows.filter((file) => /role-to-assume/.test(read(file)));
    assert.deepEqual(
      assuming.sort(),
      [
        '_ecr-collect.yml',
        '_source-security.yml',
        'break-glass-lambda-smoke.yml',
        'deploy.yml'
      ]
    );
  });

  it('source-security scopes OIDC to the source-gate break-glass path', () => {
    const source = readExecutable('_source-security.yml');

    const sourceGateStart = source.indexOf('  source-gate:');
    assert.notEqual(sourceGateStart, -1, 'source-gate job is missing');

    const sourceGate = source.slice(sourceGateStart);

    assert.ok(
      sourceGate.includes('id-token: write'),
      'source-gate must request an OIDC token'
    );

    assert.ok(
      sourceGate.includes('aws-actions/configure-aws-credentials@'),
      'source-gate must configure AWS credentials'
    );

    assert.ok(
      sourceGate.includes('role-to-assume: ${{ inputs.break_glass_lambda_role_arn }}'),
      'source-gate must assume only the configured break-glass role'
    );

    const eligibilityIndex = sourceGate.indexOf(
      'Confirm the BLOCK is eligible before loading any approval credential'
    );
    const oidcIndex = sourceGate.indexOf(
      'Assume the break-glass invoker role (OIDC)'
    );

    assert.ok(eligibilityIndex >= 0, 'eligibility check is missing');
    assert.ok(oidcIndex >= 0, 'OIDC role-assumption step is missing');
    assert.ok(
      eligibilityIndex < oidcIndex,
      'OIDC credentials must only be loaded after eligibility is confirmed'
    );
  });

  it('the break-glass Lambda OIDC job needs no repository secret', () => {
    const source = readExecutable('break-glass-lambda-smoke.yml');
    const oidcJob = source.slice(source.indexOf('  oidc-invoke:'), source.indexOf('  parity:'));
    assert.ok(oidcJob.includes('BREAK_GLASS_TRANSPORT: lambda'));
    assert.ok(!/secrets\./.test(oidcJob), 'the OIDC invoke path must not read any secret');
  });

  it('no workflow uses `secrets: inherit`', () => {
    for (const file of allWorkflows) {
      assert.ok(
        !/secrets\s*:\s*inherit/.test(readExecutable(file)),
        `${file} must not pass every repo secret into a called workflow`
      );
    }
  });

  it('the source and pre-push security workflows declare no secrets beyond break-glass', () => {
    // `_source-security.yml` accepts exactly one secret, the break-glass HMAC key,
    // which is not a cloud credential. `_image-scan-prepush.yml` accepts none.
    const source = read('_source-security.yml');
    const declared = [...source.matchAll(/^ {6}([a-z0-9_]+):\s*$/gm)]
      .map((match) => match[1])
      .filter((name) => source.includes(`secrets:\n      ${name}:`));
    assert.deepEqual(declared, ['break_glass_shared_secret']);
    assert.ok(!/^ {4}secrets:/m.test(read('_image-scan-prepush.yml')));
    assert.ok(!/^ {4}secrets:/m.test(read('_artifact-gate.yml')));
  });
});

describe('workflow split: the artifact gate stays registry-neutral', () => {
  it('names no registry, so swapping registries touches only the collector', () => {
    // Comments are allowed to explain the relationship; the executable body is not.
    const executable = readExecutable('_artifact-gate.yml');
    for (const term of [/\becr\b/i, /\bamazon\b/i, /\bgcr\b/i, /\backr\b/i, /\bdockerhub\b/i]) {
      assert.ok(!term.test(executable), `artifact gate must not reference ${term}`);
    }
  });
});

describe('workflow split: one workflow per trigger', () => {
  it('security.yml owns pull_request and schedule only', () => {
    const triggers = triggerBlock(read('security.yml'));
    assert.match(triggers, /pull_request:/);
    assert.match(triggers, /schedule:/);
    assert.ok(!/^ {2}push:/m.test(triggers), 'push belongs to deploy.yml');
    assert.ok(!/workflow_dispatch/.test(triggers), 'workflow_dispatch belongs to deploy.yml');
    // pull_request_target would run a writable token against untrusted fork code.
    assert.ok(!/pull_request_target/.test(triggers));
  });

  it('deploy.yml owns push-to-main and workflow_dispatch only', () => {
    const triggers = triggerBlock(read('deploy.yml'));
    assert.match(triggers, /push:/);
    assert.match(triggers, /workflow_dispatch:/);
    assert.ok(!/pull_request/.test(triggers), 'pull_request belongs to security.yml');
    assert.ok(!/schedule/.test(triggers), 'schedule belongs to security.yml');
  });
});

describe('workflow split: branch protection still resolves', () => {
  it('security.yml publishes a job whose check name is exactly `security-gate`', () => {
    // Required context on `main`. A reusable workflow reports its inner jobs as
    // `caller-job / inner-job`, so the required name is republished by a job in
    // the caller; if this disappears the rule matches nothing and merges stop
    // being gated with nothing visibly failing.
    const source = read('security.yml');
    assert.ok(jobIds(source).includes('security-gate'));
    assert.match(source, /^ {4}name: security-gate$/m);
  });
});

describe('workflow split: log-only cannot hide behind a stable check name', () => {
  it('the required check name is a literal, never an expression', () => {
    // Branch protection matches by exact string. If this name were computed from
    // the gate mode, the required context would stop resolving in one mode and
    // the rule would silently protect nothing.
    const source = read('security.yml');
    const nameLine = /^ {4}name: (.*)$/m.exec(
      source.slice(source.indexOf('  security-gate:'))
    );
    assert.equal(nameLine[1].trim(), 'security-gate');
    assert.ok(!nameLine[1].includes('${{'), 'required check name must not be computed');
  });

  it('a separate, non-required check carries the mode in its name', () => {
    const source = readExecutable('security.yml');
    assert.ok(jobIds(source).includes('gate-mode'));
    const modeName = /^ {4}name: "(\$\{\{.*)"$/m.exec(source.slice(source.indexOf('  gate-mode:')));
    assert.ok(modeName, 'gate-mode name must be an expression so it can show the mode');
    assert.match(modeName[1], /log-only/);
    // It must report the mode the reusable workflow actually ran under, not the
    // repo variable — otherwise an edit to this caller's `with:` block could put
    // the gate in log-only while this check still displayed "enforce".
    assert.match(modeName[1], /needs\.source-security\.outputs\.gate_mode/);
    assert.ok(!modeName[1].includes('vars.GATE_MODE'));
  });

  it('both security workflows expose whether their scan could be trusted', () => {
    for (const file of ['_source-security.yml', '_image-scan-prepush.yml']) {
      assert.match(read(file), /^ {6}integrity_trusted:$/m, `${file} must output integrity_trusted`);
    }
  });
});
