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

// The reusable workflows that must hold no cloud credentials. `_ecr-collect.yml`
// is deliberately absent: it is the registry adapter and the one place on this
// side of the boundary that assumes a role.
const CREDENTIAL_FREE = [
  '_source-security.yml',
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

  it('only the ECR adapter and the deploy job assume a role', () => {
    const assuming = allWorkflows.filter((file) => /role-to-assume/.test(read(file)));
    assert.deepEqual(assuming.sort(), ['_ecr-collect.yml', 'deploy.yml']);
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
