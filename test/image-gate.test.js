import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

import { runImageGate } from '../security/scripts/image-gate.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/image-gate');
const POLICY = resolve('security/policy.yaml');
const SCRIPT = resolve('security/scripts/image-gate.mjs');

async function evaluate(report) {
  const directory = await mkdtemp(join(tmpdir(), 'image-gate-test-'));
  try {
    return await runImageGate({
      policy: POLICY,
      report,
      output: join(directory, 'image-gate.json')
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe('image deploy gate', () => {
  it('allows deploy only for a genuinely parsed clean scan', async () => {
    const result = await evaluate(join(FIXTURES, 'clean.json'));

    assert.equal(result.verdict, 'DEPLOY');
    assert.deepEqual(result.summary, { blockDeploy: 0, log: 0 });
  });

  it('blocks deploy for a critical image finding', async () => {
    const result = await evaluate(join(FIXTURES, 'critical.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.equal(result.findings[0].policyRule, 'image.critical');
    assert.equal(result.findings[0].action, 'BLOCK_DEPLOY');
  });

  it('fails closed when the scan report is missing', async () => {
    const result = await evaluate(join(FIXTURES, 'missing.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.match(result.findings[0].reason, /missing image scan report/);
  });

  it('fails closed when the scan report is malformed', async () => {
    const result = await evaluate(join(FIXTURES, 'malformed.json'));

    assert.equal(result.verdict, 'BLOCK_DEPLOY');
    assert.match(result.findings[0].reason, /malformed JSON/);
  });

  it('maps deploy decisions directly to process exit codes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'image-gate-cli-test-'));
    const arguments_ = ['--policy', POLICY, '--output', join(directory, 'result.json')];

    try {
      const deploy = spawnSync(
        process.execPath,
        [SCRIPT, ...arguments_, '--report', join(FIXTURES, 'clean.json')],
        { encoding: 'utf8' }
      );
      const block = spawnSync(
        process.execPath,
        [SCRIPT, ...arguments_, '--report', join(FIXTURES, 'critical.json')],
        { encoding: 'utf8' }
      );

      assert.equal(deploy.status, 0);
      assert.match(deploy.stdout, /IMAGE GATE: DEPLOY/);
      assert.notEqual(block.status, 0);
      assert.match(block.stdout, /IMAGE GATE: BLOCK_DEPLOY/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
