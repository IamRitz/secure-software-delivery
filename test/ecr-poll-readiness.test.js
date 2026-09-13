// Polling readiness in enhanced mode, against a response captured live.
//
// Run 34745111774: ECR answered COMPLETE ~10s after the scan finished, but with
// `findings: []` and no severity counts — Inspector had not attached its results.
// The poller treated that as terminal and the gate blocked on an empty report.
// The block was correct (unknown is not clean); giving up at 16s was not.
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { findingsAttached, normalizeEcrResponse, pollEcrScan } from '../security/scripts/poll-ecr-scan.mjs';

const FIXTURES = resolve('security/scripts/__fixtures__/ecr-enhanced');
const DIGEST = 'sha256:7bb2656c990a9e3c82aa44a28bee2ee14fbcabbc9cf30c642f5c79f112b7b7d1';

let directory;
let originalPath;

async function fixture(name) {
  return JSON.parse(await readFile(join(FIXTURES, name), 'utf8'));
}

// The live counts-less body, re-pointed at the digest of the populated capture so
// a before -> after sequence describes one image.
async function beforeFindings() {
  const body = await fixture('complete-before-findings.json');
  body.imageId.imageDigest = DIGEST;
  return body;
}

// A fake `aws` on PATH that returns response N on call N, repeating the last one.
async function fakeAwsSequence(bodies) {
  for (const [index, body] of bodies.entries()) {
    await writeFile(join(directory, `body-${index}.json`), JSON.stringify(body));
  }
  const bin = join(directory, 'aws');
  await writeFile(
    bin,
    [
      '#!/bin/sh',
      `count_file="${join(directory, 'count')}"`,
      'n=$(cat "$count_file" 2>/dev/null || echo 0)',
      `last=${bodies.length - 1}`,
      '[ "$n" -gt "$last" ] && n=$last',
      `cat "${directory}/body-$n.json"`,
      'echo $((n + 1)) > "$count_file"'
    ].join('\n')
  );
  await chmod(bin, 0o755);
  process.env.PATH = `${directory}:${originalPath}`;
}

function options(overrides = {}) {
  return {
    repository: 'secure-software-delivery',
    region: 'us-east-1',
    image_digest: DIGEST,
    image_tag: 'test',
    raw_output: join(directory, 'raw.json'),
    maxAttempts: 5,
    delaySeconds: 0,
    ...overrides
  };
}

describe('poll readiness: COMPLETE before findings are attached', () => {
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'ecr-ready-'));
    originalPath = process.env.PATH;
  });

  afterEach(async () => {
    process.env.PATH = originalPath;
    await rm(directory, { recursive: true, force: true });
  });

  it('recognizes the live counts-less COMPLETE body as not ready', async () => {
    const body = await fixture('complete-before-findings.json');
    assert.equal(body.imageScanStatus.status, 'COMPLETE');
    assert.equal(findingsAttached(body), false);
    assert.equal(findingsAttached(await fixture('complete-mixed.json')), true);
    assert.equal(findingsAttached(await fixture('empty-complete.json')), true);
  });

  it('keeps waiting through it and returns the populated result', async () => {
    await fakeAwsSequence([await beforeFindings(), await beforeFindings(), await fixture('complete-mixed.json')]);
    const report = await pollEcrScan(options());
    assert.equal(report.source, 'aws-ecr-enhanced');
    assert.equal(report.findings.length, 6);

    const raw = JSON.parse(await readFile(join(directory, 'raw.json'), 'utf8'));
    assert.equal(raw.attempts.length, 3);
  });

  it('fails closed at the limit if findings never attach — never reads it as clean', async () => {
    await fakeAwsSequence([await beforeFindings()]);
    await assert.rejects(
      pollEcrScan(options({ maxAttempts: 3 })),
      /did not complete before the polling limit \(last state: COMPLETE but findings not yet attached/
    );
  });

  it('the normalizer still rejects the counts-less body on its own (defence in depth)', async () => {
    const body = await beforeFindings();
    assert.throws(
      () => normalizeEcrResponse(body, { repository: 'r', image_digest: DIGEST }),
      /lacks findingSeverityCounts/
    );
  });
});
