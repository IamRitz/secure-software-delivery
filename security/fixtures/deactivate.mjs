// THIS IS A DELIBERATE TEST FIXTURE FOR A CI/CD SECURITY DEMO. NOT REAL. NOT PRODUCTION CODE. See security/fixtures/README.md.

import { readFile, rm, writeFile } from 'node:fs/promises';

const TARGETS = {
  secret: 'src/config/_demo_secret.js',
  sast: 'src/_demo_sast.js'
};

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

async function assertDemoBranch(name) {
  const expected = `demo/phase-10-${name}`;
  const head = (await readFile('.git/HEAD', 'utf8')).trim();
  const actual = head.startsWith('ref: refs/heads/') ? head.slice('ref: refs/heads/'.length) : '';
  if (actual !== expected) {
    throw new Error(`refusing to deactivate ${name} on ${actual || 'detached HEAD'}; use ${expected}`);
  }
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function deactivateDependency() {
  const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
  const lockfile = JSON.parse(await readFile('package-lock.json', 'utf8'));

  if (packageJson.dependencies?.minimist !== '1.2.5') {
    throw new Error('expected activated minimist 1.2.5 dependency was not found');
  }
  if (lockfile.packages?.['node_modules/minimist']?.version !== '1.2.5') {
    throw new Error('expected activated minimist 1.2.5 lock entry was not found');
  }

  delete packageJson.dependencies.minimist;
  delete lockfile.packages[''].dependencies.minimist;
  delete lockfile.packages['node_modules/minimist'];
  await writeJson('package.json', packageJson);
  await writeJson('package-lock.json', lockfile);
  console.log('Deactivated dependency: restored the application manifest and lockfile');
}

const name = process.argv[2];
if (!['secret', 'sast', 'dependency'].includes(name)) {
  fail('Usage: node security/fixtures/deactivate.mjs <secret|sast|dependency>');
} else {
  try {
    await assertDemoBranch(name);
    if (name === 'dependency') {
      await deactivateDependency();
    } else {
      await rm(TARGETS[name], { force: true });
      if (name === 'secret') {
        await rm('src/config', { recursive: false, force: true });
      }
      console.log(`Deactivated ${name}: removed ${TARGETS[name]}`);
    }
  } catch (error) {
    fail(`Deactivation failed: ${error.message}`);
  }
}
