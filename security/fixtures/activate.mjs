// THIS IS A DELIBERATE TEST FIXTURE FOR A CI/CD SECURITY DEMO. NOT REAL. NOT PRODUCTION CODE. See security/fixtures/README.md.

import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const NOTICE =
  'THIS IS A DELIBERATE TEST FIXTURE FOR A CI/CD SECURITY DEMO. NOT REAL. NOT PRODUCTION CODE. See security/fixtures/README.md.';
const FIXTURES = {
  secret: {
    source: 'security/fixtures/secrets/demo-secret.js',
    target: 'src/config/_demo_secret.js'
  },
  sast: {
    source: 'security/fixtures/sast/command-injection.js',
    target: 'src/_demo_sast.js'
  }
};
const DEPENDENCY = {
  name: 'minimist',
  version: '1.2.5',
  lockEntry: {
    version: '1.2.5',
    resolved: 'https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz',
    integrity:
      'sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==',
    license: 'MIT'
  }
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
    throw new Error(`refusing to activate ${name} on ${actual || 'detached HEAD'}; use ${expected}`);
  }
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function activateSourceFixture(name) {
  const fixture = FIXTURES[name];
  await mkdir(dirname(resolve(fixture.target)), { recursive: true });
  await copyFile(resolve(fixture.source), resolve(fixture.target));
  console.log(`Activated ${name}: ${fixture.target}`);
}

async function activateDependency() {
  const fixture = JSON.parse(
    await readFile('security/fixtures/dependency/package.json', 'utf8')
  );
  if (fixture._fixtureNotice !== NOTICE || fixture.dependencies?.minimist !== DEPENDENCY.version) {
    throw new Error('dependency fixture metadata is invalid');
  }

  const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
  const lockfile = JSON.parse(await readFile('package-lock.json', 'utf8'));
  if (packageJson.dependencies?.[DEPENDENCY.name]) {
    throw new Error(`${DEPENDENCY.name} already exists in the application dependency tree`);
  }
  if (lockfile.packages?.[`node_modules/${DEPENDENCY.name}`]) {
    throw new Error(`${DEPENDENCY.name} already exists in the application lockfile`);
  }

  packageJson.dependencies[DEPENDENCY.name] = DEPENDENCY.version;
  lockfile.packages[''].dependencies[DEPENDENCY.name] = DEPENDENCY.version;
  lockfile.packages[`node_modules/${DEPENDENCY.name}`] = DEPENDENCY.lockEntry;
  await writeJson('package.json', packageJson);
  await writeJson('package-lock.json', lockfile);
  console.log(
    'Activated dependency: minimist 1.2.5 (GHSA-xvch-5gv4-984h; fixed in 1.2.6)'
  );
}

const name = process.argv[2];
if (!['secret', 'sast', 'dependency'].includes(name)) {
  fail('Usage: node security/fixtures/activate.mjs <secret|sast|dependency>');
} else {
  try {
    await assertDemoBranch(name);
    if (name === 'dependency') {
      await activateDependency();
    } else {
      await activateSourceFixture(name);
    }
  } catch (error) {
    fail(`Activation failed: ${error.message}`);
  }
}
