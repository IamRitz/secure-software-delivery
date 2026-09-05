import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { URL } from 'node:url';

const WORKFLOW_ID = 'pxM7aQXKFfa2bmWO';
const TEMPLATE = resolve('n8n/workflows/break-glass-workflow.json');
const BACKUP_DIRECTORY = resolve('n8n/backups');

function required(name) {
  const value = process.env[name];
  if (!value || value === '...') throw new Error(`${name} is not configured`);
  return value;
}

async function request(url, apiKey, options = {}) {
  const response = await globalThis.fetch(url, {
    ...options,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-n8n-api-key': apiKey,
      ...options.headers
    },
    signal: globalThis.AbortSignal.timeout(30_000)
  });
  if (!response.ok) {
    throw new Error(`n8n API ${options.method || 'GET'} ${url.pathname} returned ${response.status}`);
  }
  return response.json();
}

function configureCredentials(workflow, sharedCredentialId, githubCredentialId) {
  for (const node of workflow.nodes) {
    const header = node.credentials?.httpHeaderAuth;
    if (header?.id === 'REPLACE_SHARED_SECRET_CREDENTIAL_ID') {
      header.id = sharedCredentialId;
    }
    if (header?.id === 'REPLACE_GITHUB_PAT_CREDENTIAL_ID') {
      header.id = githubCredentialId;
    }
  }
  if (JSON.stringify(workflow).includes('REPLACE_')) {
    throw new Error('workflow still contains a credential placeholder');
  }
}

async function main() {
  const baseUrl = new URL(required('N8N_URL'));
  if (baseUrl.protocol !== 'https:') throw new Error('N8N_URL must use HTTPS');
  const apiKey = required('N8N_API_KEY');
  const sharedCredentialId = required('N8N_SHARED_SECRET_CREDENTIAL_ID');
  const githubCredentialId = required('N8N_GITHUB_CREDENTIAL_ID');
  const endpoint = new URL(`/api/v1/workflows/${WORKFLOW_ID}`, baseUrl);

  const current = await request(endpoint, apiKey);
  await mkdir(BACKUP_DIRECTORY, { recursive: true });
  const stamp = new Date().toISOString().replaceAll(':', '-');
  const backup = resolve(BACKUP_DIRECTORY, `${WORKFLOW_ID}-${stamp}.json`);
  await writeFile(backup, `${JSON.stringify(current, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600
  });

  const template = JSON.parse(await readFile(TEMPLATE, 'utf8'));
  configureCredentials(template, sharedCredentialId, githubCredentialId);
  const update = {
    name: template.name,
    nodes: template.nodes,
    connections: template.connections,
    settings: template.settings
  };
  const saved = await request(endpoint, apiKey, {
    method: 'PUT',
    body: JSON.stringify(update)
  });
  await request(new URL(`/api/v1/workflows/${WORKFLOW_ID}/activate`, baseUrl), apiKey, {
    method: 'POST',
    body: '{}'
  });
  console.log(`Updated and activated n8n workflow ${saved.id}; backup: ${backup}`);
}

await main();
