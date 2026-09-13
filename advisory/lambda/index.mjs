// AWS Lambda entry point for the advisory finding explainer (shadow-mode POC).
//
// Invoked by GitHub Actions through an OIDC-federated role that can call
// lambda:InvokeFunction on this function and nothing else. The model API key
// lives only in Secrets Manager, read by this function's execution role; it is
// never in GitHub or n8n.

import Anthropic from '@anthropic-ai/sdk';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

import { explainFindings } from './explain.mjs';

let cachedClient;

async function modelClient() {
  if (cachedClient) return cachedClient;
  const secretId = process.env.ANTHROPIC_API_KEY_SECRET_ARN;
  if (!secretId) throw new Error('ANTHROPIC_API_KEY_SECRET_ARN is not configured');
  const secret = await new SecretsManagerClient({}).send(new GetSecretValueCommand({ SecretId: secretId }));
  if (!secret.SecretString) throw new Error('model API key secret is empty');
  cachedClient = new Anthropic({ apiKey: secret.SecretString });
  return cachedClient;
}

const log = (entry) => console.log(JSON.stringify(entry));

export async function handler(event) {
  const started = Date.now();
  let client;
  try {
    client = await modelClient();
  } catch (error) {
    log({ event: 'config_error', error: error.message });
    return { ok: false, error: 'explainer is not configured' };
  }
  const result = await explainFindings(event, { client, log });
  const totalLatencyMs = Date.now() - started;
  // Counts only — explanation text is returned to the caller, not logged here.
  log({
    event: 'invocation',
    ok: result.ok,
    error: result.ok ? undefined : result.error,
    totalLatencyMs,
    modelLatencyMs: result.modelLatencyMs,
    usage: result.usage,
    statuses: result.results?.map((r) => r.status)
  });
  return { ...result, totalLatencyMs };
}
