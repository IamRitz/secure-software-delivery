import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

const require = createRequire(import.meta.url);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const workflow = JSON.parse(
  await readFile('n8n/workflows/break-glass-workflow.json', 'utf8')
);

function node(name) {
  const result = workflow.nodes.find((candidate) => candidate.name === name);
  assert(result, `workflow node ${name} is missing`);
  return result;
}

describe('n8n break-glass workflow definition', () => {
  it('defines authenticated notify/status hooks and preserves the live Discord route', () => {
    assert.equal(node('Webhook A - Notify').parameters.authentication, 'headerAuth');
    assert.equal(node('Webhook C - Status').parameters.authentication, 'headerAuth');
    assert.equal(node('Webhook B - Discord Interactions').parameters.path, 'discord/interactions');
    assert.equal(node('Webhook B - Discord Interactions').parameters.options.rawBody, true);
    assert.equal(
      node('Webhook B - Break Glass Interactions Alias').parameters.path,
      'break-glass/interactions'
    );
  });

  it('rejects an invalid signature in the actual n8n Code node', async () => {
    const code = node('Verify Discord Signature').parameters.jsCode;
    const execute = new AsyncFunction('require', '$input', code);
    const result = await execute.call(
      { helpers: { getBinaryDataBuffer: async () => Buffer.from('{"type":1}') } },
      require,
      {
        first: () => ({
          json: {
            headers: {
              'x-signature-ed25519': '00'.repeat(64),
              'x-signature-timestamp': '1725400000'
            }
          },
          binary: { data: { data: Buffer.from('{"type":1}').toString('base64') } }
        })
      }
    );
    assert.equal(result[0].json.responseCode, 401);
    assert.equal(result[0].json.responseBody.error, 'invalid_request_signature');
  });

  it('accepts a genuinely valid signature and defers component clicks in the actual node', async () => {
    const rawCode = node('Verify Discord Signature').parameters.jsCode;
    const productionKeyHex = /const publicKeyHex = '([0-9a-f]{64})'/.exec(rawCode)[1];
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const testKeyHex = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString(
      'hex'
    );
    // Patch only the hardcoded Discord key so we can sign with a known keypair;
    // Discord never publishes its private key, so this is the only way to prove
    // the real runtime node accepts a correctly-signed request, not just rejects.
    const code = rawCode.replace(productionKeyHex, testKeyHex);
    const execute = new AsyncFunction('require', '$input', code);

    async function run(bodyObject) {
      const rawBody = Buffer.from(JSON.stringify(bodyObject));
      const timestamp = String(Math.floor(Date.now() / 1000));
      const signatureHex = sign(
        null,
        Buffer.concat([Buffer.from(timestamp), rawBody]),
        privateKey
      ).toString('hex');
      return execute.call(
        { helpers: { getBinaryDataBuffer: async () => rawBody } },
        require,
        {
          first: () => ({
            json: {
              headers: {
                'x-signature-ed25519': signatureHex,
                'x-signature-timestamp': timestamp
              }
            },
            binary: { data: { data: rawBody.toString('base64') } }
          })
        }
      );
    }

    const ping = await run({ type: 1 });
    assert.equal(ping[0].json.responseCode, 200);
    assert.equal(ping[0].json.responseBody.type, 1);
    assert.equal(ping[0].json.processComponent, false);

    const component = await run({
      type: 3,
      data: { custom_id: 'breakglass:11111111-1111-4111-8111-111111111111:approve' }
    });
    assert.equal(component[0].json.responseCode, 200);
    assert.equal(component[0].json.responseBody.type, 6);
    assert.equal(component[0].json.processComponent, true);
  });

  it('leaves pending state unchanged for an unauthorized Approve click', async () => {
    const code = node('Authorize and Claim Decision').parameters.jsCode;
    const execute = new AsyncFunction('$json', '$env', '$getWorkflowStaticData', code);
    const requestId = '11111111-1111-4111-8111-111111111111';
    const state = {
      requests: {
        [requestId]: { status: 'pending', expiresAt: '2099-01-01T00:00:00.000Z' }
      }
    };
    const result = await execute(
      {
        interaction: {
          type: 3,
          data: { custom_id: `breakglass:${requestId}:approve` },
          member: { user: { id: 'not-allowed', username: 'intruder' } }
        }
      },
      { DISCORD_APPROVER_IDS: 'allowed-user' },
      () => state
    );
    assert.equal(result[0].json.outcome, 'unauthorized');
    assert.equal(state.requests[requestId].status, 'pending');
  });
});
