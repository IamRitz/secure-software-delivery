import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';

import { createApp } from '../src/app.js';

describe('REST API', () => {
  it('reports its health', async () => {
    const response = await request(createApp()).get('/health');

    assert.equal(response.status, 200);
    assert.ok(Object.hasOwn(response.body, 'status'));
    assert.equal(response.body.status, 'ok');
  });

  it('lists users', async () => {
    const response = await request(createApp()).get('/api/users');

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [
      { id: 1, name: 'Ada Lovelace', email: 'ada@example.com' },
      { id: 2, name: 'Grace Hopper', email: 'grace@example.com' }
    ]);
  });

  it('lists products', async () => {
    const response = await request(createApp()).get('/api/products');

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [
      { id: 1, name: 'Pipeline Starter', price: 29.99 },
      { id: 2, name: 'Security Gate', price: 49.99 }
    ]);
  });

  it('creates a normalized user', async () => {
    const app = createApp();
    const createResponse = await request(app).post('/api/users').send({
      name: '  Katherine Johnson  ',
      email: 'Katherine@Example.COM'
    });

    assert.equal(createResponse.status, 201);
    assert.deepEqual(createResponse.body, {
      id: 3,
      name: 'Katherine Johnson',
      email: 'katherine@example.com'
    });

    const listResponse = await request(app).get('/api/users');
    assert.equal(listResponse.body.length, 3);
  });

  for (const [description, body, expectedField] of [
    ['a missing name', { email: 'valid@example.com' }, 'name'],
    ['an invalid name', { name: 'A', email: 'valid@example.com' }, 'name'],
    ['a missing email', { name: 'Valid Name' }, 'email'],
    ['an invalid email', { name: 'Valid Name', email: 'not-an-email' }, 'email']
  ]) {
    it(`rejects ${description}`, async () => {
      const response = await request(createApp()).post('/api/users').send(body);

      assert.equal(response.status, 400);
      assert.match(response.body.error, new RegExp(expectedField));
    });
  }

  it('rejects duplicate email addresses', async () => {
    const response = await request(createApp())
      .post('/api/users')
      .send({ name: 'Another Ada', email: 'ADA@example.com' });

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, { error: 'email already exists' });
  });

  it('rejects malformed JSON', async () => {
    const response = await request(createApp())
      .post('/api/users')
      .set('Content-Type', 'application/json')
      .send('{broken');

    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'request body must be valid JSON' });
  });

  it('returns JSON for unknown routes', async () => {
    const response = await request(createApp()).get('/missing');

    assert.equal(response.status, 404);
    assert.deepEqual(response.body, { error: 'not found' });
  });
});
