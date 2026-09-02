import express from 'express';

const initialUsers = [
  { id: 1, name: 'Ada Lovelace', email: 'ada@example.com' },
  { id: 2, name: 'Grace Hopper', email: 'grace@example.com' }
];

const products = [
  { id: 1, name: 'Pipeline Starter', price: 29.99 },
  { id: 2, name: 'Security Gate', price: 49.99 }
];

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function createApp() {
  const app = express();
  const users = initialUsers.map((user) => ({ ...user }));

  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));

  app.get('/health', (_request, response) => {
    response.json({ status: 'ok' });
  });

  app.get('/api/users', (_request, response) => {
    response.json(users);
  });

  app.get('/api/products', (_request, response) => {
    response.json(products);
  });

  app.post('/api/users', (request, response) => {
    const { name, email } = request.body ?? {};
    const normalizedName = typeof name === 'string' ? name.trim() : '';
    const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

    if (normalizedName.length < 2 || normalizedName.length > 100) {
      return response.status(400).json({
        error: 'name must be between 2 and 100 characters'
      });
    }

    if (normalizedEmail.length > 254 || !emailPattern.test(normalizedEmail)) {
      return response.status(400).json({ error: 'email must be valid' });
    }

    if (users.some((user) => user.email === normalizedEmail)) {
      return response.status(409).json({ error: 'email already exists' });
    }

    const user = {
      id: users.length === 0 ? 1 : Math.max(...users.map(({ id }) => id)) + 1,
      name: normalizedName,
      email: normalizedEmail
    };

    users.push(user);
    return response.status(201).json(user);
  });

  app.use((_request, response) => {
    response.status(404).json({ error: 'not found' });
  });

  app.use((error, _request, response, _next) => {
    if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
      return response.status(400).json({ error: 'request body must be valid JSON' });
    }

    console.error(error);
    return response.status(500).json({ error: 'internal server error' });
  });

  return app;
}
