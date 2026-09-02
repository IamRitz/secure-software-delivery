# Secure Software Delivery

A deliberately small Node.js and Express REST API used to demonstrate a secure
CI/CD pipeline in GitHub Actions and Jenkins.

> `npm install` and `pip install` do not just download packages: they run
> someone else's code on the runner with whatever credentials that runner is
> holding. Therefore, untrusted install/build code must never run in a job that
> holds AWS, ECR, or deployment credentials.

That principle defines the future pipeline boundary. This repository currently
contains the application plus Phase 2 tests, linting, and container packaging.
No CI/CD or cloud deployment has been added yet.

## Requirements

- Node.js 22 or newer
- npm
- Docker (optional)

## Run locally

```sh
npm ci
npm test
npm run lint
npm start
```

The committed lockfile is authoritative. Local automation and all future CI
jobs must use `npm ci`, never `npm install`, so dependency resolution cannot
silently rewrite it. The repository's current npm 10.9.2 does not support
`min-release-age`; `.npmrc` records the seven-day setting in commented form and
the requirement to enable it with npm 11.10.0 or newer.

The service listens on `http://localhost:3000` by default. Set `PORT` to use a
different port.

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Return service health |
| `GET` | `/api/users` | List in-memory users |
| `GET` | `/api/products` | List sample products |
| `POST` | `/api/users` | Create an in-memory user |

Create a user with a JSON body containing `name` and `email`:

```sh
curl -X POST http://localhost:3000/api/users \
  -H 'content-type: application/json' \
  -d '{"name":"Katherine Johnson","email":"katherine@example.com"}'
```

Data is intentionally in memory and resets whenever the process restarts.

## Container

```sh
docker build -t secure-software-delivery:phase2 .
docker run --rm -p 3000:3000 secure-software-delivery:phase2
```
