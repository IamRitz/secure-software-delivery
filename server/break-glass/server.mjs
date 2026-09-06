import { resolve } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

import { loadConfig } from './config.mjs';
import { createFileStore } from './store.mjs';
import { createSlackClient } from './slack.mjs';
import { createGithubClient } from './github.mjs';
import { createBreakGlassApp } from './app.mjs';

const DATA_PATH = fileURLToPath(new URL('./data/requests.json', import.meta.url));

export function startServer(env = process.env) {
  const config = loadConfig(env);
  const app = createBreakGlassApp({
    config,
    store: createFileStore(DATA_PATH),
    slack: createSlackClient({ botToken: config.botToken }),
    github: createGithubClient({ token: config.githubToken })
  });
  const server = app.listen(config.port, () => {
    console.log(`break-glass service listening on port ${config.port}`);
  });
  return server;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) startServer();
