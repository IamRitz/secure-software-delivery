import { readFileSync } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

// Request state store. Replaces n8n's workflow static data. Updates are
// serialized through an in-process promise chain so the pending -> processing
// claim guard is race-free without any external "concurrency = 1" setting, and
// each write is atomic (temp file + rename). Sufficient for a handful of pending
// requests at this scale; a multi-repo rollout would swap the adapter for a
// shared store without changing callers.
function createStore({ initial = {}, persist }) {
  const requests = initial;
  let chain = Promise.resolve();

  async function run(mutator) {
    const result = await mutator(requests);
    await persist(requests);
    return result;
  }

  return {
    get: (id) => requests[id],
    all: () => requests,
    // Serialize every mutation; a rejected mutator must not break the chain.
    update(mutator) {
      const result = chain.then(() => run(mutator));
      chain = result.then(
        () => {},
        () => {}
      );
      return result;
    }
  };
}

export function createFileStore(filePath) {
  let initial;
  try {
    initial = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    initial = {};
  }
  async function persist(requests) {
    const tmp = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(tmp, `${JSON.stringify(requests, null, 2)}\n`);
    await rename(tmp, filePath);
  }
  return createStore({ initial, persist });
}

export function createMemoryStore(initial = {}) {
  return createStore({ initial, persist: async () => {} });
}
