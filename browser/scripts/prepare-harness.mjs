import { cp } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
await cp(resolve(root, 'dist'), resolve(root, 'test-dist'), { recursive: true });
for (const name of ['harness.html', 'harness.js', 'harness-worker.js', 'parity.js']) {
  await cp(resolve(root, 'tests', name), resolve(root, 'test-dist', name));
}
