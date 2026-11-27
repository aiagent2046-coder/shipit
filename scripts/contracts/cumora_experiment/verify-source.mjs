// Compare every prepared source file in the image with the host-bound manifest.
// Generated build files and installed dependencies are outside this source scope.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
try {
  const [rootArgument, manifestPath, expectedDigest] = process.argv.slice(2);
  if (!rootArgument || !manifestPath || !/^[a-f0-9]{64}$/.test(expectedDigest ?? '')) {
    throw new Error('invalid source verification arguments');
  }
  const root = resolve(rootArgument);
  const raw = readFileSync(manifestPath);
  if (raw.length > 8 * 1024 * 1024 || hash(raw) !== expectedDigest) {
    throw new Error('source manifest identity mismatch');
  }
  const manifest = JSON.parse(raw);
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('invalid source manifest');
  }
  const entries = Object.entries(manifest);
  if (!entries.length || entries.length > 50000) throw new Error('invalid source file count');
  for (const [name, expected] of entries) {
    const parts = name.split('/');
    const file = resolve(root, ...parts);
    if (name.includes('\\') || parts.some(part => !part || part === '.' || part === '..')
        || !file.startsWith(root + sep) || typeof expected !== 'string'
        || !/^[a-f0-9]{64}$/.test(expected)) {
      throw new Error('invalid source manifest entry');
    }
    if (!lstatSync(file).isFile() || hash(readFileSync(file)) !== expected) {
      throw new Error('prepared source file mismatch: ' + name);
    }
  }
  process.stdout.write(expectedDigest + '\n');
} catch (error) {
  process.stderr.write('Source verification failed: ' + error.message + '\n');
  process.exitCode = 1;
}
