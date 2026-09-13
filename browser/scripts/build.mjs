// A static directory, with no runtime CDN or API dependency. No customer code
// is part of the build; engine-files.json contains only our reviewed modules.
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const out = resolve(process.argv[2] || join(root, 'browser/dist'));
const runtime = join(root, 'browser/node_modules/pyodide');
const version = JSON.parse(await readFile(join(runtime, 'package.json'))).version;
const lock = JSON.parse(await readFile(join(runtime, 'pyodide-lock.json')));
await mkdir(join(out, 'runtime'), { recursive: true });
for (const name of ['pyodide.mjs', 'pyodide.asm.mjs', 'pyodide.asm.wasm',
                    'python_stdlib.zip', 'pyodide-lock.json']) {
  await cp(join(runtime, name), join(out, 'runtime', name));
}
// Use the runtime's pinned package name AND hash. Build-time download only.
const yaml = lock.packages.pyyaml;
const wheel = join(out, 'runtime', yaml.file_name);
let cached;
try { cached = await readFile(wheel); } catch { /* first build */ }
if (!cached || createHash('sha256').update(cached).digest('hex') !== yaml.sha256) {
  execFileSync('curl', ['--fail', '--silent', '--show-error', '--location',
    '--max-time', '120', '--output', wheel,
    `https://cdn.jsdelivr.net/pyodide/v${version}/full/${yaml.file_name}`], { stdio: 'inherit' });
}
if (createHash('sha256').update(await readFile(wheel)).digest('hex') !== yaml.sha256) {
  throw new Error('PyYAML wheel integrity mismatch');
}

const files = {};
// Never ship provider clients, the API, billing, or the orchestration pipeline.
const excluded = new Set(['pipeline.py', 'llm_scan.py']);
const paths = (await readdir(join(root, 'app/scan')))
  .filter(name => name.endsWith('.py') && !excluded.has(name))
  .map(name => `app/scan/${name}`);
paths.push('app/__init__.py', 'app/capabilities.py', 'app/ingest/__init__.py',
  'app/ingest/validators.py', 'app/report/__init__.py', 'app/report/plain_language.py',
  'app/report/sarif.py', 'app/sca/__init__.py', 'app/sca/lockfiles.py');
for (const path of paths.sort()) files[path] = await readFile(join(root, path), 'utf8');
const bundle = JSON.stringify(files);
await writeFile(join(out, 'engine-files.json'), bundle);
await cp(join(root, 'LICENSE'), join(out, 'LICENSE.txt'));
await cp(join(root, 'browser/THIRD_PARTY_NOTICES.md'), join(out, 'THIRD_PARTY_NOTICES.txt'));
for (const name of ['index.html', 'app.js', 'styles.css', 'worker.js', 'runtime.js']) {
  await cp(join(root, 'browser/src', name), join(out, name));
}
const manifest = {
  profile: 'python-browser-preview', pyodide: version,
  python: lock.info.python, engine_sha256: createHash('sha256').update(bundle).digest('hex'),
  native_parsers: { tree_sitter: 'unavailable', pglast: 'unavailable' },
};
await writeFile(join(out, 'build.json'), JSON.stringify(manifest, null, 2) + '\n');
let bytes = 0;
for (const name of await readdir(join(out, 'runtime'))) bytes += (await readFile(join(out, 'runtime', name))).length;
console.log(JSON.stringify({ output: out, runtime_bytes: bytes, engine_bytes: Buffer.byteLength(bundle), ...manifest }));
