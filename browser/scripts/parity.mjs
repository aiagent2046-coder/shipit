// Runs the exact shipped Python bundle in WASM. Browser-specific verification
// uses the same assertions in tests/harness-worker.js through real Chromium.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { installEngine, loadNativeParsers, scanBytes, startSession, continueSession } from '../src/runtime.js';
import { assertParserParity, evaluateCase, summarize } from '../tests/parity.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pyodide = await loadPyodide({ indexURL: resolve(root, 'dist/runtime'),
  stdout: () => {}, stderr: () => {} });
await pyodide.loadPackage('pyyaml');
const nativeFailures = await loadNativeParsers(pyodide);
if (nativeFailures.length) throw new Error(JSON.stringify(nativeFailures));
await installEngine(pyodide, JSON.parse(await readFile(resolve(root, 'dist/engine-files.json'))));
const cases = JSON.parse(await readFile(resolve(root, 'test-dist/cases.json')));
const probeSource = await readFile(resolve(root, 'test-dist/parser-probes.py'), 'utf8');
const expectedProbes = JSON.parse(await readFile(resolve(root, 'test-dist/parser-probes.json')));
const actualProbes = JSON.parse(pyodide.runPython(probeSource + '\nimport json\njson.dumps(probe_parsers())'));
assertParserParity(expectedProbes, actualProbes);
const start = performance.now();
const rows = cases.map(item => {
  const bytes = Uint8Array.from(Buffer.from(item.archive, 'base64'));
  return evaluateCase(item, scanBytes(pyodide, bytes.buffer));
});
const continuation = JSON.parse(await readFile(resolve(root, 'test-dist/continuation.json')));
const archive = Uint8Array.from(Buffer.from(continuation.archive, 'base64'));
assert.deepEqual(startSession(pyodide, archive.buffer), continuation.initial);
for (const expected of continuation.continuations) {
  assert.deepEqual(continueSession(pyodide), expected);
}
const summary = summarize(rows);
summary.continuation = 'passed';
summary.elapsed_ms = Math.round(performance.now() - start);
summary.runtime = 'Pyodide in Node (browser run recorded separately)';
summary.parser_probes = 'passed';
await mkdir(resolve(root, 'measurements'), { recursive: true });
await writeFile(resolve(root, 'measurements/wasm-parity.json'), JSON.stringify({ summary, rows }, null, 2));
console.log(JSON.stringify(summary, null, 2));
if (summary.unexpected_failures > 0) process.exitCode = 1;
