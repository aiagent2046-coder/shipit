// Runs the exact shipped Python bundle in WASM. Browser-specific verification
// uses the same assertions in tests/harness-worker.js through real Chromium.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { installEngine, installCatalog, loadNativeParsers, scanBytes, startSession, continueSession } from '../src/runtime.js';
import { assertParserParity, evaluateCase, summarize } from '../tests/parity.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pyodide = await loadPyodide({ indexURL: resolve(root, 'dist/runtime'),
  stdout: () => {}, stderr: () => {} });
await pyodide.loadPackage('pyyaml');
const nativeFailures = await loadNativeParsers(pyodide);
if (nativeFailures.length) throw new Error(JSON.stringify(nativeFailures));
await installEngine(pyodide, JSON.parse(await readFile(resolve(root, 'dist/engine-files.json'))));
const catalog = new Uint8Array(await readFile(resolve(root, 'dist/cve-catalog.json')));
const build = JSON.parse(await readFile(resolve(root, 'dist/build.json')));
await installCatalog(pyodide, catalog.buffer, build.cve_catalog_sha256);
await assert.rejects(installCatalog(pyodide, catalog.buffer, '0'.repeat(64)), /integrity/);
const cases = JSON.parse(await readFile(resolve(root, 'test-dist/cases.json')));
const probeSource = await readFile(resolve(root, 'test-dist/parser-probes.py'), 'utf8');
const expectedProbes = JSON.parse(await readFile(resolve(root, 'test-dist/parser-probes.json')));
const actualProbes = JSON.parse(pyodide.runPython(probeSource + '\nimport json\njson.dumps(probe_parsers())'));
assertParserParity(expectedProbes, actualProbes);
const start = performance.now();
const rows = cases.map(item => {
  const bytes = Uint8Array.from(Buffer.from(item.archive, 'base64'));
  return evaluateCase(item, scanBytes(pyodide, bytes.buffer, item.native.report.project_checks.threat_context.as_of));
});
// Corrupt/missing or changed KEV knowledge may change threat context only.
// Exercise the shipped filesystem loader, not a mocked catalog callback.
const kevCase = cases.find(item => item.id === 'threat-context/pillow-affected');
assert.ok(kevCase, 'Need a real CVE-to-KEV alias regression');
const kevArchive = Uint8Array.from(Buffer.from(kevCase.archive, 'base64')).buffer;
const kevDate = kevCase.native.report.project_checks.threat_context.as_of;
const kevPath = '/engine/app/data/kev-catalog.json';
const kevReceiptPath = kevPath + '.sha256';
const originalKev = pyodide.FS.readFile(kevPath, { encoding: 'utf8' });
const originalKevReceipt = pyodide.FS.readFile(kevReceiptPath, { encoding: 'utf8' });
for (const problem of ['corrupt', 'missing']) {
  if (problem === 'corrupt') pyodide.FS.writeFile(kevPath, '{}');
  else pyodide.FS.unlink(kevPath);
  const degraded = scanBytes(pyodide, kevArchive, kevDate);
  assert.equal(degraded.report.project_checks.threat_context.status, 'unavailable');
  assert.deepEqual(degraded.report.findings, kevCase.native.report.findings);
  assert.deepEqual(degraded.report.project_checks.source, kevCase.native.report.project_checks.source);
  assert.deepEqual(degraded.report.project_checks.binary_static, kevCase.native.report.project_checks.binary_static);
  assert.equal(degraded.sarif.runs[0].results.length, kevCase.native.sarif.runs[0].results.length);
  pyodide.FS.writeFile(kevPath, originalKev);
}
pyodide.runPython(`
from pathlib import Path
import hashlib, json
from app.scan.kev_catalog import encode_catalog
_kev_path = Path('/engine/app/data/kev-catalog.json')
_kev_data = json.loads(_kev_path.read_text())
del _kev_data['entries']['CVE-2023-4863']
_kev_bytes = encode_catalog(_kev_data)
_kev_path.write_bytes(_kev_bytes)
_kev_path.with_suffix('.json.sha256').write_text(hashlib.sha256(_kev_bytes).hexdigest() + '\\n')
`);
const revisedKev = scanBytes(pyodide, kevArchive, kevDate);
assert.deepEqual(revisedKev.report.findings, kevCase.native.report.findings);
assert.ok(!revisedKev.report.project_checks.threat_context.matches.some(row => row.cve_id === 'CVE-2023-4863'));
assert.notEqual(revisedKev.report.project_checks.threat_context.fingerprint,
  kevCase.native.report.project_checks.threat_context.fingerprint);
pyodide.FS.writeFile(kevPath, originalKev);
pyodide.FS.writeFile(kevReceiptPath, originalKevReceipt);
assert.deepEqual(scanBytes(pyodide, kevArchive, kevDate), kevCase.native);
const continuation = JSON.parse(await readFile(resolve(root, 'test-dist/continuation.json')));
const archive = Uint8Array.from(Buffer.from(continuation.archive, 'base64'));
assert.deepEqual(startSession(pyodide, archive.buffer, continuation.initial.report.project_checks.threat_context.as_of), continuation.initial);
for (const expected of continuation.continuations) {
  assert.deepEqual(continueSession(pyodide), expected);
}
const summary = summarize(rows);
summary.continuation = 'passed';
summary.kev_snapshot_integrity = 'passed';
summary.elapsed_ms = Math.round(performance.now() - start);
summary.runtime = 'Pyodide in Node (browser run recorded separately)';
summary.parser_probes = 'passed';
await mkdir(resolve(root, 'measurements'), { recursive: true });
await writeFile(resolve(root, 'measurements/wasm-parity.json'), JSON.stringify({ summary, rows }, null, 2));
console.log(JSON.stringify(summary, null, 2));
if (!summary.full_parity) process.exitCode = 1;
