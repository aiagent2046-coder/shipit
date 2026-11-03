// Shared by the worker and the reproducible WASM parity harness.
export async function loadNativeParsers(pyodide) {
  const failures = [];
  for (const name of ['tree-sitter', 'tree-sitter-typescript', 'tree-sitter-javascript', 'pglast']) {
    try {
      await pyodide.loadPackage(name);
      // loadPackage can report download errors through its callback rather
      // than reject. Confirm installation before recording a successful load.
      if (!pyodide.loadedPackages[name]) throw new Error('Package not installed');
    } catch {
      // A missing/corrupt native asset must not erase the pure-Python results.
      // Imports in the shared engine decide which dependent checks cannot run.
      failures.push({ package: name, reason: 'native_package_load_failed' });
    }
  }
  return failures;
}

export async function installEngine(pyodide, files) {
  const dataLimits = new Map([
    ['app/data/kev-catalog.json', 8 * 1024 * 1024],
    ['app/data/kev-catalog.json.sha256', 1024],
  ]);
  // Keep data names exact: a JSON fixture must never widen the Python import
  // boundary or let arbitrary bundle paths enter the virtual filesystem.
  for (const [path, source] of Object.entries(files)) {
    if (typeof source !== 'string' || (!/^app\/[a-zA-Z0-9_/]+\.py$/.test(path) && !dataLimits.has(path))) {
      throw new Error('Invalid engine bundle');
    }
    if (dataLimits.has(path) && new TextEncoder().encode(source).byteLength > dataLimits.get(path)) {
      throw new Error('Oversized engine data');
    }
  }
  for (const [path, source] of Object.entries(files)) {
    const target = `/engine/${path}`;
    pyodide.FS.mkdirTree(target.slice(0, target.lastIndexOf('/')));
    pyodide.FS.writeFile(target, source);
  }
  await pyodide.runPythonAsync("import sys\nsys.path.insert(0, '/engine')\nfrom app.scan.browser import scan_archive");
  pyodide.runPython('_dependency_catalog = None');
}

export async function installCatalog(pyodide, bytes, expectedHash) {
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength > 32 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(expectedHash || '')) throw new Error('Invalid CVE snapshot');
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
    byte => byte.toString(16).padStart(2, '0')).join('');
  if (hash !== expectedHash) throw new Error('CVE snapshot integrity mismatch');
  pyodide.globals.set('_catalog_json', new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  try {
    pyodide.runPython('import json\n_dependency_catalog = json.loads(_catalog_json)');
  } finally {
    pyodide.globals.delete('_catalog_json');
  }
}

export function scanBytes(pyodide, archive, threatAsOf = null) {
  // Only bytes cross this boundary, never interpolated Python source. Uploaded
  // files are read from an in-memory ZIP; they never enter Python's import path.
  pyodide.globals.set('_archive_bytes', new Uint8Array(archive));
  pyodide.globals.set('_threat_as_of', threatAsOf);
  try {
    return JSON.parse(pyodide.runPython(`
import json
from app.ingest.validators import ArchiveValidationError
def _browser_scan():
    try:
        return json.dumps(scan_archive(bytes(_archive_bytes.to_py()), _dependency_catalog, threat_as_of=_threat_as_of))
    except ArchiveValidationError as exc:
        return json.dumps({"error": "invalid_archive", "reason": exc.reason})
_browser_scan()
`));
  } finally {
    pyodide.globals.delete('_archive_bytes');
    pyodide.globals.delete('_threat_as_of');
  }
}

export function startSession(pyodide, archive, threatAsOf = null) {
  pyodide.globals.set('_archive_bytes', new Uint8Array(archive));
  pyodide.globals.set('_threat_as_of', threatAsOf);
  try {
    return JSON.parse(pyodide.runPython(`
import json
from app.scan.browser import ScanSession
from app.ingest.validators import ArchiveValidationError
def _start_session():
    global _scan_session
    _scan_session = None
    try:
        _scan_session = ScanSession(bytes(_archive_bytes.to_py()), _dependency_catalog, threat_as_of=_threat_as_of)
        return json.dumps(_scan_session.result())
    except ArchiveValidationError as exc:
        return json.dumps({"error": "invalid_archive", "reason": exc.reason})
_start_session()
`));
  } finally {
    pyodide.globals.delete('_archive_bytes');
    pyodide.globals.delete('_threat_as_of');
  }
}

export function continueSession(pyodide) {
  return JSON.parse(pyodide.runPython('json.dumps(_scan_session.continue_scan())'));
}
