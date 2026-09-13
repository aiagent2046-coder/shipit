// Shared by the worker and the reproducible WASM parity harness.
export async function installEngine(pyodide, files) {
  for (const [path, source] of Object.entries(files)) {
    if (!/^app\/[a-zA-Z0-9_/]+\.py$/.test(path)) throw new Error('Invalid engine bundle');
    const target = `/engine/${path}`;
    pyodide.FS.mkdirTree(target.slice(0, target.lastIndexOf('/')));
    pyodide.FS.writeFile(target, source);
  }
  await pyodide.runPythonAsync("import sys\nsys.path.insert(0, '/engine')\nfrom app.scan.browser import scan_archive");
}

export function scanBytes(pyodide, archive) {
  // Only bytes cross this boundary, never interpolated Python source. Uploaded
  // files are read from an in-memory ZIP; they never enter Python's import path.
  pyodide.globals.set('_archive_bytes', new Uint8Array(archive));
  try {
    return JSON.parse(pyodide.runPython(`
import json
from app.ingest.validators import ArchiveValidationError
def _browser_scan():
    try:
        return json.dumps(scan_archive(bytes(_archive_bytes.to_py())))
    except ArchiveValidationError as exc:
        return json.dumps({"error": "invalid_archive", "reason": exc.reason})
_browser_scan()
`));
  } finally {
    pyodide.globals.delete('_archive_bytes');
  }
}
