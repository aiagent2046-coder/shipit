import { loadPyodide } from './runtime/pyodide.mjs';
import { installEngine, loadNativeParsers, startSession, continueSession } from './runtime.js';

let started = false;
let runtime = null;
let runtimeMetadata = null;
let canContinue = false;
self.onmessage = async ({ data }) => {
  if (data?.type === 'continue' && runtime && canContinue) {
    canContinue = false;
    try {
      self.postMessage({ type: 'progress', stage: 'scanning' });
      const result = continueSession(runtime);
      result.report.runtime = runtimeMetadata;
      canContinue = result.can_continue;
      self.postMessage({ type: 'result', ...result });
    } catch {
      self.postMessage({ type: 'error', code: 'scan_failed' });
    }
    return;
  }
  if (started || data?.type !== 'scan') return;
  started = true;
  if (!(data.archive instanceof ArrayBuffer) || data.archive.byteLength > 50 * 1024 * 1024) {
    self.postMessage({ type: 'error', code: 'invalid_archive' });
    return;
  }
  try {
    self.postMessage({ type: 'progress', stage: 'loading_runtime' });
    const [files, build, pyodide] = await Promise.all([
      fetch(new URL('./engine-files.json', import.meta.url)).then(r => { if (!r.ok) throw new Error(); return r.json(); }),
      fetch(new URL('./build.json', import.meta.url)).then(r => { if (!r.ok) throw new Error(); return r.json(); }),
      loadPyodide({ indexURL: new URL('./runtime/', import.meta.url).href,
        stdout: () => {}, stderr: () => {} }),
    ]);
    await pyodide.loadPackage('pyyaml');
    const nativeFailures = await loadNativeParsers(pyodide);
    await installEngine(pyodide, files);
    // All assets have loaded. Close network APIs before any customer bytes
    // enter Python. CSP adds an independent same-origin boundary in hosting.
    const offline = () => { throw new Error('Network disabled during local scan'); };
    self.fetch = offline;
    self.XMLHttpRequest = class { constructor() { offline(); } };
    self.WebSocket = class { constructor() { offline(); } };
    self.postMessage({ type: 'progress', stage: 'scanning' });
    const result = startSession(pyodide, data.archive);
    if (result.error) {
      self.postMessage({ type: 'error', code: result.error });
      return;
    }
    runtime = pyodide;
    runtimeMetadata = { ...build, native_load_failures: nativeFailures };
    canContinue = result.can_continue;
    result.report.runtime = runtimeMetadata;
    self.postMessage({ type: 'result', ...result });
  } catch {
    // Parser exceptions may contain source or secrets. Only stable codes cross
    // into UI/logs; per-check failures are already normalized by the engine.
    self.postMessage({ type: 'error', code: 'scan_failed' });
  }
};
