import { loadPyodide } from './runtime/pyodide.mjs';
import { installEngine, scanBytes } from './runtime.js';
import { evaluateCase, summarize } from './parity.js';

self.onmessage = async () => {
  try {
    const [files, cases] = await Promise.all(['engine-files.json', 'cases.json'].map(path => fetch(path).then(r => r.json())));
    const started = performance.now();
    const pyodide = await loadPyodide({ indexURL: new URL('./runtime/', import.meta.url).href,
      stdout: () => {}, stderr: () => {} });
    await pyodide.loadPackage('pyyaml');
    await installEngine(pyodide, files);
    const loaded = performance.now();
    // Observe that the corpus still executes after network access is disabled.
    self.fetch = () => { throw new Error('offline'); };
    const rows = [];
    for (const item of cases) {
      const bytes = Uint8Array.from(atob(item.archive), c => c.charCodeAt(0));
      rows.push(evaluateCase(item, scanBytes(pyodide, bytes.buffer)));
      if (rows.length % 25 === 0) self.postMessage({ type: 'progress', message: `${rows.length}/${cases.length}` });
    }
    const summary = summarize(rows);
    summary.load_ms = Math.round(loaded - started);
    summary.scan_ms = Math.round(performance.now() - loaded);
    summary.runtime = navigator.userAgent;
    self.postMessage({ summary, rows });
  } catch (e) {
    // This harness contains only synthetic reviewed fixtures, never customer input.
    self.postMessage({ error: String(e) });
  }
};
