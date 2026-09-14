import { loadPyodide } from './runtime/pyodide.mjs';
import { installEngine, installCatalog, loadNativeParsers, scanBytes } from './runtime.js';
import { assertParserParity, evaluateCase, summarize } from './parity.js';

self.onmessage = async () => {
  try {
    const [files, cases, expectedProbes] = await Promise.all(
      ['engine-files.json', 'cases.json', 'parser-probes.json'].map(path => fetch(path).then(r => r.json())));
    const probeSource = await fetch('parser-probes.py').then(r => r.text());
    const started = performance.now();
    const pyodide = await loadPyodide({ indexURL: new URL('./runtime/', import.meta.url).href,
      stdout: () => {}, stderr: () => {} });
    await pyodide.loadPackage('pyyaml');
    const nativeFailures = await loadNativeParsers(pyodide);
    if (nativeFailures.length) throw new Error(JSON.stringify(nativeFailures));
    await installEngine(pyodide, files);
    const build = await fetch('build.json').then(r => r.json());
    const catalog = await fetch('cve-catalog.json').then(r => r.arrayBuffer());
    await installCatalog(pyodide, catalog, build.cve_catalog_sha256);
    const loaded = performance.now();
    const actualProbes = JSON.parse(pyodide.runPython(probeSource + '\nimport json\njson.dumps(probe_parsers())'));
    assertParserParity(expectedProbes, actualProbes);
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
    summary.parser_probes = 'passed';
    self.postMessage({ summary, rows });
  } catch (e) {
    // This harness contains only synthetic reviewed fixtures, never customer input.
    self.postMessage({ error: String(e) });
  }
};
