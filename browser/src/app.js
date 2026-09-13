const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;
const SCAN_TIMEOUT_MS = 120_000;
const byId = (id) => document.getElementById(id);
const input = byId('archive');
const scanButton = byId('scan-button');
const cancelButton = byId('cancel-button');
const status = byId('scan-status');
const error = byId('scan-error');
const results = byId('results');
let worker = null;
let timeout = null;
let generation = 0;
let busy = false;
let exportedReport = null;
let exportedSarif = null;

const errorMessages = {
  invalid_archive: 'This ZIP is invalid or exceeds the supported archive limits. Re-create an archive containing project source files.',
  archive_too_large: 'This ZIP exceeds the 50 MiB limit. Choose a smaller source archive.',
  zip_too_large: 'This ZIP exceeds the 50 MiB limit. Choose a smaller source archive.',
  invalid_zip: 'This file could not be read as a supported ZIP. Choose another source archive.',
  unsafe_archive: 'The ZIP contains unsupported or unsafe entries. Re-create a ZIP containing only project source files.',
  archive_limit_exceeded: 'The ZIP exceeds the extraction limits. Reduce the number or size of source files and try again.',
  runtime_load_failed: 'The scanner runtime could not load. Check your connection and try again.',
  runtime_unavailable: 'The scanner runtime could not load. Check your connection and try again.',
  scan_failed: 'The local scan could not finish. Try again with a smaller source ZIP.',
};

function node(tag, content, className) {
  const element = document.createElement(tag);
  if (content !== undefined) element.textContent = String(content);
  if (className) element.className = className;
  return element;
}

function text(value, fallback = '') {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : fallback;
}

function setStatus(message) {
  status.textContent = message;
}

function selectedArchive() {
  const file = input.files?.[0];
  return file && /\.zip$/i.test(file.name) && file.size <= MAX_ARCHIVE_BYTES && file.size > 0 ? file : null;
}

function setBusy(value) {
  busy = value;
  input.disabled = value;
  scanButton.disabled = value || !selectedArchive();
  cancelButton.hidden = !value;
  status.classList.toggle('busy', value);
  byId('scan-form').setAttribute('aria-busy', String(value));
}

function releaseWorker() {
  if (worker) worker.terminate();
  worker = null;
  clearTimeout(timeout);
  timeout = null;
}

function finish() {
  releaseWorker();
  generation += 1;
  setBusy(false);
}

function fail(message) {
  finish();
  error.textContent = message;
  error.hidden = false;
  setStatus('Scan could not complete.');
  scanButton.focus();
}

function clearResults() {
  results.hidden = true;
  exportedReport = null;
  exportedSarif = null;
}

input.addEventListener('change', () => {
  clearResults();
  error.hidden = true;
  const file = input.files?.[0];
  byId('selected-file').textContent = file ? `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MiB` : 'No project selected.';
  scanButton.disabled = !selectedArchive();
  if (file && !selectedArchive()) {
    error.textContent = file.size > MAX_ARCHIVE_BYTES
      ? errorMessages.archive_too_large
      : 'Choose a nonempty .zip file to scan.';
    error.hidden = false;
    setStatus('Choose a supported source ZIP.');
  } else {
    setStatus(file ? 'Ready to scan on your device.' : 'Choose a ZIP to begin.');
  }
});

cancelButton.addEventListener('click', () => {
  finish();
  setStatus('Scan cancelled. You can start another scan.');
  scanButton.focus();
});

byId('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = selectedArchive();
  if (busy || !file) return;
  clearResults();
  error.hidden = true;
  setBusy(true);
  setStatus('Preparing your ZIP locally…');
  const current = ++generation;
  timeout = setTimeout(() => {
    if (current === generation) fail('The scan exceeded the two-minute limit and was stopped. Try a smaller source ZIP.');
  }, SCAN_TIMEOUT_MS);
  try {
    worker = new Worker('./worker.js', { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (current !== generation || !data || typeof data !== 'object') return;
      if (data.type === 'progress') {
        const stages = {
          loading_runtime: 'Loading the scanner runtime… The initial download needs an internet connection.',
          extracting: 'Opening and checking ZIP entries locally…',
          scanning: 'Running supported static checks on your device…',
          exporting: 'Preparing your local report…',
        };
        setStatus(Object.hasOwn(stages, data.stage) ? stages[data.stage] : 'Running the local scan…');
      } else if (data.type === 'result') {
        if (!data.report || typeof data.report !== 'object' || !Array.isArray(data.report.findings) || !data.sarif || typeof data.sarif !== 'object') {
          fail('The scanner returned an incomplete report. Try scanning again.');
          return;
        }
        try {
          renderReport(data.report);
          exportedReport = data.report;
          exportedSarif = data.sarif;
          finish();
          setStatus('Local scan complete. Review the findings and coverage below.');
          results.hidden = false;
          byId('results-title').focus();
        } catch {
          clearResults();
          fail('The report could not be displayed. Try scanning again.');
        }
      } else if (data.type === 'error') {
        fail(Object.hasOwn(errorMessages, data.code) ? errorMessages[data.code] : errorMessages.scan_failed);
      }
    };
    worker.onerror = (event) => {
      event.preventDefault();
      if (current === generation) fail('The local scanner stopped unexpectedly. Try again with a smaller source ZIP.');
    };
    worker.onmessageerror = () => {
      if (current === generation) fail('The local scanner could not return a report. Try scanning again.');
    };
    const archive = await file.arrayBuffer();
    if (current !== generation) return;
    setStatus('Loading the scanner runtime… The initial download needs an internet connection.');
    worker.postMessage({ type: 'scan', archive }, [archive]);
  } catch {
    if (current === generation) fail('The local scanner could not start or read this ZIP. Try again with a supported source archive.');
  }
});

function readable(value) {
  if (value === null || value === undefined) return 'Not reported';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function renderDefinitions(container, entries) {
  container.replaceChildren();
  const list = node('dl');
  for (const [key, value] of entries) {
    const row = node('div', undefined, 'coverage-definition');
    row.append(node('dt', key), node('dd', readable(value)));
    list.append(row);
  }
  container.append(list);
}

function renderReport(report) {
  byId('engine-version').textContent = report.engine_version ? `Engine ${text(report.engine_version)}` : 'Local static scan';
  const gaps = Array.isArray(report.checks_not_run) ? report.checks_not_run : [];
  const gapList = byId('checks-not-run');
  gapList.replaceChildren();
  for (const gap of gaps) {
    const item = node('li');
    item.append(node('strong', text(gap?.check, 'Check not run')), node('span', ` — ${text(gap?.reason, 'No reason was provided.')}`));
    gapList.append(item);
  }
  byId('partial-coverage').hidden = gaps.length === 0;

  const findings = report.findings;
  byId('findings-summary').textContent = findings.length === 0
    ? 'No findings from the checks that ran.'
    : `${findings.length} ${findings.length === 1 ? 'finding' : 'findings'} to review`;
  const findingList = byId('findings');
  findingList.replaceChildren();
  for (const finding of findings) {
    if (!finding || typeof finding !== 'object') continue;
    const article = node('article', undefined, 'finding');
    const heading = node('div', undefined, 'finding-heading');
    const severity = text(finding.severity, 'unspecified').toLowerCase();
    const knownSeverity = ['critical', 'high', 'medium', 'warning', 'low', 'info'].includes(severity) ? severity : 'unknown';
    heading.append(node('span', severity, `severity severity-${knownSeverity}`), node('h3', text(finding.title, 'Static finding')));
    const location = text(finding.file, 'Project');
    const line = Number.isInteger(finding.line) && finding.line > 0 ? `:${finding.line}` : '';
    const rule = finding.rule_id ? ` · ${text(finding.rule_id)}` : '';
    article.append(heading, node('p', `${location}${line}${rule}`, 'finding-location'));
    if (finding.explanation) article.append(node('p', text(finding.explanation)));
    if (finding.fix_hint) {
      const hint = node('p', undefined, 'fix-hint');
      hint.append(node('strong', 'Suggested next step: '), node('span', text(finding.fix_hint)));
      article.append(hint);
    }
    if (finding.masked) article.append(node('p', 'Sensitive values are masked in this finding.', 'masked-note'));
    findingList.append(article);
  }

  const checks = Array.isArray(report.checks_run) ? report.checks_run : [];
  byId('checks-run').replaceChildren(...(checks.length ? checks.map((check) => node('li', text(check))) : [node('li', 'No completed checks reported.')]));
  const coverage = report.coverage && typeof report.coverage === 'object' ? report.coverage : {};
  renderDefinitions(byId('coverage-descriptions'), Object.entries(coverage));
  const ruleCoverage = report.rule_coverage && typeof report.rule_coverage === 'object' ? report.rule_coverage : {};
  renderRuleCoverage(ruleCoverage);
  const limits = Array.isArray(report.limitations) ? report.limitations : [];
  const baseline = 'No runtime tests, dependency advisory scan, or LLM analysis. Absence of findings does not establish safety.';
  byId('limitations').replaceChildren(node('li', baseline), ...limits.map((limit) => node('li', text(limit))));
}

function renderRuleCoverage(coverage) {
  const container = byId('rule-coverage');
  container.replaceChildren();
  const entries = Object.entries(coverage);
  byId('rule-coverage-details').hidden = entries.length === 0;
  // Keep file counts scoped to each check: one file can be counted by multiple checks.
  byId('rule-coverage-details').open = entries.length > 0;
  for (const [check, detail] of entries) {
    const section = node('section');
    section.append(node('h4', check));
    const content = node('div');
    const fields = detail && typeof detail === 'object' && !Array.isArray(detail) ? Object.entries(detail) : [['Coverage', detail]];
    const countNames = { eligible_files: 'Eligible files', analyzed_files: 'Analyzed files', skipped_files: 'Skipped files' };
    const counts = node('dl', undefined, 'file-counts');
    for (const [key, value] of fields) {
      if (Object.hasOwn(countNames, key) && Number.isInteger(value) && value >= 0) {
        const item = node('div');
        item.append(node('dt', countNames[key]), node('dd', value));
        counts.append(item);
      }
    }
    if (counts.childElementCount) section.append(counts);
    const remaining = fields.filter(([key, value]) => !(Object.hasOwn(countNames, key) && Number.isInteger(value) && value >= 0));
    renderDefinitions(content, remaining.map(([key, value]) => [key.replaceAll('_', ' '), value]));
    section.append(content);
    container.append(section);
  }
}

function download(data, filename) {
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = node('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

byId('export-json').addEventListener('click', () => download(exportedReport, 'drydock-local-report.json'));
byId('export-sarif').addEventListener('click', () => download(exportedSarif, 'drydock-local-report.sarif'));
window.addEventListener('pagehide', releaseWorker);
