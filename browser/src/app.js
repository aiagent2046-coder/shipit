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
  byId('continue-button').disabled = value;
  status.classList.toggle('busy', value);
  byId('scan-form').setAttribute('aria-busy', String(value));
}

function releaseWorker() {
  if (worker) worker.terminate();
  worker = null;
  clearTimeout(timeout);
  timeout = null;
}

function finish(keepWorker = false) {
  if (keepWorker) {
    clearTimeout(timeout);
    timeout = null;
  } else {
    releaseWorker();
    generation += 1;
    byId('continue-button').hidden = true;
  }
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
  finish();
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

byId('continue-button').addEventListener('click', () => {
  if (busy || !worker) return;
  error.hidden = true;
  setBusy(true);
  setStatus('Scanning the next portion of remaining files locally…');
  const current = generation;
  timeout = setTimeout(() => {
    if (current === generation) fail('This portion exceeded the two-minute limit. The previous report remains available.');
  }, SCAN_TIMEOUT_MS);
  worker.postMessage({ type: 'continue' });
});

byId('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = selectedArchive();
  if (busy || !file) return;
  releaseWorker();
  byId('continue-button').hidden = true;
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
          finish(data.can_continue === true);
          byId('continue-button').hidden = data.can_continue !== true;
          setStatus(data.can_continue
            ? 'This portion is complete. You can continue scanning remaining files.'
            : 'Local scan complete. Review the findings and coverage below.');
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

// Context changes presentation only; findings and exports retain every signal.
const findingContexts = {
  test_file: 'Test file', test_fixture: 'Test fixture or placeholder',
  doc_example: 'Documentation or example', comment: 'Comment',
  ci_service: 'CI service', configuration_template: 'Configuration template',
  placeholder_uri: 'Placeholder URI', docstring: 'Documentation string',
  deployment_inventory: 'Deployment inventory',
};

function findingContext(finding) {
  return text(finding.context) || text(finding.claim_evidence?.source_context?.kind);
}

function isContextualFinding(finding) {
  // A credible or severe signal deserves review even when found in a test.
  if (['high', 'critical'].includes(text(finding.severity).toLowerCase())) return false;
  if (typeof finding.confidence === 'number' && finding.confidence >= 0.8
      && findingContext(finding) !== 'deployment_inventory') return false;
  return Object.hasOwn(findingContexts, findingContext(finding));
}

function findingMetadata(finding) {
  const context = findingContext(finding);
  const contextLabel = findingContexts[context] || (context ? context.replaceAll('_', ' ') : 'Context not identified');
  const confidence = finding.confidence;
  const confidenceLabel = typeof confidence === 'number' && Number.isFinite(confidence)
    && confidence >= 0 && confidence <= 1 ? confidence.toFixed(2) : 'Not reported';
  return `${contextLabel} · Detector confidence: ${confidenceLabel} · Verification: ${text(finding.verification_status, 'Not reported').replaceAll('_', ' ')}`;
}

function renderFinding(finding) {
  const article = node('article', undefined, 'finding');
  const heading = node('div', undefined, 'finding-heading');
  const severity = text(finding.severity, 'unspecified').toLowerCase();
  const knownSeverity = ['critical', 'high', 'medium', 'warning', 'low', 'info'].includes(severity) ? severity : 'unknown';
  heading.append(node('span', severity, `severity severity-${knownSeverity}`), node('h4', text(finding.title, 'Static finding')));
  const location = text(finding.file, 'Project');
  const line = Number.isInteger(finding.line) && finding.line > 0 ? `:${finding.line}` : '';
  const rule = finding.rule_id ? ` · ${text(finding.rule_id)}` : '';
  article.append(heading, node('p', `${location}${line}${rule}`, 'finding-location'));
  article.append(node('p', findingMetadata(finding), 'finding-metadata'));
  if (finding.explanation) article.append(node('p', text(finding.explanation)));
  const advisory = finding.claim_evidence?.advisory_id || finding.claim_evidence?.cve_id;
  let advisoryHref = '';
  if (finding.rule_id === 'dependency-cve-match' && typeof advisory === 'string') {
    if (/^CVE-\d{4}-\d{4,19}$/.test(advisory)) {
      advisoryHref = `https://www.cve.org/CVERecord?id=${encodeURIComponent(advisory)}`;
    } else if (/^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$/.test(advisory)) {
      advisoryHref = `https://github.com/advisories/${encodeURIComponent(advisory)}`;
    }
  }
  if (advisoryHref) {
    const link = node('a', `Read ${advisory}`);
    link.href = advisoryHref;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    article.append(link);
  }
  if (finding.fix_hint) {
    const hint = node('p', undefined, 'fix-hint');
    hint.append(node('strong', 'Suggested next step: '), node('span', text(finding.fix_hint)));
    article.append(hint);
  }
  if (finding.masked) article.append(node('p', 'Sensitive values are masked in this finding.', 'masked-note'));
  return article;
}

function renderReport(report) {
  byId('engine-version').textContent = report.engine_version ? `Engine ${text(report.engine_version)}` : 'Local static scan';
  const gaps = Array.isArray(report.checks_not_run) ? [...report.checks_not_run] : [];
  const dependency = report.dependency_cve;
  byId('dependency-cve').hidden = !dependency;
  if (dependency) {
    const source = dependency.source || {};
    const identifiedSources = Object.entries(dependency.sources || {})
      .filter(([, value]) => value && typeof value === 'object');
    const sourceCommits = identifiedSources
      .map(([name, value]) => `${name}: ${text(value.commit, 'Unavailable')}`).join('; ');
    const sourceDates = identifiedSources
      .map(([name, value]) => `${name}: ${text(value.generated_at, 'Unavailable')}`).join('; ');
    renderDefinitions(byId('dependency-cve-details'), [
      ['Status', text(dependency.status, 'unavailable')],
      ['Source commits', sourceCommits || text(source.commit, 'Unavailable')],
      ['Snapshot dates', sourceDates || text(source.generated_at, 'Unavailable')],
      ['Resolved dependencies checked', `${text(dependency.dependencies_checked, 0)} / ${text(dependency.dependencies_found, 0)}`],
      ['Version comparisons unresolved', text(dependency.unresolved_ranges, 0)],
      ['Dependencies absent from this catalog', text(dependency.status_counts?.not_in_catalog, 0)],
      ['Unresolved manifests', Object.entries(dependency.incomplete_manifests || {}).map(([path, reason]) =>
        `${path}: ${reason === 'unsupported' && path.split('/').at(-1) === 'bun.lockb'
          ? 'Binary bun.lockb is unsupported; provide a text bun.lock' : reason}`).join('; ') || 'None reported'],
      ['Scope', 'A match identifies a package version listed by a CVE or reviewed GHSA. Runtime exploitability is not checked. Unlisted packages are not a clean bill of health.'],
    ]);
    if (dependency.status === 'partial' || dependency.status === 'unavailable') {
      gaps.push({ check: 'dependency_cve', reason: 'Dependency coverage is incomplete; inspect the snapshot scope and unresolved comparisons.' });
    }
    const snapshotTimes = identifiedSources
      .map(([, value]) => Date.parse(value.generated_at)).filter(Number.isFinite);
    if (!snapshotTimes.length && Number.isFinite(Date.parse(source.generated_at))) {
      snapshotTimes.push(Date.parse(source.generated_at));
    }
    const oldestSnapshot = snapshotTimes.length ? Math.min(...snapshotTimes) : NaN;
    if (dependency.status !== 'not_applicable' && Number.isFinite(oldestSnapshot)
        && Date.now() - oldestSnapshot > 7 * 86400000) {
      gaps.push({ check: 'dependency_cve', reason: 'An advisory snapshot source is older than seven days. Reload an updated scanner before relying on its advisory coverage.' });
    }
  }
  for (const [check, detail] of Object.entries(report.rule_coverage || {})) {
    if (!detail || !(detail.partial || detail.skipped_files > 0)) continue;
    const reasons = Object.entries(detail.skip_reasons || {}).filter(([, count]) => count > 0)
      .map(([reason, count]) => `${reason.replaceAll('_', ' ')}: ${count}`).join(', ');
    gaps.push({ check, reason: `${text(detail.analyzed_files, '?')} of ${text(detail.eligible_files, '?')} eligible files analyzed; ${reasons || 'coverage incomplete'}.` });
  }
  const httpCoverage = report.coverage?.http_success;
  if (typeof httpCoverage === 'string' && /Parser limits: (?!none(?:$|[.;]))\S/.test(httpCoverage)) {
    gaps.push({ check: 'http_success', reason: httpCoverage });
  }
  const gapList = byId('checks-not-run');
  gapList.replaceChildren();
  for (const gap of gaps) {
    const item = node('li');
    item.append(node('strong', text(gap?.check, 'Check not run')), node('span', ` — ${text(gap?.reason, 'No reason was provided.')}`));
    gapList.append(item);
  }
  byId('partial-coverage').hidden = gaps.length === 0;

  const findings = report.findings.filter(finding => finding && typeof finding === 'object');
  const contextual = findings.filter(isContextualFinding);
  const review = findings.filter(finding => !isContextualFinding(finding));
  byId('findings-summary').textContent = findings.length === 0
    ? 'No findings from the checks that ran.'
    : `${findings.length} total findings · ${review.length} for initial review · ${contextual.length} contextual or informational`;
  const findingList = byId('findings');
  findingList.replaceChildren();
  const reviewSection = node('section', undefined, 'finding-group');
  reviewSection.setAttribute('aria-labelledby', 'initial-review-title');
  const reviewTitle = node('h3', `Initial review (${review.length})`);
  reviewTitle.id = 'initial-review-title';
  reviewSection.append(reviewTitle);
  if (review.length) {
    reviewSection.append(node('p', 'Review these signals first. Priority does not establish that a vulnerability is present.', 'hint'));
    reviewSection.append(...review.map(renderFinding));
  } else {
    reviewSection.append(node('p', contextual.length
      ? 'All reported signals are grouped below. This does not establish that the project is safe.'
      : 'Review the coverage and limitations below; no findings does not establish safety.', 'hint'));
  }
  findingList.append(reviewSection);
  if (contextual.length) {
    const details = node('details', undefined, 'finding-group contextual-findings');
    details.append(node('summary', `Tests, examples and informational signals (${contextual.length})`));
    details.append(node('p', 'Grouped by reported context, not dismissed as false positives. Real credentials can also appear in tests. Every finding remains in JSON and SARIF exports.', 'hint'));
    details.append(...contextual.map(renderFinding));
    findingList.append(details);
  }

  const checks = Array.isArray(report.checks_run) ? report.checks_run : [];
  byId('checks-run').replaceChildren(...(checks.length ? checks.map((check) => node('li', text(check))) : [node('li', 'No completed checks reported.')]));
  const coverage = report.coverage && typeof report.coverage === 'object' ? report.coverage : {};
  renderDefinitions(byId('coverage-descriptions'), Object.entries(coverage));
  const ruleCoverage = report.rule_coverage && typeof report.rule_coverage === 'object' ? report.rule_coverage : {};
  renderRuleCoverage(ruleCoverage);
  renderSecurityAgent(report.security_agent);
  const limits = Array.isArray(report.limitations) ? report.limitations : [];
  const baseline = 'No runtime tests or LLM analysis. Dependency results, when present, are limited to the recorded advisory snapshot. Absence of findings does not establish safety.';
  byId('limitations').replaceChildren(node('li', baseline), ...limits.map((limit) => node('li', text(limit))));
}

function renderSecurityAgent(agent) {
  const details = byId('security-agent-details');
  const container = byId('security-agent');
  container.replaceChildren();
  details.hidden = !agent || typeof agent !== 'object' || Array.isArray(agent);
  details.open = false;
  if (details.hidden) return;

  const observations = Array.isArray(agent.observations)
    ? agent.observations.filter(observation => observation && typeof observation === 'object') : [];
  const reviewStatus = ['completed', 'partial', 'unavailable'].includes(agent.status) ? agent.status : 'unavailable';
  const label = value => text(value, 'Not reported').replaceAll('_', ' ');
  const count = value => Number.isInteger(value) && value >= 0 ? value : 'Not reported';
  byId('security-agent-summary').textContent = `Pattern review · ${reviewStatus} · observations: ${observations.length}`;
  container.append(node('p', 'Static review with no LLM. Completion describes the review scope; runtime exploitability and repairs remain unverified.', 'hint'));
  const summary = node('div');
  const catalog = agent.catalog || {};
  const budget = agent.budget || {};
  const plan = Array.isArray(agent.plan) ? agent.plan.filter(step => step && typeof step === 'object') : [];
  renderDefinitions(summary, [
    ['Pattern catalog', `${text(catalog.version, 'Not reported')} · patterns: ${count(catalog.cards)}`],
    ['Catalog SHA-256', text(catalog.sha256, 'Not reported')],
    ['Candidate review', `${count(budget.processed)} processed / ${count(budget.candidates_found)} found · ${count(budget.candidates_omitted)} omitted · limit ${count(budget.max_candidates)}`],
    ['Pattern checks', plan.map(step => `${text(step.title, text(step.pattern_id))}: ${label(step.status)}`).join('; ') || 'Not reported'],
    ['Stop reason', label(agent.stop_reason)],
  ]);
  container.append(summary);
  for (const observation of observations) {
    const section = node('section');
    section.append(node('h4', `${text(observation.title, 'Static observation')} · ${label(observation.state)}`));
    const sql = observation.evidence?.sql_observation;
    const location = text(observation.file, 'Project');
    const line = Number.isInteger(observation.line) && observation.line > 0 ? `:${observation.line}` : '';
    section.append(node('p', `${location}${line}`, 'finding-location'));
    if (sql && typeof sql === 'object') {
      section.append(node('p', `Possible local SQL flow: assembly line ${count(sql.assembly_line)} → ${text(sql.sink_method, 'query call')} line ${count(sql.sink_line)}. Driver behavior and external input control are not checked.`, 'hint'));
    }
    const missing = Array.isArray(observation.missing_evidence) ? observation.missing_evidence : [];
    const evidence = node('div');
    renderDefinitions(evidence, [
      ['Candidate weakness classes', Array.isArray(observation.weaknesses)
        ? observation.weaknesses.map(value => text(value)).join(', ') || 'Not reported' : 'Not reported'],
      ['Missing evidence', missing.length ? missing.map(label).join('; ') : 'Not reported'],
      ['Next step', sql
        ? 'Manual review: trace the input origin and check the database driver’s parameter binding at the query call.'
        : 'Manual review: inspect the reported source location and gather the missing evidence.'],
      ['Repair guidance', observation.recipe?.status === 'manual_guidance'
        ? `${text(observation.recipe.id, 'Manual guidance')} · review prerequisites before choosing a repair; no patch is applied.`
        : 'No repair guidance available; no patch is applied.'],
    ]);
    section.append(evidence);
    container.append(section);
  }
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
