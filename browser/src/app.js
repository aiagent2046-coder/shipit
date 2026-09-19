import { sha256 } from './vendor/noble/sha2.js';

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

// Keep this bounded contract in sync with app/scan/evidence_record.py and
// web/src/lib/securityAgent.ts. Source facts do not establish runtime safety.
function normalizeAcquisition(value, trace) {
    const obj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    const integer = (v, min = 0, max = 2 ** 31 - 1) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
    const keys = (v, required, optional = []) => obj(v) && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
    const span = (v) => Array.isArray(v) && v.length === 4
        && v.every(n => integer(n)) && v[0] > 0 && (v[2] > v[0] || v[2] === v[0] && v[3] > v[1]);
    const identifier = (v) => typeof v === "string" && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(v);
    // Python uses Unicode identifier rules and counts code points, not UTF-16
    // units. Join controls are not Python identifiers; require absolute end too.
    const parameter = (v) => typeof v === "string" && v.length <= 256
        && [...v].length <= 128 && /^[_\p{XID_Start}]\p{XID_Continue}*(?![\s\S])/u.test(v)
        && !/[\u200c\u200d]/u.test(v);
    const choice = (v, options) => typeof v === "string" && options.includes(v);
    const sha = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
    const deserialization = normalizeDeserializationObservation(trace) !== null;
    const actions = deserialization ? ["locate_source", "trace_request_input"]
        : ["locate_source", "trace_request_input", "inspect_sql_slots", "collect_value_constraints"];
    const methods = { request_input_source: "fastapi_ast_binding",
        local_input_flow: "python_ast_straight_line", sql_value_position: "postgresql_ast_slot_context",
        value_constraints: "python_ast_constraints" };
    const fields = { request_input_source: "sources", local_input_flow: "locations",
        sql_value_position: "slots", value_constraints: "constraints" };
    const produces = { locate_source: [], trace_request_input: ["request_input_source", "local_input_flow"],
        inspect_sql_slots: ["sql_value_position"], collect_value_constraints: ["value_constraints"] };
    const stops = ["source_goal_reached", "no_further_action", "source_unavailable", "source_changed", "source_parse_error",
        "source_limit", "ambiguous_sink", "sink_not_found", "budget_exhausted", "collector_error"];
    const reasons = ["source_snapshot_matched", "source_unavailable", "source_changed", "source_limit", "source_parse_error",
        "sink_not_found", "ambiguous_sink", "request_flow_established", "request_flow_not_established",
        "sql_value_positions_established", "sql_slots_not_established", "value_constraints_recorded",
        "value_constraints_unknown", "collector_failed", "work_budget_exhausted", "step_budget_exhausted"];
    if (!obj(trace) || !integer(trace.sink_line, 1)
        || !keys(value, ["version", "status", "stop_reason", "source", "facts", "attempts", "budget"])
        || value.version !== (deserialization ? 2 : 1) || !choice(value.status, ["completed", "partial", "unsupported"])
        || !choice(value.stop_reason, stops))
        return null;
    const driver = trace.driver_provenance;
    const validDriver = trace.driver_status === "source_resolved" && choice(trace.sink_method, ["execute", "executemany"])
        && obj(driver) && driver.version === 1 && driver.driver === "psycopg3" && driver.method === "python_ast_straight_line"
        && integer(driver.import_line, 1, trace.sink_line) && integer(driver.connection_line, 1, trace.sink_line)
        && integer(driver.cursor_line, 1, trace.sink_line)
        && driver.import_line <= driver.connection_line && driver.connection_line <= driver.cursor_line;
    if (!deserialization && (trace.version !== 2 || trace.method !== "python_ast_local_flow"
        || trace.input_control_status !== "not_checked" || trace.flow_status !== "possible_local_flow"
        || trace.driver_status === "source_resolved" && !validDriver
        || trace.driver_status === "unknown" && "driver_provenance" in trace
        || !choice(trace.driver_status, ["unknown", "source_resolved"])
        || !integer(trace.assembly_line, 1)
        || !choice(trace.assembly_kind, ["concatenation", "percent_format", "f_string", "format_call", "join_call"])
        || !choice(trace.sink_method, ["execute", "executemany", "executescript", "raw", "execute_sql"])))
        return null;
    const source = value.source;
    if (!keys(source, ["file", "source_sha256"], ["sink_span"]) || typeof source.file !== "string"
        || !source.file.length || source.file.length > 4096 || /[\x00-\x1f]/.test(source.file)
        || source.file !== trace.file || !sha(source.source_sha256) || source.source_sha256 !== trace.source_sha256
        || deserialization && (!span(source.sink_span) || !Array.isArray(trace.sink_span)
            || source.sink_span.some((n, i) => n !== trace.sink_span[i]))
        || "sink_span" in source && (!span(source.sink_span) || source.sink_span[0] !== trace.sink_line))
        return null;
    const { facts, attempts, budget } = value;
    if (!Array.isArray(facts) || facts.length > actions.length || !Array.isArray(attempts) || attempts.length > actions.length
        || !keys(budget, ["max_steps", "steps", "work_units"]) || !integer(budget.max_steps, 0, actions.length)
        || !integer(budget.steps, 0, budget.max_steps) || budget.steps !== attempts.length || !integer(budget.work_units))
        return null;
    const found = new Map();
    for (const fact of facts) {
        if (!obj(fact) || typeof fact.id !== "string" || !Object.hasOwn(methods, fact.id) || found.has(fact.id)
            || fact.method !== methods[fact.id]
            || deserialization && !["request_input_source", "local_input_flow"].includes(fact.id))
            return null;
        const field = fields[fact.id], entries = fact[field];
        if (!keys(fact, ["id", "method", field]) || !Array.isArray(entries) || !entries.length
            || entries.length > (["locations", "constraints"].includes(field) ? 128 : 64))
            return null;
        if (field === "sources") {
            if (deserialization && entries.length !== 1)
                return null;
            if (entries.some(item => !keys(item, ["parameter", "channel", "span"]) || !parameter(item.parameter)
                || !choice(item.channel, deserialization ? ["body"] : ["query", "path"]) || !span(item.span)))
                return null;
        }
        else if (field === "locations") {
            if (!entries.every(span))
                return null;
        }
        else if (field === "slots") {
            if (!validDriver || entries.some((item, index) => !keys(item, ["index", "role"])
                || item.index !== index || item.role !== "value"))
                return null;
        }
        else if (entries.some(item => !keys(item, ["slot", "kind", "type", "span"])
            || !integer(item.slot, 0, 63) || !choice(item.kind, ["declared_type", "int_conversion", "request_string"])
            || !choice(item.type, ["str", "int", "float", "bool"]) || !span(item.span)
            || item.kind === "int_conversion" && item.type !== "int" || item.kind === "request_string" && item.type !== "str"))
            return null;
        found.set(fact.id, fact);
    }
    if (found.has("request_input_source") !== found.has("local_input_flow"))
        return null;
    if (deserialization && found.has("local_input_flow")) {
        const locations = found.get("local_input_flow").locations;
        const origin = found.get("request_input_source").sources[0].span;
        if (JSON.stringify(locations[0]) !== JSON.stringify(origin)
            || JSON.stringify(locations.at(-1)) !== JSON.stringify(trace.sink_span)
            || new Set(locations.map(location => JSON.stringify(location))).size !== locations.length)
            return null;
    }
    if (found.has("value_constraints")) {
        if (!found.has("local_input_flow"))
            return null;
        const covered = new Set(found.get("value_constraints").constraints.map(item => item.slot));
        const slots = found.get("sql_value_position")?.slots?.map(item => item.index)
            ?? Array.from({ length: covered.size }, (_, i) => i);
        if (covered.size !== slots.length || slots.some(index => !covered.has(index)))
            return null;
    }
    const emitted = new Set();
    let previous = -1;
    for (const attempt of attempts) {
        if (!keys(attempt, ["action", "result", "reason", "produced"], ["detail"])
            || typeof attempt.action !== "string" || !actions.includes(attempt.action)
            || "detail" in attempt && !identifier(attempt.detail)
            || !choice(attempt.result, ["established", "unknown", "unsupported", "error", "budget_exhausted"])
            || !choice(attempt.reason, reasons) || !Array.isArray(attempt.produced)
            || attempt.produced.some(id => typeof id !== "string"))
            return null;
        const establishedReasons = { locate_source: "source_snapshot_matched", trace_request_input: "request_flow_established",
            inspect_sql_slots: "sql_value_positions_established", collect_value_constraints: "value_constraints_recorded" };
        if (attempt.result === "established" && attempt.reason !== establishedReasons[attempt.action]
            || attempt.action === "locate_source" && attempt.result === "established" && !("sink_span" in source))
            return null;
        const order = actions.indexOf(attempt.action), produced = new Set(attempt.produced);
        const expected = attempt.result === "established" ? produces[attempt.action] : [];
        if (order <= previous || produced.size !== attempt.produced.length || produced.size !== expected.length
            || expected.some(id => !produced.has(id)) || [...produced].some(id => !found.has(id))
            || order > 0 && (!obj(attempts[0]) || attempts[0].action !== "locate_source" || attempts[0].result !== "established"))
            return null;
        produced.forEach(id => emitted.add(id));
        previous = order;
    }
    if (emitted.size !== found.size || facts.length > 0 && !("sink_span" in source))
        return null;
    const complete = found.size === actions.length;
    if ((value.status === "completed") !== complete || (value.stop_reason === "source_goal_reached") !== complete
        || (value.status === "partial") !== choice(value.stop_reason, ["budget_exhausted", "collector_error", "source_limit"]))
        return null;
    return structuredClone(value);
}
function normalizeDeserializationObservation(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        return null;
    const record = value;
    const required = ["version", "method", "file", "source_sha256", "sink_line", "sink_span", "sink_method", "loader", "input_control_status"];
    const integer = (v) => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 2 ** 31;
    const span = record.sink_span;
    if (Object.keys(record).length !== required.length || !required.every(key => Object.hasOwn(record, key))
        || record.version !== 1 || record.method !== "python_ast_import_resolved"
        || typeof record.file !== "string" || !record.file.length || [...record.file].length > 4096 || /[\x00-\x1f]/.test(record.file)
        || typeof record.source_sha256 !== "string" || !/^[a-f0-9]{64}(?![\s\S])/.test(record.source_sha256)
        || !integer(record.sink_line) || record.sink_line < 1 || !Array.isArray(span) || span.length !== 4 || !span.every(integer)
        || span[0] !== record.sink_line || !(span[2] > span[0] || span[2] === span[0] && span[3] > span[1])
        || record.sink_method !== "loads" || record.loader !== "pickle.loads" || record.input_control_status !== "not_checked")
        return null;
    return structuredClone(record);
}
function deserializationTraceRows(value, file, line) {
    const trace = normalizeDeserializationObservation(value);
    if (!trace || trace.file !== file || trace.sink_line !== line)
        return [];
    return [["Deserialization source trace", `Import-resolved pickle.loads() at line ${trace.sink_line}. `
                + "Input trust and loader runtime behavior were not checked."],
        ["Deserialization source SHA-256", String(trace.source_sha256)]];
}
function deserializationEvidenceRows(finding) {
    if (finding.source !== "static" || finding.rule_id !== "unsafe-deserialization" || finding.claim_evidence?.version !== 1)
        return [];
    return deserializationTraceRows(finding.claim_evidence.deserialization_observation, finding.file, finding.line);
}
function acquisitionRows(value, trace) {
    const record = normalizeAcquisition(value, trace);
    if (!record)
        return [];
    const human = (v) => v.replaceAll("_", " ");
    const rows = [["Source investigation", `${record.status}; ${human(record.stop_reason)}. `
                + "Source evidence only; runtime exploitability and repair behavior remain unverified."]];
    const labels = { locate_source: "Locate the source", trace_request_input: "Trace request input",
        inspect_sql_slots: "Check SQL value positions", collect_value_constraints: "Check value constraints" };
    for (const step of record.attempts)
        rows.push([`Investigation: ${labels[step.action]}`, `${human(step.result)}; ${human(step.reason)}`]);
    for (const fact of record.facts) {
        const detail = fact.sources ? fact.sources.map(item => `${item.channel} parameter ${item.parameter} at line ${item.span[0]}`).join("; ")
            : fact.locations ? `Local flow at lines ${fact.locations.map(item => item[0]).join(", ")}`
                : fact.slots ? `${fact.slots.length} substitution(s) in SQL value positions.`
                    : fact.constraints.map(item => `slot ${item.slot + 1}: ${human(item.kind)} ${item.type} at line ${item.span[0]}`).join("; ");
        rows.push([`Source fact: ${human(fact.id)}`, detail]);
    }
    rows.push(["Investigation budget", `${record.budget.steps} of ${record.budget.max_steps} actions; ${record.budget.work_units} work units.`]);
    return rows;
}

// Mirror the pure Python saved-record boundary. This validates a saved synthetic
// recipe record; it does not authenticate JSON or verify the customer project.
function normalizeSyntheticContract(value, observation, agentSource, catalog) {
    const obj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    const keys = (v, required) => obj(v)
        && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).length === required.length;
    const integer = (v) => Number.isSafeInteger(v) && Number(v) > 0 && Number(v) <= 2 ** 31 - 1;
    const sha = (v) => typeof v === "string" && /^[a-f0-9]{64}(?![\s\S])/.test(v);
    const exactRows = (v, expected) => Array.isArray(v) && v.length === expected.length
        && v.every((id, index) => id === expected[index]);
    if (!keys(value, ["version", "scope", "contract_id", "contract_revision", "status", "reason", "evidence_sha256",
        "synthetic_recipe_verified", "runtime_verified", "customer_project_verified", "automatic_patch", "proof", "source", "reused"])
        || value.version !== 1 || value.scope !== "synthetic_recipe" || value.contract_revision !== 1
        || value.contract_id !== "sql-value-parameterization-python-psycopg3" || !sha(value.evidence_sha256)
        || value.runtime_verified !== false || value.customer_project_verified !== false || value.automatic_patch !== false
        || typeof value.reused !== "boolean" || !obj(observation) || !obj(agentSource) || !obj(catalog))
        return null;
    const passed = value.status === "passed";
    const unavailableReasons = ["database_not_configured", "invalid_database_target", "ambient_libpq_options", "execution_unavailable",
        "execution_timeout", "output_limit", "invalid_contract_result", "unsupported_runtime", "budget_exhausted"];
    if (value.synthetic_recipe_verified !== passed || (passed ? value.reason !== "synthetic_contract_passed"
        : value.status === "failed" ? value.reason !== "synthetic_contract_failed"
            : value.status !== "unavailable" || typeof value.reason !== "string" || !unavailableReasons.includes(value.reason)))
        return null;
    if (observation.pattern_id !== "python-sql-string-assembly" || !integer(observation.pattern_revision)
        || observation.rule_id !== "sql-injection-string-built-query" || typeof observation.file !== "string"
        || !observation.file.toLowerCase().endsWith(".py") || !integer(observation.line) || !sha(observation.id)
        || !obj(observation.recipe) || observation.recipe.id !== value.contract_id || observation.recipe.status !== "manual_guidance"
        || observation.recipe.automatic_apply !== false || !obj(observation.evidence))
        return null;
    if (passed ? observation.state !== "synthetic_recipe_verified" || observation.next_action !== "review_project_runtime_contract"
        : observation.state !== "source_evidence_collected" || observation.next_action !== "review_runtime_contract")
        return null;
    const gaps = ["runtime_behavior_contract", "intended_value_type", "caller_authorization", "route_reachability"];
    const missing = observation.missing_evidence;
    if (!Array.isArray(missing) || !missing.every(item => typeof item === "string") || !gaps.every(gap => missing.includes(gap)))
        return null;
    const trace = observation.evidence.sql_observation;
    if (!obj(trace) || trace.file !== observation.file || trace.sink_line !== observation.line
        || trace.driver_status !== "source_resolved" || trace.sink_method !== "execute")
        return null;
    const acquisition = normalizeAcquisition(observation.acquisition, trace);
    if (acquisition?.status !== "completed")
        return null;
    const slots = acquisition.facts.find(fact => fact.id === "sql_value_position")?.slots;
    const constraints = acquisition.facts.find(fact => fact.id === "value_constraints")?.constraints;
    if (slots?.length !== 1 || !constraints?.length || constraints.some(item => item.slot !== 0 || item.type !== "str"))
        return null;
    const source = value.source;
    if (!keys(source, ["archive_sha256", "source_sha256", "observation_id", "engine_version", "catalog_sha256"])
        || !sha(source.archive_sha256) || source.archive_sha256 !== agentSource.archive_sha256
        || !sha(source.source_sha256) || source.source_sha256 !== trace.source_sha256
        || !sha(source.observation_id) || source.observation_id !== observation.id
        || !sha(source.catalog_sha256) || source.catalog_sha256 !== catalog.sha256
        || typeof source.engine_version !== "string" || !source.engine_version.length || [...source.engine_version].length > 128
        || source.engine_version !== agentSource.engine_version)
        return null;
    const proof = value.proof;
    if (passed) {
        if (!keys(proof, ["fixture_sha256", "schema_sha256", "psycopg_version", "postgresql_version", "executions", "cases_per_stage",
            "before_row_ids", "after_row_ids", "mutation_row_ids", "rollback_completed", "temporary_table_absent"])
            || proof.fixture_sha256 !== "8c856f7ededaa7fc4bf8c8cbb56819a30eb3f9553209e222e13ad7e4926b9517"
            || proof.schema_sha256 !== "9ca4174618e52ccbafebba9d1b5b6151f6ecdd1d5c67ba9f3b7f4706e2ff91a2"
            || typeof proof.psycopg_version !== "string" || proof.psycopg_version.length > 64
            || !/^3\.[0-9]+\.[0-9]+(?![\s\S])/.test(proof.psycopg_version) || !integer(proof.postgresql_version) || proof.postgresql_version < 100000
            || proof.executions !== 27 || proof.cases_per_stage !== 9 || proof.rollback_completed !== true
            || proof.temporary_table_absent !== true || !exactRows(proof.before_row_ids, [1, 2, 3, 4, 5, 6, 7, 8, 9])
            || !exactRows(proof.after_row_ids, [9]) || !exactRows(proof.mutation_row_ids, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
            return null;
    }
    else if (proof !== null)
        return null;
    return structuredClone(value);
}
function syntheticContractRows(record) {
    const rows = [
        ["Synthetic recipe contract", `Saved synthetic evidence: ${record.status}; ${record.reason.replaceAll("_", " ")}. Scope: synthetic recipe.`],
        ["Synthetic evidence SHA-256", record.evidence_sha256],
    ];
    if (record.proof)
        rows.push(["Before / after / mutation", "9 / 1 / 9 rows in the attack control; 27 executions across 9 cases."], ["Fixture cleanup", "Transaction rollback and temporary table removal confirmed."], ["Synthetic runtime", `PostgreSQL ${record.proof.postgresql_version}; Psycopg ${record.proof.psycopg_version}.`]);
    rows.push(["Synthetic execution", record.reused ? "Reused within this investigation." : "One bounded attempt; no automatic retry."], ["Customer project verification", "Customer project runtime tests not run. No automatic patch applied."]);
    return rows;
}

// JavaScript SQL view mirrors web/src/lib/jsSqlReview.ts.
function jsSqlReview(value, source) {
    const object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    const count = (v) => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 2 ** 31;
    const digest = (v) => typeof v === "string" && v.length === 64 && /^[a-f0-9]{64}$/.test(v);
    const keys = (v, expected) => Object.keys(v).length === expected.length && expected.every(key => Object.hasOwn(v, key));
    const states = ["fixed_sql_fragments", "dynamic_sql_unresolved", "unavailable"];
    // Match Python json.dumps(sort_keys=True, ensure_ascii=True, separators=(",", ":")).
    // Only the bounded, typed schema below reaches this function; its object keys are ASCII.
    const canonical = (v) => {
        if (typeof v === "string")
            return JSON.stringify(v).replace(/[\u007f-\uffff]/g, char => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0"));
        if (v === null || typeof v === "boolean" || typeof v === "number")
            return JSON.stringify(v);
        if (Array.isArray(v))
            return "[" + v.map(canonical).join(",") + "]";
        const item = v;
        return "{" + Object.keys(item).sort().map(key => canonical(key) + ":" + canonical(item[key])).join(",") + "}";
    };
    const receiptDigest = (v) => Array.from(sha256(Uint8Array.from(canonical(v), char => char.charCodeAt(0))), byte => byte.toString(16).padStart(2, "0")).join("");
    if (!object(value) || !object(source) || !object(value.source) || value.version !== 1
        || !digest(source.archive_sha256) || typeof source.engine_version !== "string"
        || value.source.archive_sha256 !== source.archive_sha256 || value.source.engine_version !== source.engine_version
        || value.runtime_verified !== false || value.automatic_patch !== false || value.model_calls !== 0
        || typeof value.coverage_partial !== "boolean" || !object(value.budget) || !Array.isArray(value.observations))
        return null;
    if (!keys(value, ["version", "source", "status", "budget", "observations", "coverage_partial", "runtime_verified", "automatic_patch", "model_calls"])
        || !keys(source, ["archive_sha256", "engine_version"]) || !keys(value.source, ["archive_sha256", "engine_version"])
        || source.engine_version.length < 1 || source.engine_version.length > 256 || [...source.engine_version].length > 128
        || !keys(value.budget, ["max_candidates", "candidates_found", "processed", "omitted"]))
        return null;
    const budget = value.budget;
    if (budget.max_candidates !== 32 || !count(budget.candidates_found) || !count(budget.processed)
        || !count(budget.omitted) || budget.processed > 32 || budget.processed !== value.observations.length
        || budget.candidates_found !== budget.processed + budget.omitted || budget.processed !== Math.min(32, budget.candidates_found))
        return null;
    const observations = [];
    const ids = new Set();
    for (const item of value.observations) {
        if (!object(item) || typeof item.id !== "string" || !digest(item.id) || ids.has(item.id)
            || typeof item.file !== "string" || !item.file || item.file.length > 8192 || [...item.file].length > 4096
            || !count(item.line) || item.line < 1 || typeof item.state !== "string" || !states.includes(item.state) || !object(item.analysis))
            return null;
        if (!keys(item, ["id", "file", "line", "state", "analysis", "tasks"]))
            return null;
        ids.add(item.id);
        const a = item.analysis;
        if (a.version !== 1 || a.runtime_verified !== false || a.file !== item.file || a.sink_line !== item.line
            || a.verdict !== item.state || !digest(a.source_sha256)
            || !(a.sink_column === null || (count(a.sink_column) && a.sink_column > 0))
            || !(a.sink_method === null || (typeof a.sink_method === "string" && a.sink_method.length > 0
                && a.sink_method.length <= 160 && [...a.sink_method].length <= 80))
            || typeof a.parameter_argument !== "string" || !["present", "absent", "unknown"].includes(a.parameter_argument)
            || typeof a.reason !== "string"
            || !Array.isArray(a.fragments) || a.fragments.length > 32 || !Array.isArray(item.tasks) || item.tasks.length !== 3)
            return null;
        if (!keys(a, ["version", "file", "source_sha256", "sink_line", "sink_column", "sink_method", "verdict", "parameter_argument", "fragments", "reason", "runtime_verified"]))
            return null;
        const reasons = { fixed_literal: "literal", fixed_helper: "single_return_literal_args",
            fixed_const: "stable_const", unknown: "unresolved_expression" };
        for (const f of a.fragments) {
            if (!object(f) || !keys(f, ["line", "kind", "reason"]) || !count(f.line) || f.line < 1 || typeof f.kind !== "string"
                || !Object.hasOwn(reasons, f.kind) || f.reason !== reasons[f.kind])
                return null;
        }
        for (let index = 0; index < 3; index++) {
            const task = item.tasks[index];
            const previous = index ? item.tasks[index - 1] : null;
            if (!object(task) || !keys(task, ["agent", "status", "input_sha256", "output_sha256", "depends_on"]) || task.agent !== ["detector", "researcher", "verifier"][index]
                || task.status !== (index && item.state === "unavailable" ? "blocked" : "completed")
                || !digest(task.input_sha256) || !digest(task.output_sha256) || !Array.isArray(task.depends_on)
                || task.depends_on.length !== (index ? 1 : 0)
                || (index && (task.input_sha256 !== previous.output_sha256 || task.depends_on[0] !== previous.output_sha256)))
                return null;
        }
        if (item.state !== "unavailable" && (a.sink_column === null || a.sink_method === null || a.parameter_argument === "unknown"))
            return null;
        const fixed = item.state === "fixed_sql_fragments";
        if (fixed && (a.reason !== "proven_fixed" || !a.fragments.length || a.fragments.some(f => f.kind === "unknown")))
            return null;
        if (item.state === "dynamic_sql_unresolved" && a.reason !== "unresolved_expression")
            return null;
        const unavailable = ["invalid_utf8", "unsupported_file", "file_limit", "parse_error", "node_limit", "depth_limit",
            "sink_not_found", "ambiguous_sink", "source_unavailable", "source_limit", "source_changed", "researcher_unavailable", "work_limit"];
        if (item.state === "unavailable" && !unavailable.includes(a.reason))
            return null;
        const seed = { source, ordinal: observations.length, file: item.file, line: item.line };
        if (item.id !== receiptDigest(seed))
            return null;
        const detected = { ...seed, rule_id: "sql-injection-string-built-query", source_sha256: a.source_sha256 };
        const researched = { ...detected, analysis: a };
        const verified = { ...researched, state: item.state };
        const digests = [seed, detected, researched, verified].map(receiptDigest);
        if (item.tasks.some((task, index) => task.input_sha256 !== digests[index]
            || task.output_sha256 !== digests[index + 1]))
            return null;
        const summary = fixed ? "Query text uses fixed fragments within bounded source analysis."
            : item.state === "dynamic_sql_unresolved" ? "Dynamic SQL text remains unresolved; external input control was not established."
                : "Source review unavailable; no conclusion about the query was established.";
        observations.push({ id: item.id, title: "JavaScript SQL source review", file: item.file, line: item.line,
            rows: [["Source result", summary], ["Reason", a.reason.replaceAll("_", " ")],
                ["Parameter argument", `${a.parameter_argument}; presence alone does not establish parameter binding or driver behavior.`],
                ["Source fragments", a.fragments.length ? a.fragments.map(f => `Line ${f.line}: ${String(f.kind).replaceAll("_", " ")} (${String(f.reason).replaceAll("_", " ")})`).join("; ") : "No source fragments established."],
                ["Task handoff", "Detector → researcher → verifier; bounded deterministic source review. Saved digests are consistency links, not independent attestation."],
                ["Source SHA-256", String(a.source_sha256)],
                ["Scope", "Static source analysis only. Runtime exploitability and database driver behavior remain unverified. The original finding is retained."]] });
    }
    const partial = value.coverage_partial || budget.omitted > 0 || value.observations.some(item => item.state === "unavailable");
    if (value.status !== (partial ? "partial" : "completed"))
        return null;
    return { rows: [["JavaScript SQL source review", `${value.status}; ${observations.length} observations; ${budget.omitted} omitted; limit 32.`],
            ["JavaScript SQL review limits", "No LLM calls, runtime execution or automatic patch. Fixed SQL fragments do not establish project safety."]], observations };
}

function renderSecurityAgent(agent) {
  const details = byId('security-agent-details');
  const container = byId('security-agent');
  container.replaceChildren();
  details.hidden = !agent || typeof agent !== 'object' || Array.isArray(agent)
    || agent.version !== 1 || !['deterministic_static', 'deterministic_evidence'].includes(agent.mode)
    || agent.runtime_verified !== false || agent.automatic_patch !== false;
  details.open = false;
  if (details.hidden) return;

  const observations = Array.isArray(agent.observations)
    ? agent.observations.filter(observation => observation && typeof observation === 'object') : [];
  const reviewStatus = ['completed', 'partial', 'unavailable'].includes(agent.status) ? agent.status : 'unavailable';
  const label = value => text(value, 'Not reported').replaceAll('_', ' ');
  const count = value => Number.isInteger(value) && value >= 0 ? value : 'Not reported';
  byId('security-agent-summary').textContent = `Pattern review · ${reviewStatus} · observations: ${observations.length}`;
  const js = jsSqlReview(agent.js_sql_review, agent.source);
  if (js) byId('security-agent-summary').textContent = `Pattern review · Python catalog: ${observations.length} · JavaScript SQL: ${js.observations.length}`;
  const hasSynthetic = observations.some(item => 'synthetic_contract' in item);
  container.append(node('p', hasSynthetic
    ? 'Review with no LLM, including saved synthetic recipe evidence. Customer project runtime exploitability and repairs remain unverified.'
    : 'Static review with no LLM. Completion describes the review scope; runtime exploitability and repairs remain unverified.', 'hint'));
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
  if (js) {
    const jsSummary = node('div');
    renderDefinitions(jsSummary, js.rows);
    container.append(jsSummary);
    for (const observation of js.observations) {
      const section = node('section');
      section.append(node('h4', observation.title));
      section.append(node('p', observation.file + ':' + observation.line, 'finding-location'));
      renderDefinitions(section, observation.rows);
      container.append(section);
    }
  } else if ('js_sql_review' in agent) {
    container.append(node('p', 'JavaScript SQL source review unavailable: the saved record could not be validated. Original findings are retained.', 'hint'));
  }
  let displayed = 0;
  for (const observation of observations.slice(0, 128)) {
    const deserialization = observation.rule_id === 'unsafe-deserialization';
    const sourceRecord = deserialization ? observation.evidence?.deserialization_observation : observation.evidence?.sql_observation;
    const acquisition = (deserialization || observation.rule_id === 'sql-injection-string-built-query')
      && sourceRecord?.file === observation.file && sourceRecord?.sink_line === observation.line
      ? normalizeAcquisition(observation.acquisition, sourceRecord) : null;
    const missing = Array.isArray(observation.missing_evidence) ? observation.missing_evidence : [];
    if (deserialization && acquisition && (observation.pattern_id !== 'python-unsafe-deserialization'
      || !['input_trust_boundary', 'loader_runtime_contract'].every(key => missing.includes(key)))) continue;
    const synthetic = normalizeSyntheticContract(observation.synthetic_contract, observation, agent.source, agent.catalog);
    const verified = observation.state === 'synthetic_recipe_verified';
    const collected = observation.state === 'source_evidence_collected';
    if (!(verified && observation.next_action === 'review_project_runtime_contract' && synthetic?.status === 'passed')
        && !(collected && observation.next_action === 'review_runtime_contract' && acquisition?.status === 'completed')
        && !(observation.state === 'needs_evidence' && observation.next_action === 'manual_review')) continue;
    if (!observation.recipe || observation.recipe.automatic_apply !== false
        || !['manual_guidance', 'not_available'].includes(observation.recipe.status)) continue;
    displayed += 1;
    const section = node('section');
    section.append(node('h4', `${text(observation.title, 'Static observation')} · ${label(observation.state)}`));
    const sql = deserialization ? undefined : observation.evidence?.sql_observation;
    const location = text(observation.file, 'Project');
    const line = Number.isInteger(observation.line) && observation.line > 0 ? `:${observation.line}` : '';
    section.append(node('p', `${location}${line}`, 'finding-location'));
    if (sql && typeof sql === 'object') {
      section.append(node('p', `Possible local SQL flow: assembly line ${count(sql.assembly_line)} → ${text(sql.sink_method, 'query call')} line ${count(sql.sink_line)}. Driver behavior and external input control are not checked.`, 'hint'));
    }
    const proof = sql?.driver_provenance;
    if (observation.rule_id === 'sql-injection-string-built-query'
        && sql?.version === 2 && sql.driver_status === 'source_resolved'
        && sql.input_control_status === 'not_checked'
        && ['concatenation', 'percent_format', 'f_string', 'format_call', 'join_call'].includes(sql.assembly_kind)
        && sql.method === 'python_ast_local_flow' && sql.flow_status === 'possible_local_flow'
        && sql.file === observation.file && sql.sink_line === observation.line
        && typeof sql.source_sha256 === 'string' && /^[a-f0-9]{64}$/.test(sql.source_sha256)
        && ['execute', 'executemany'].includes(sql.sink_method)
        && proof?.version === 1 && proof.driver === 'psycopg3' && proof.method === 'python_ast_straight_line'
        && [proof.import_line, proof.connection_line, proof.cursor_line, sql.sink_line, sql.assembly_line].every(n => Number.isInteger(n) && n > 0 && n < 2 ** 31)
        && proof.import_line <= proof.connection_line && proof.connection_line <= proof.cursor_line && proof.cursor_line <= sql.sink_line) {
      section.append(node('p', `Psycopg 3: import line ${proof.import_line} → connect() line ${proof.connection_line} → cursor() line ${proof.cursor_line}. Static source provenance only; installed driver and runtime behavior are unverified.`, 'hint'));
    } else if (sql) {
      section.append(node('p', sql.driver_status === 'not_checked'
        ? 'SQL driver source: not checked in this historical report.'
        : 'SQL driver source: unknown; cursor provenance was not established.', 'hint'));
    }
    const evidence = node('div');
    renderDefinitions(evidence, [
      ['Candidate weakness classes', Array.isArray(observation.weaknesses)
        ? observation.weaknesses.map(value => text(value)).join(', ') || 'Not reported' : 'Not reported'],
      ['Missing evidence', missing.length ? missing.map(label).join('; ') : 'Not reported'],
      ...(deserialization ? deserializationTraceRows(sourceRecord, observation.file, observation.line) : []),
      ...acquisitionRows(acquisition, sourceRecord),
      ...(synthetic ? syntheticContractRows(synthetic) : []),
      ...('synthetic_contract' in observation && !synthetic ? [['Synthetic evidence unavailable',
        'The saved synthetic evidence could not be validated. Customer project runtime behavior remains unverified.']] : []),
      ...('acquisition' in observation && !acquisition ? [['Source investigation unavailable',
        'The saved evidence could not be validated. Do not treat missing source facts as established.']] : []),
      ['Next step', verified
        ? 'Review the customer project runtime contract: confirm authorization, deployed reachability, intended value types and expected query behavior before choosing a repair.'
        : collected
        ? (deserialization
          ? 'Review the runtime contract: confirm input trust, loader options and expected object types before choosing a repair.'
          : 'Review the runtime contract: confirm reachability, input control and expected query behavior before choosing a repair.')
        : !('acquisition' in observation) && sql
          ? 'Manual review: trace the input origin and check the database driver’s parameter binding at the query call.'
          : 'Manual review: inspect the reported source location and gather the missing evidence.'],
      ['Repair guidance', observation.recipe?.status === 'manual_guidance'
        ? `${text(observation.recipe.id, 'Manual guidance')} · review prerequisites before choosing a repair; no patch is applied.`
        : 'No repair guidance available; no patch is applied.'],
    ]);
    section.append(evidence);
    container.append(section);
  }
  if (displayed < observations.length) container.append(node('p',
    `${observations.length - displayed} records could not be displayed within the supported schema and limit.`, 'hint'));
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
