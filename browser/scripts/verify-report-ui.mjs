// Report presentation contract, exercised in Chromium without loading the scanner runtime.
// The worker returns controlled findings; the real upload, rendering and export code runs.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(root, 'src');
const base = 'http://scanner.test';
const fileReports = JSON.parse(await readFile(resolve(root, '../tests/fixtures/deserialization-file-agent.json'), 'utf8'));
const fileReport = fileReports.find(item => item.name === 'completed').report;
const fileSarif = { version: '2.1.0', runs: [{ results: fileReport.findings.map(f => ({
  ruleId: f.rule_id, message: { text: f.title },
  ...(f.file && f.line > 0 ? { locations: [{ physicalLocation: {
    artifactLocation: { uri: f.file }, region: { startLine: f.line },
  } }] } : {}),
})) }] };
const finding = (title, overrides = {}) => ({
  title, rule_id: 'test-rule', severity: 'medium', confidence: 0.4,
  file: 'src/config.py', line: 1, verification_status: 'unverified', ...overrides,
});
const report = {
  findings: [
    finding('Production candidate', { explanation: 'Review the credential origin.', fix_hint: 'Check whether the value is synthetic.' }),
    finding('Fixture candidate', { context: 'test_fixture', confidence: 0.1 }),
    finding('Severe test signal', { context: 'test_file', severity: 'high', confidence: 0.2 }),
    finding('Credible test signal', { context: 'test_file', confidence: 0.95 }),
    finding('Deployment inventory', { context: 'deployment_inventory', severity: 'low', confidence: 0.9 }),
    finding('Template candidate', { claim_evidence: { source_context: { kind: 'configuration_template' } } }),
    finding('<img src=x onerror=alert(1)>', { context: 'comment' }),
    finding('Unknown context', { context: 'future_context' }),
  ],
  checks_run: ['secrets', 'xss'], checks_not_run: [], limitations: ['static_source_only'],
  rule_coverage: { xss: { analyzed_files: 400, eligible_files: 429, skipped_files: 29,
    partial: true, skip_reasons: { file_limit: 29 } } },
  security_agent: {
    version: 1, mode: 'deterministic_static', status: 'partial',
    catalog: { version: '2026-09-18-1', sha256: 'a'.repeat(64), cards: 1 },
    plan: [{ pattern_id: 'sql-string-assembly', title: 'String-built SQL', check: 'sql_injection', status: 'partial',
      coverage: { analyzed_files: 128, eligible_files: 129, skipped_files: 1, partial: true } }],
    observations: [{ id: 'observation-1', pattern_id: 'sql-string-assembly', pattern_revision: 1,
      title: 'String-built SQL', weaknesses: ['CWE-89'], rule_id: 'sql-injection-string-built-query',
      file: '<img src=x onerror=alert(2)>.py', line: 9, state: 'needs_evidence',
      evidence: { sql_observation: { version: 2, method: 'python_ast_local_flow', source_sha256: 'b'.repeat(64), file: '<img src=x onerror=alert(2)>.py',
        assembly_line: 7, assembly_kind: 'f_string', sink_line: 9, sink_method: 'execute',
        flow_status: 'possible_local_flow', driver_status: 'source_resolved', input_control_status: 'not_checked',
        driver_provenance: { version: 1, driver: 'psycopg3', method: 'python_ast_straight_line',
          import_line: 1, connection_line: 3, cursor_line: 4 } } },
      missing_evidence: ['external_input_control', 'driver_parameter_binding', 'runtime_exploitability'],
      next_action: 'manual_review', recipe: { id: 'sql-parameter-binding', status: 'manual_guidance', automatic_apply: false },
      steps: [],
    }],
    budget: { max_candidates: 128, candidates_found: 129, processed: 128, candidates_omitted: 1 },
    stop_reason: 'candidate_limit', limitations: ['static_analysis_only'], runtime_verified: false, automatic_patch: false,
  },
};
// The same source identity binds every fact and recorded action to this sink.
const acquiredReport = structuredClone(report);
const acquiredAgent = acquiredReport.security_agent;
acquiredAgent.status = 'completed';
acquiredAgent.stop_reason = 'bounded_review_completed';
acquiredAgent.budget = { max_candidates: 128, candidates_found: 1, processed: 1, candidates_omitted: 0 };
const acquired = acquiredAgent.observations[0];
acquired.title = 'Request input source investigation';
acquired.state = 'source_evidence_collected';
acquired.next_action = 'review_runtime_contract';
acquired.missing_evidence = ['runtime_reachability', 'attacker_control', 'expected_query_contract'];
acquired.acquisition = {
  version: 1, status: 'completed', stop_reason: 'source_goal_reached',
  source: { file: acquired.file, source_sha256: 'b'.repeat(64), sink_span: [9, 4, 9, 42] },
  facts: [
    { id: 'request_input_source', method: 'fastapi_ast_binding',
      sources: [{ parameter: 'user_id', channel: 'query', span: [5, 11, 5, 23] }] },
    { id: 'local_input_flow', method: 'python_ast_straight_line', locations: [[5, 11, 5, 23], [7, 18, 7, 25], [9, 4, 9, 42]] },
    { id: 'sql_value_position', method: 'postgresql_ast_slot_context', slots: [{ index: 0, role: 'value' }] },
    { id: 'value_constraints', method: 'python_ast_constraints',
      constraints: [{ slot: 0, kind: 'declared_type', type: 'str', span: [5, 20, 5, 23] }] },
  ],
  attempts: [
    { action: 'locate_source', result: 'established', reason: 'source_snapshot_matched', produced: [] },
    { action: 'trace_request_input', result: 'established', reason: 'request_flow_established', produced: ['request_input_source', 'local_input_flow'] },
    { action: 'inspect_sql_slots', result: 'established', reason: 'sql_value_positions_established', produced: ['sql_value_position'] },
    { action: 'collect_value_constraints', result: 'established', reason: 'value_constraints_recorded', produced: ['value_constraints'] },
  ],
  budget: { max_steps: 4, steps: 4, work_units: 100 },
};
const sarif = { version: '2.1.0', runs: [{ results: report.findings.map(f => ({ message: { text: f.title } })) }] };
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.route('**/*', async route => {
    const name = new URL(route.request().url()).pathname.slice(1) || 'index.html';
    if (['sha2.js', '_md.js', '_u64.js', 'utils.js'].some(file => name === 'vendor/noble/' + file)) {
      return route.fulfill({ body: await readFile(resolve(root, 'node_modules/@noble/hashes', name.slice('vendor/noble/'.length))),
        contentType: 'application/javascript' });
    }
    if (!['index.html', 'app.js', 'styles.css'].includes(name)) return route.abort();
    await route.fulfill({ body: await readFile(resolve(source, name)), contentType: name.endsWith('.js')
      ? 'application/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html' });
  });
  await context.addInitScript(({ report, sarif }) => {
    window.scanResponse = { report, sarif };
    window.Worker = class {
      postMessage() { queueMicrotask(() => this.onmessage({ data: { type: 'result', ...window.scanResponse } })); }
      terminate() {}
    };
  }, { report, sarif });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(base);
  await page.getByLabel('Project ZIP', { exact: true }).setInputFiles({ name: 'project.zip', mimeType: 'application/zip', buffer: Buffer.from('worker fixture') });
  await page.getByRole('button', { name: 'Scan locally', exact: true }).click();
  await page.locator('#results').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#partial-coverage').isVisible(), true);
  assert.match(await page.locator('#checks-not-run').innerText(), /400 of 429/);
  const initial = page.getByRole('region', { name: 'Initial review (4)' });
  assert.equal(await initial.locator('article').count(), 4);
  for (const title of ['Production candidate', 'Severe test signal', 'Credible test signal', 'Unknown context']) {
    assert.equal(await initial.getByRole('heading', { name: title, exact: true }).isVisible(), true);
  }
  assert.equal(await page.locator('#findings article').count(), 8, 'Grouping must retain all findings');
  const details = page.locator('.contextual-findings');
  assert.equal(await details.getAttribute('open'), null, 'Contextual findings should initially be collapsed');
  assert.equal(await page.getByRole('heading', { name: 'Fixture candidate', exact: true }).isVisible(), false);
  await details.locator('summary').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.getByRole('heading', { name: 'Fixture candidate', exact: true }).isVisible(), true);
  assert.equal(await details.locator('article').count(), 4);
  assert.equal(await details.locator('img').count(), 0, 'Finding text must not become HTML');
  assert.match(await details.innerText(), /Detector confidence: 0.10/);
  assert.match(await initial.innerText(), /Verification: unverified/);
  assert.match(await initial.innerText(), /Suggested next step: Check whether the value is synthetic/);
  const patternReview = page.locator('#security-agent-details');
  assert.equal(await patternReview.isVisible(), true);
  assert.equal(await patternReview.getAttribute('open'), null, 'Pattern review should initially be collapsed');
  assert.match(await patternReview.locator('summary').innerText(), /Pattern review · partial · observations: 1/);
  await patternReview.locator('summary').focus();
  await page.keyboard.press('Enter');
  const patternText = await patternReview.innerText();
  assert.match(patternText, /2026-09-18-1 · patterns: 1/);
  assert.ok(patternText.includes('a'.repeat(64)), 'The review must identify its exact catalog');
  assert.match(patternText, /128 processed \/ 129 found · 1 omitted · limit 128/);
  assert.match(patternText, /String-built SQL: partial/);
  assert.match(patternText, /assembly line 7 → execute line 9/);
  assert.match(patternText, /Psycopg 3: import line 1 → connect\(\) line 3 → cursor\(\) line 4/);
  assert.match(patternText, /installed driver and runtime behavior are unverified/);
  assert.match(patternText, /Candidate weakness classes[\s\S]*CWE-89/);
  assert.ok(patternText.includes('<img src=x onerror=alert(2)>.py:9'));
  assert.equal(await patternReview.locator('img').count(), 0, 'Observation filenames must remain text');
  assert.match(patternText, /external input control; driver parameter binding; runtime exploitability/);
  assert.match(patternText, /Manual review: trace the input origin/);
  assert.match(patternText, /review prerequisites before choosing a repair; no patch is applied/);
  assert.match(patternText, /runtime exploitability and repairs remain unverified/);
  for (const [label, expected] of [['Export JSON', report], ['Export SARIF', sarif]]) {
    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name: label }).click();
    const stream = await (await pending).createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()), expected, 'Presentation must not modify exports');
  }
  async function scanControlled(nextReport, nextSarif = sarif) {
    await page.evaluate(next => { window.scanResponse = next; }, { report: nextReport, sarif: nextSarif });
    await page.getByRole('button', { name: 'Scan locally', exact: true }).click();
    await patternReview.locator('summary').click();
  }
  await scanControlled(acquiredReport);
  const acquiredSection = patternReview.locator('section').filter({ hasText: 'Request input source investigation' });
  await acquiredSection.waitFor({ state: 'visible' });
  const acquiredText = await acquiredSection.innerText();
  assert.match(acquiredText, /source evidence collected/);
  assert.match(acquiredText, /Source investigation[\s\S]*completed; source goal reached/);
  assert.match(acquiredText, /Investigation: Locate the source[\s\S]*established; source snapshot matched/);
  assert.match(acquiredText, /Investigation: Trace request input[\s\S]*established; request flow established/);
  assert.match(acquiredText, /Investigation: Check SQL value positions[\s\S]*established; sql value positions established/);
  assert.match(acquiredText, /Investigation: Check value constraints[\s\S]*established; value constraints recorded/);
  assert.match(acquiredText, /query parameter user_id at line 5/);
  assert.match(acquiredText, /Local flow at lines 5, 7, 9/);
  assert.match(acquiredText, /1 substitution\(s\) in SQL value positions/);
  assert.match(acquiredText, /slot 1: declared type str at line 5/);
  assert.match(acquiredText, /runtime reachability; attacker control; expected query contract/);
  assert.match(acquiredText, /Review the runtime contract: confirm reachability/);
  assert.doesNotMatch(acquiredText, /Manual review: trace the input origin/);
  assert.match(acquiredText, /runtime exploitability and repair behavior remain unverified/);
  assert.equal(await acquiredSection.locator('img').count(), 0, 'Source identities remain text in acquired evidence');
  for (const [label, expected] of [['Export JSON', acquiredReport], ['Export SARIF', sarif]]) {
    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name: label }).click();
    const stream = await (await pending).createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()), expected, 'Acquisition display must preserve exports');
  }
  const partialReport = structuredClone(acquiredReport);
  const partialObservation = partialReport.security_agent.observations[0];
  partialObservation.title = 'Incomplete source investigation';
  partialObservation.state = 'needs_evidence';
  partialObservation.next_action = 'manual_review';
  partialObservation.missing_evidence.unshift('psycopg3_cursor_provenance', 'sql_value_position');
  partialObservation.evidence.sql_observation.driver_status = 'unknown';
  delete partialObservation.evidence.sql_observation.driver_provenance;
  partialObservation.acquisition.status = 'unsupported';
  partialObservation.acquisition.stop_reason = 'no_further_action';
  partialObservation.acquisition.facts.splice(2, 1);
  partialObservation.acquisition.attempts[2] = { action: 'inspect_sql_slots', result: 'unknown',
    reason: 'sql_slots_not_established', produced: [] };
  await scanControlled(partialReport);
  const partialSection = patternReview.locator('section').filter({ hasText: 'Incomplete source investigation' });
  await partialSection.waitFor({ state: 'visible' });
  const partialText = await partialSection.innerText();
  assert.match(partialText, /unsupported; no further action/);
  assert.match(partialText, /unknown; sql slots not established/);
  assert.match(partialText, /query parameter user_id at line 5/);
  assert.match(partialText, /slot 1: declared type str at line 5/);
  assert.match(partialText, /psycopg3 cursor provenance; sql value position/);
  assert.match(partialText, /Manual review: inspect the reported source location and gather the missing evidence/);
  assert.doesNotMatch(partialText, /Review the runtime contract:|substitution\(s\) in SQL value positions/);
  for (const mutate of [
    observation => { observation.acquisition.source.source_sha256 = 'c'.repeat(64); },
    observation => { observation.acquisition.facts.pop(); },
  ]) {
    const forged = structuredClone(acquiredReport);
    mutate(forged.security_agent.observations[0]);
    await scanControlled(forged);
    assert.equal(await patternReview.locator('section').count(), 0, 'Invalid acquisition must not promote a decision');
    assert.match(await patternReview.innerText(), /1 records could not be displayed within the supported schema and limit/);
    assert.doesNotMatch(await patternReview.innerText(), /Review the runtime contract:|query parameter user_id/);
  }
  // Actual scanner-produced file evidence: group two loader locations while
  // retaining each card and the original JSON/SARIF download records.
  await scanControlled(fileReport, fileSarif);
  const fileGroup = page.locator('#findings details').filter({
    has: page.locator('summary', { hasText: 'Pickle file loading · 2 locations' }),
  });
  await fileGroup.waitFor({ state: 'visible' });
  assert.equal(await fileGroup.locator('article').count(), 2);
  assert.equal(await page.locator('#findings article').count(), fileReport.findings.length);
  assert.match(await page.locator('#findings-summary').innerText(), new RegExp(`^${fileReport.findings.length} total findings`));
  for (const evidence of await fileGroup.locator('article details').all()) {
    await evidence.locator(':scope > summary').click();
  }
  const fileGroupText = await fileGroup.innerText();
  for (const line of [7, 11]) assert.ok(fileGroupText.includes(`src/checkpoints.py:${line}`));
  assert.match(fileGroupText, /Detector confidence: 0\.80/);
  assert.match(fileGroupText, /Verification: unverified/);
  assert.match(fileGroupText, /Deserialization source SHA-256/);
  const fileReviewText = await patternReview.innerText();
  assert.match(fileReviewText, /Function read_primary/);
  assert.match(fileReviewText, /Function read_secondary/);
  assert.match(fileReviewText, /Calling code and origin of the file[\s\S]*not checked/i);
  assert.doesNotMatch(fileReviewText, /body parameter|pickle\.loads\(\)/);
  await fileGroup.locator(':scope > summary').focus();
  await page.keyboard.press('Enter');
  assert.equal(await fileGroup.locator('article').first().isVisible(), false);
  await page.keyboard.press('Enter');
  assert.equal(await fileGroup.locator('article').first().isVisible(), true);
  for (const [label, expected] of [['Export JSON', fileReport], ['Export SARIF', fileSarif]]) {
    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name: label }).click();
    const stream = await (await pending).createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()), expected, 'File grouping must preserve exports');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await scanControlled(acquiredReport);
  await page.evaluate(() => {
    window.scanResponse.report.findings = window.scanResponse.report.findings.filter(f => f.context === 'test_fixture');
    delete window.scanResponse.report.security_agent;
  });
  await page.getByRole('button', { name: 'Scan locally', exact: true }).click();
  await page.getByRole('heading', { name: 'Initial review (0)', exact: true }).waitFor();
  assert.match(await page.locator('#findings').innerText(), /All reported signals are grouped below/);
  assert.match(await page.locator('#findings').innerText(), /does not establish that the project is safe/);
  assert.equal(await page.locator('#findings article').count(), 1, 'Rescanning must clear old cards');
  assert.equal(await patternReview.isVisible(), false, 'Older reports without pattern review must hide the section');
  assert.equal(await page.locator('#security-agent').textContent(), '', 'Rescanning must clear previous observations');
  assert.deepEqual(errors, []);
  console.log('Report UI: grouping, retained priority, legacy review, acquired source facts, remaining gaps, rejected forged records, keyboard disclosure, safe text, exports and mobile layout passed');
} finally {
  await browser.close();
}
