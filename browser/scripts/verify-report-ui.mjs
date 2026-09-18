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
      evidence: { sql_observation: { source_sha256: 'b'.repeat(64), file: '<img src=x onerror=alert(2)>.py',
        assembly_line: 7, assembly_kind: 'f_string', sink_line: 9, sink_method: 'execute',
        flow_status: 'possible_local_flow', driver_status: 'not_checked', input_control_status: 'not_checked' } },
      missing_evidence: ['external_input_control', 'driver_parameter_binding', 'runtime_exploitability'],
      next_action: 'manual_review', recipe: { id: 'sql-parameter-binding', status: 'manual_guidance', automatic_apply: false },
      steps: [],
    }],
    budget: { max_candidates: 128, candidates_found: 129, processed: 128, candidates_omitted: 1 },
    stop_reason: 'candidate_limit', limitations: ['static_analysis_only'], runtime_verified: false, automatic_patch: false,
  },
};
const sarif = { version: '2.1.0', runs: [{ results: report.findings.map(f => ({ message: { text: f.title } })) }] };
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.route('**/*', async route => {
    const name = new URL(route.request().url()).pathname.slice(1) || 'index.html';
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
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
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
  console.log('Report UI: grouping, retained priority, pattern review evidence, keyboard disclosure, safe text, metadata, exports and mobile layout passed');
} finally {
  await browser.close();
}
