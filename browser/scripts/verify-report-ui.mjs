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
  await page.evaluate(() => { window.scanResponse.report.findings = window.scanResponse.report.findings.filter(f => f.context === 'test_fixture'); });
  await page.getByRole('button', { name: 'Scan locally', exact: true }).click();
  await page.getByRole('heading', { name: 'Initial review (0)', exact: true }).waitFor();
  assert.match(await page.locator('#findings').innerText(), /All reported signals are grouped below/);
  assert.match(await page.locator('#findings').innerText(), /does not establish that the project is safe/);
  assert.equal(await page.locator('#findings article').count(), 1, 'Rescanning must clear old cards');
  assert.deepEqual(errors, []);
  console.log('Report UI: grouping, retained priority, keyboard disclosure, safe text, metadata, exports and mobile layout passed');
} finally {
  await browser.close();
}
