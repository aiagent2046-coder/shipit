// CI verification of the published static artifact in real Chromium.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const base = 'http://127.0.0.1:8765';
const output = resolve(root, 'measurements');
await mkdir(output, { recursive: true });
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const requests = [];
  context.on('request', r => requests.push({ method: r.method(), url: r.url() }));
  // Reject any unintended connection. All runtime assets must be on this host.
  await context.route('**/*', route => {
    const request = route.request();
    if (request.url().startsWith(base + '/') && request.method() === 'GET') return route.continue();
    return route.abort();
  });
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(e.message));
  await page.goto(base + '/harness.html');
  await page.waitForFunction(() => ['PASSED', 'FAILED'].includes(document.querySelector('#status').textContent), { timeout: 120_000 });
  const measured = JSON.parse(await page.locator('#result').textContent());
  await writeFile(resolve(output, 'chromium-parity.json'), JSON.stringify(measured, null, 2));
  assert.equal(measured.summary?.unexpected_failures, 0, 'Chromium corpus parity failed');
  assert.equal(measured.summary.cases, 251);
  assert.equal(measured.summary.expectation_passed, 209, 'Update measured scope explicitly when changing support');
  assert.equal(measured.summary.full_parity, false);

  const cases = JSON.parse(await readFile(resolve(root, 'test-dist/cases.json')));
  const item = cases.find(c => c.rule === 'stripe-live-key' && c.polarity === 'positive');
  assert.ok(item, 'Need a real synthetic credential fixture');
  const input = { name: 'synthetic-project.zip', mimeType: 'application/zip', buffer: Buffer.from(item.archive, 'base64') };
  await page.goto(base + '/index.html');
  await page.getByLabel('Project ZIP', { exact: true }).setInputFiles(input);
  await page.getByRole('button', { name: 'Scan locally' }).click();
  await page.locator('#results').waitFor({ state: 'visible', timeout: 120_000 });
  assert.equal(await page.locator('#checks-not-run li').count(), 4);
  assert.equal(await page.locator('#checks-run li').count(), 13);
  assert.match(await page.locator('#findings').innerText(), /Stripe/);
  await page.screenshot({ path: resolve(output, 'scanner-desktop.png'), fullPage: true });

  for (const [label, name] of [['Export JSON', 'report.json'], ['Export SARIF', 'report.sarif']]) {
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: label }).click();
    const download = await downloadPromise;
    await download.saveAs(resolve(output, name));
  }
  const report = JSON.parse(await readFile(resolve(output, 'report.json')));
  assert.equal(report.checks_not_run.length, 4);
  assert.ok(report.findings.some(f => f.rule_id === 'stripe-live-key'));
  assert.equal('score' in report, false);
  const sarif = JSON.parse(await readFile(resolve(output, 'report.sarif')));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  assert.equal(sarif.runs[0].results.length, report.findings.length);

  // Cancel an actual new worker, then scan an invalid archive. Old results must
  // not survive as if they belonged to the next selected file.
  await page.getByRole('button', { name: 'Scan locally' }).click();
  await page.getByRole('button', { name: 'Cancel scan' }).click();
  assert.match(await page.locator('#scan-status').innerText(), /cancelled/);
  await page.getByLabel('Project ZIP', { exact: true }).setInputFiles({
    name: 'invalid.zip', mimeType: 'application/zip', buffer: Buffer.from('not a ZIP'),
  });
  await page.getByRole('button', { name: 'Scan locally' }).click();
  await page.locator('#scan-error').waitFor({ state: 'visible', timeout: 120_000 });
  assert.equal(await page.locator('#results').isVisible(), false);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await page.screenshot({ path: resolve(output, 'scanner-mobile.png'), fullPage: true });
  assert.deepEqual(pageErrors, []);
  assert.ok(requests.every(r => r.method === 'GET' && r.url.startsWith(base + '/') && !r.url.includes('?')),
    'Unexpected network request; source must never enter a request');
  await writeFile(resolve(output, 'network.json'), JSON.stringify(requests, null, 2));
  console.log(JSON.stringify({ ...measured.summary, ui: 'passed', exports: 'passed', network: 'same-origin GET assets only' }));
} finally {
  await browser.close();
}
