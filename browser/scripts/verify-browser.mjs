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
  await page.waitForFunction(() => ['PASSED', 'FAILED'].includes(document.querySelector('#status').textContent), null,
    { timeout: 120_000 });
  const cases = JSON.parse(await readFile(resolve(root, 'test-dist/cases.json')));
  assert.ok(cases.length > 0, 'Need a nonempty corpus');
  const expectedChecks = cases[0].native.report.checks_run;
  const measured = JSON.parse(await page.locator('#result').textContent());
  await writeFile(resolve(output, 'chromium-parity.json'), JSON.stringify(measured, null, 2));
  assert.equal(measured.summary?.unexpected_failures, 0, 'Chromium corpus parity failed');
  assert.equal(measured.summary.cases, cases.length);
  assert.equal(measured.summary.expectation_passed, cases.length, 'Every corpus expectation must pass');
  assert.equal(measured.summary.full_parity, true);

  assert.equal(measured.summary.parser_probes, 'passed');
  assert.equal(measured.summary.supported_checks, expectedChecks.length);

  assert.deepEqual(measured.rows.map(r => r.id).sort(), cases.map(c => c.id).sort());
  const item = cases.find(c => c.rule === 'stripe-live-key' && c.polarity === 'positive');
  assert.ok(item, 'Need a real synthetic credential fixture');
  const input = { name: 'synthetic-project.zip', mimeType: 'application/zip', buffer: Buffer.from(item.archive, 'base64') };
  await page.goto(base + '/index.html');
  await page.getByLabel('Project ZIP', { exact: true }).setInputFiles(input);
  await page.getByRole('button', { name: 'Scan locally' }).click();
  await page.locator('#results').waitFor({ state: 'visible', timeout: 120_000 });
  assert.equal(await page.locator('#checks-not-run li').count(), 0);
  assert.equal(await page.locator('#checks-run li').count(), expectedChecks.length);
  assert.match(await page.locator('#findings').innerText(), /Stripe/);
  await page.screenshot({ path: resolve(output, 'scanner-desktop.png'), fullPage: true });

  for (const [label, name] of [['Export JSON', 'report.json'], ['Export SARIF', 'report.sarif']]) {
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: label }).click();
    const download = await downloadPromise;
    await download.saveAs(resolve(output, name));
  }
  const report = JSON.parse(await readFile(resolve(output, 'report.json')));
  assert.equal(report.checks_not_run.length, 0);
  assert.deepEqual([...report.checks_run].sort(), [...expectedChecks].sort());
  assert.ok(report.findings.some(f => f.rule_id === 'stripe-live-key'));
  assert.equal('score' in report, false);
  const sarif = JSON.parse(await readFile(resolve(output, 'report.sarif')));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
  assert.equal(sarif.runs[0].results.length, report.findings.length);

  const continuation = JSON.parse(await readFile(resolve(root, 'test-dist/continuation.json')));
  await page.getByLabel('Project ZIP', { exact: true }).setInputFiles({
    name: 'large-project.zip', mimeType: 'application/zip', buffer: Buffer.from(continuation.archive, 'base64'),
  });
  await page.getByRole('button', { name: 'Scan locally', exact: true }).click();
  await page.getByRole('button', { name: 'Continue scanning remaining files', exact: true }).waitFor({ timeout: 120_000 });
  assert.equal(await page.locator('#partial-coverage').isVisible(), true);
  assert.match(await page.locator('#checks-not-run').innerText(), /400 of 403/);
  for (const expected of continuation.continuations) {
    const button = page.getByRole('button', { name: 'Continue scanning remaining files', exact: true });
    await button.click();
    await page.waitForFunction(() => document.querySelector('#scan-button').disabled === false,
      null, { timeout: 120_000 });
    assert.equal(await button.isVisible(), expected.can_continue);
  }
  assert.match(await page.locator('#checks-not-run').innerText(), /402 of 403/);
  assert.match(await page.locator('#checks-not-run').innerText(), /parse error/);
  assert.match(await page.locator('#findings').innerText(), /tail.js/);
  assert.match(await page.locator('#findings').innerText(), /tail.vue/);
  assert.match(await page.locator('#findings').innerText(), /tail.py/);
  const continuedDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON', exact: true }).click();
  await (await continuedDownload).saveAs(resolve(output, 'continued.json'));
  const continued = JSON.parse(await readFile(resolve(output, 'continued.json')));
  delete continued.runtime;
  assert.deepEqual(continued, continuation.final.report);

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
  // A missing native asset must preserve useful findings and explicitly mark
  // incomplete coverage. A fresh context avoids a previously cached wheel.
  const degraded = await browser.newContext();
  await degraded.route('**/*', route => {
    const r = route.request();
    if (!r.url().startsWith(base + '/') || r.method() !== 'GET') return route.abort();
    if (/\/(tree_sitter[^/]*|pglast[^/]*)\.whl$/.test(r.url())) return route.abort();
    return route.continue();
  });
  const fallback = await degraded.newPage();
  await fallback.goto(base + '/index.html');
  await fallback.getByLabel('Project ZIP', { exact: true }).setInputFiles(input);
  await fallback.getByRole('button', { name: 'Scan locally' }).click();
  await fallback.locator('#results').waitFor({ state: 'visible', timeout: 120_000 });
  assert.equal(await fallback.locator('#checks-not-run li').count(), item.portable.report.checks_not_run.length);
  assert.equal(await fallback.locator('#checks-run li').count(), item.portable.report.checks_run.length);
  assert.match(await fallback.locator('#findings').innerText(), /Stripe/);
  assert.equal(await fallback.locator('#partial-coverage').isVisible(), true);
  const fallbackDownload = fallback.waitForEvent('download');
  await fallback.getByRole('button', { name: 'Export SARIF' }).click();
  await (await fallbackDownload).saveAs(resolve(output, 'degraded.sarif'));
  const incomplete = JSON.parse(await readFile(resolve(output, 'degraded.sarif')));
  assert.equal(incomplete.runs[0].invocations[0].executionSuccessful, false);
  const fallbackJson = fallback.waitForEvent('download');
  await fallback.getByRole('button', { name: 'Export JSON' }).click();
  await (await fallbackJson).saveAs(resolve(output, 'degraded.json'));
  const partialReport = JSON.parse(await readFile(resolve(output, 'degraded.json')));
  assert.equal(partialReport.runtime.native_load_failures.length, 4);
  delete partialReport.runtime;
  assert.deepEqual({ report: partialReport, sarif: incomplete }, item.portable);
  await degraded.close();
  console.log(JSON.stringify({ ...measured.summary, ui: 'passed', exports: 'passed', network: 'same-origin GET assets only' }));
} finally {
  await browser.close();
}
