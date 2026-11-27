import assert from 'node:assert/strict';
const origin = 'http://127.0.0.1:5181';
const checks = [];
for (const path of ['/api/livez', '/api/health']) {
  const response = await fetch(origin + path, { signal: AbortSignal.timeout(3000) });
  const body = await response.json();
  assert.equal(response.status, 200, path);
  assert.equal(body.ok, true, path);
  checks.push({ path, status: response.status, ok: body.ok });
}
const page = await fetch(origin + '/', { signal: AbortSignal.timeout(3000) });
const html = await page.text();
assert.equal(page.status, 200);
assert.match(html, /<html/i);
assert.match(html, /id=["']root["']/);
const asset = html.match(/<script[^>]+src="([^"]+)"/i)?.[1];
assert.ok(asset && asset.startsWith('/assets/'), 'built JavaScript asset');
const js = await fetch(origin + asset, { signal: AbortSignal.timeout(3000) });
assert.equal(js.status, 200);
assert.ok((await js.text()).length > 100);
checks.push({ path: '/', status: page.status, spa: true, asset, assetStatus: js.status });
const metrics = await fetch(origin + '/api/metrics', { signal: AbortSignal.timeout(3000) });
assert.equal(metrics.status, 404);
checks.push({ path: '/api/metrics', status: metrics.status });
console.log(JSON.stringify({ status: 'passed', at: new Date().toISOString(), checks,
  scope: 'real application boot, migrations, PostgreSQL readiness, static frontend and JavaScript delivery',
  browserExecuted: false, authenticatedFlowsChecked: false, vulnerabilityRemediationVerified: false }, null, 2));
