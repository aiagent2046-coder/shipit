import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateCase, summarize } from './parity.js';

function fixture(checks) {
  const native = {
    report: { findings: [], checks_run: checks, checks_not_run: [], limitations: [] },
    sarif: { runs: [{ invocations: [{ executionSuccessful: true }] }] },
  };
  return { id: 'synthetic/negative/clean', rule: 'synthetic', polarity: 'negative',
    expected: { forbid: ['synthetic'] }, native };
}

test('expanded check sets preserve parity without a stale fixed count', () => {
  const item = fixture(['original', 'new-check']);
  const row = evaluateCase(item, structuredClone(item.native));
  assert.deepEqual(row.errors, []);
  assert.equal(summarize([row]).supported_checks, 2);
  assert.equal(summarize([row]).full_parity, true);
});

test('missing, duplicate and substituted checks are rejected even at the same count', () => {
  const item = fixture(['original', 'new-check']);
  for (const checks of [['original'], ['original', 'original'], ['original', 'wrong-check']]) {
    const result = structuredClone(item.native);
    result.report.checks_run = checks;
    const row = evaluateCase(item, result);
    assert.ok(row.errors.includes('check_partition'));
    assert.equal(summarize([row]).full_parity, false);
  }
});

test('a failed check stays visible and cannot produce a green full profile', () => {
  const item = fixture(['original', 'new-check']);
  const result = structuredClone(item.native);
  result.report.checks_run = ['original'];
  result.report.checks_not_run = [{ check: 'new-check', reason: 'check_error: ImportError' }];
  result.sarif.runs[0].invocations[0].executionSuccessful = false;
  const row = evaluateCase(item, result);
  assert.ok(row.errors.includes('unexpected_check_failure'));
  assert.deepEqual(summarize([row]).unavailable_checks, ['new-check']);
  assert.equal(summarize([row]).full_parity, false);
});

test('an empty corpus is never a successful parity measurement', () => {
  assert.equal(summarize([]).full_parity, false);
});

test('advisory expectations check GHSA identities without requiring a CVE field', () => {
  const item = fixture(['dependencies']);
  const advisory = 'GHSA-p7fg-763f-g4gf';
  item.native.report.findings = [{ rule_id: 'dependency-cve-match', claim_evidence: { advisory_id: advisory } }];
  item.expected = { expect: [{ rule_id: 'dependency-cve-match', advisory_id: advisory }] };
  assert.equal(evaluateCase(item, item.native).expectation_passed, true);
  const missing = structuredClone(item.native);
  missing.report.findings = [];
  assert.equal(evaluateCase(item, missing).expectation_passed, false);
  item.expected = { forbid_advisories: [advisory] };
  assert.equal(evaluateCase(item, item.native).expectation_passed, false);
  assert.equal(evaluateCase(item, missing).expectation_passed, true);
});
