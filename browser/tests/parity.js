// Findings compared as a multiset, including multiplicity and locations.
// Native WASM wheels must preserve the entire report, including advice guards.
const identity = f => JSON.stringify([f.rule_id, f.file, f.line ?? null, f.severity,
  f.confidence, f.title, f.explanation ?? '', f.masked ?? null]);
const findingsKey = findings => findings.map(identity).sort().join('\n');
const canonical = value => JSON.stringify(normalize(value));
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, normalize(value[k])]));
  return value;
}
export function assertParserParity(expected, actual) {
  if (canonical(expected) !== canonical(actual)) throw new Error('Native parser Unicode/AST parity mismatch');
}

export function evaluateCase(item, result) {
  if (!result.report || !result.sarif) return { id: item.id, error: 'scan_did_not_complete' };
  const { report, sarif } = result;
  const findings = report.findings;
  const failures = report.checks_not_run;
  const errors = [];
  if (canonical(result) !== canonical(item.native)) errors.push('native_profile_mismatch');
  const checks = [...report.checks_run, ...failures.map(f => f.check)];
  const expectedChecks = [...item.native.report.checks_run,
    ...item.native.report.checks_not_run.map(f => f.check)];
  if (new Set(checks).size !== checks.length ||
      canonical([...checks].sort()) !== canonical([...expectedChecks].sort())) errors.push('check_partition');
  if (failures.length) {
    errors.push('unexpected_check_failure');
  }
  if (sarif.runs[0].invocations[0].executionSuccessful !== true) errors.push('sarif_execution_failure');
  if (report.limitations.includes('recommendation_enrichment_unavailable')) errors.push('advice_guards_missing');
  // A browser must never invent additional findings due to a failed parser.
  const remaining = item.native.report.findings.map(identity);
  for (const f of findings) {
    const at = remaining.indexOf(identity(f));
    if (at < 0) errors.push('extra_or_changed_finding');
    else remaining.splice(at, 1);
  }
  const matches = (f, want) => Object.entries(want).every(([key, value]) =>
    key === 'count' || (key === 'cve_id' ? f.claim_evidence?.cve_id === value :
      key === 'file_endswith' ? f.file?.endsWith(value) : f[key] === value));
  const expectationPassed = (item.expected.expect || []).every(want => {
    const n = findings.filter(f => matches(f, want)).length;
    return n > 0 && (want.count === undefined || n === want.count);
  }) && (item.expected.forbid || []).every(rule => !findings.some(f => f.rule_id === rule))
    && (item.expected.forbid_cves || []).every(cve => !findings.some(f => f.claim_evidence?.cve_id === cve));
  return { id: item.id, rule: item.rule, polarity: item.polarity,
    expectation_passed: expectationPassed,
    finding_parity: findingsKey(findings) === findingsKey(item.native.report.findings),
    browser_findings: findings.length, native_findings: item.native.report.findings.length,
    checks_run: report.checks_run, checks_not_run: failures.map(f => f.check), errors };
}

export function summarize(rows) {
  return { cases: rows.length,
    expectation_passed: rows.filter(r => r.expectation_passed).length,
    finding_parity: rows.filter(r => r.finding_parity).length,
    unexpected_failures: rows.filter(r => r.error || r.errors?.length).length,
    supported_checks: rows.length ? rows[0].checks_run?.length ?? 0 : 0,
    unavailable_checks: [...new Set(rows.flatMap(r => r.checks_not_run ?? []))],
    full_parity: rows.length > 0 && rows.every(r => !r.error && !r.errors.length && r.finding_parity && r.expectation_passed) };
}
