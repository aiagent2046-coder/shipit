import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import reports from "../../../tests/fixtures/security-agent-reports.json";
import { claimEvidenceRows, manifestRows, nonModelStatusNotices } from "./evidence";
import { acquisitionRows, normalizeAcquisition, normalizeSyntheticContract, syntheticContractRows, patternReview, sqlEvidenceRows } from "./securityAgent";
import type { Finding, Score } from "./types";

const browserSource = readFileSync("../browser/src/app.js", "utf8");
const browserContract = browserSource.slice(browserSource.indexOf("function normalizeAcquisition("),
  browserSource.indexOf("function renderSecurityAgent(agent)"));
const [browserNormalizeAcquisition, browserAcquisitionRows] = runInNewContext(
  `${browserContract}; [normalizeAcquisition, acquisitionRows]`, { structuredClone });

const completed = reports.find(report => report.name === "completed")!;
const record = completed.score.scan_manifest.security_agent;
const finding = completed.finding as unknown as Finding;

it.each(reports)("preserves the saved $name scan and explains the bounded review", report => {
  const before = JSON.stringify(report);
  const score = report.score as unknown as Score;
  const saved = report.score.scan_manifest.security_agent;
  const review = patternReview(saved)!;
  expect(review.status).toBe(saved.status);
  expect(review.observations).toHaveLength(saved.observations.length);
  expect(score.scan_manifest!.model_calls).toBe(0);
  const rows = Object.fromEntries(manifestRows(score));
  expect(rows["Pattern review"]).toContain(saved.stop_reason);
  expect(rows["Pattern review"]).toContain("Completion describes bounded review, not project safety.");
  if (saved.catalog) expect(rows["Pattern catalog"]).toContain(saved.catalog.sha256);
  expect(nonModelStatusNotices(score).filter(([label]) => label === "Pattern review incomplete"))
    .toHaveLength(saved.status === "completed" ? 0 : 1);
  expect(JSON.stringify(nonModelStatusNotices(score))).not.toMatch(/security_agent_(incomplete|unavailable)/);
  const evidence = Object.fromEntries(claimEvidenceRows(report.finding as unknown as Finding));
  expect(evidence["Static observation — unverified"]).toBe(report.finding.claim_evidence.observation);
  expect(evidence["Model interpretation — unverified"]).toBeUndefined();
  expect(evidence["SQL source trace"]).toBe("concatenation at line 2 → execute() at line 3. Possible local flow; "
    + "input control and runtime behavior were not checked.");
  expect(evidence["SQL source SHA-256"]).toBe(report.finding.claim_evidence.sql_observation.source_sha256);
  for (const observation of review.observations) {
    const detail = Object.fromEntries(observation.rows);
    expect(detail["Candidate weakness classes"]).toContain("CWE-89");
    expect(detail["Missing evidence"]).toContain("psycopg3 cursor provenance");
    expect(detail["SQL source trace"]).toBe(evidence["SQL source trace"]);
    expect(detail["Repair guidance"]).toContain(saved.observations[0].recipe.id);
  }
  expect(JSON.stringify(report)).toBe(before);
});

it.each([
  ["version", 2], ["runtime_verified", true], ["automatic_patch", true],
  ["mode", "model"], ["status", "verified"], ["budget", []], ["observations", {}], ["plan", null],
])("does not present unsupported or stronger review metadata: %s", (field, value) => {
  expect(patternReview({ ...record, [field as string]: value })).toBeNull();
});

it.each([
  { state: "verified" }, { next_action: "automatic_patch" }, { line: true }, { file: [] },
  { recipe: null }, { recipe: { ...record.observations[0].recipe, automatic_apply: true } },
  { recipe: { ...record.observations[0].recipe, status: "verified" } },
])("retains the review summary and marks an unsupported observation as undisplayed: %j", invalid => {
  const review = patternReview({ ...record, observations: [{ ...record.observations[0], ...invalid }] })!;
  expect(review.status).toBe("completed");
  expect(review.observations).toEqual([]);
  expect(Object.fromEntries(review.rows)["Observation display incomplete"])
    .toBe("1 records could not be displayed within the supported schema and limit.");
});

it("does not echo a stored exception message or retrieve newer repair instructions", () => {
  const old = { ...record, stop_reason: "agent_error: ValueError: private credentials", observations: [{
    ...record.observations[0], recipe: { status: "manual_guidance", automatic_apply: false, id: "historical-recipe" },
  }] };
  const review = patternReview(old)!;
  expect(JSON.stringify(review)).not.toContain("private credentials");
  expect(Object.fromEntries(review.rows)["Pattern review"]).toContain("Stop reason not recorded");
  expect(Object.fromEntries(review.observations[0].rows)["Repair guidance"]).toContain("historical-recipe");
  expect(JSON.stringify(review)).not.toContain(record.observations[0].recipe.id);
});

it.each([
  { version: 2 }, { file: "another.py" }, { sink_line: 4 }, { assembly_line: true },
  { method: "model_flow" }, { source_sha256: "missing" }, { driver_status: "verified" },
  { input_control_status: "verified" }, { flow_status: "confirmed" },
])("does not display unsupported or mismatched SQL evidence: %j", invalid => {
  const trace = { ...completed.finding.claim_evidence.sql_observation, ...invalid };
  const changed = { ...finding, claim_evidence: { ...finding.claim_evidence!, sql_observation: trace } };
  expect(sqlEvidenceRows(changed)).toEqual([]);
  expect(Object.fromEntries(claimEvidenceRows(changed))["Static observation — unverified"])
    .toBe(finding.claim_evidence!.observation);
  const review = patternReview({ ...record, observations: [{ ...record.observations[0], evidence: {
    sql_observation: trace,
  } }] })!;
  expect(Object.fromEntries(review.observations[0].rows)["SQL source trace"]).toBeUndefined();
});

it.each([
  ["llm", "llm-security", "Model interpretation — unverified"],
  [undefined, "llm-security", "Model interpretation — unverified"],
  ["dependency", "dependency-cve-match", "Source observation — unverified"],
  [undefined, "old-rule", "Legacy observation — provenance not recorded"],
])("labels the recorded producer without importing a static SQL trace: %s", (source, rule, label) => {
  const changed = { ...finding, source, rule_id: rule } as Finding;
  const rows = Object.fromEntries(claimEvidenceRows(changed));
  expect(rows[label!]).toBe(finding.claim_evidence!.observation);
  expect(rows["SQL source trace"]).toBeUndefined();
  expect(rows["Consequence check"]).toBe("No independent verification recorded.");
});

it("leaves legacy findings readable without inventing a trace or review", () => {
  const changed = structuredClone(finding);
  delete changed.claim_evidence!.sql_observation;
  expect(sqlEvidenceRows(changed)).toEqual([]);
  expect(patternReview(undefined)).toBeNull();
  expect(Object.fromEntries(claimEvidenceRows(changed))["Static observation — unverified"])
    .toBe(finding.claim_evidence!.observation);
});

const driverTrace = {
  ...completed.finding.claim_evidence.sql_observation, version: 2, driver_status: "source_resolved",
  driver_provenance: { version: 1, driver: "psycopg3", method: "python_ast_straight_line",
    import_line: 1, connection_line: 2, cursor_line: 2 },
};

it("shows the source driver chain in findings and pattern decisions without runtime proof", () => {
  const changed = { ...finding, claim_evidence: { ...finding.claim_evidence!, sql_observation: driverTrace } };
  const rows = Object.fromEntries(sqlEvidenceRows(changed));
  expect(rows["SQL driver source"]).toContain("import line 1 → connect() line 2 → cursor() line 2");
  expect(rows["SQL driver source"]).toContain("installed driver and runtime behavior are unverified");
  const observation = record.observations[0];
  const review = patternReview({ ...record, observations: [{ ...observation,
    evidence: { sql_observation: driverTrace },
    missing_evidence: observation.missing_evidence.filter(key => key !== "psycopg3_cursor_provenance"),
  }] })!;
  const details = Object.fromEntries(review.observations[0].rows);
  expect(details["SQL driver source"]).toBe(rows["SQL driver source"]);
  expect(details["Missing evidence"]).not.toContain("psycopg3 cursor provenance");
  expect(details["Missing evidence"]).toContain("attacker control");
  expect(details["Review state"]).toContain("Needs evidence");
  expect(details["Repair guidance"]).toContain("No automatic patch applied");
});

it.each([
  { driver_status: "unknown" }, { version: 1 }, { version: 3 },
  { driver_provenance: null }, { driver_provenance: { ...driverTrace.driver_provenance, version: true } },
  { driver_provenance: { ...driverTrace.driver_provenance, import_line: 0 } },
  { driver_provenance: { ...driverTrace.driver_provenance, connection_line: 3 } },
  { driver_provenance: { ...driverTrace.driver_provenance, cursor_line: 4 } },
  { driver_provenance: { ...driverTrace.driver_provenance, driver: "psycopg2" } },
])("rejects contradictory or malformed driver proof: %j", invalid => {
  expect(sqlEvidenceRows({ ...finding, claim_evidence: { ...finding.claim_evidence!,
    sql_observation: { ...driverTrace, ...invalid } } })).toEqual([]);
});

it("keeps unknown and historical driver evidence distinguishable", () => {
  const trace = { ...completed.finding.claim_evidence.sql_observation, version: 2, driver_status: "unknown" };
  expect(Object.fromEntries(sqlEvidenceRows({ ...finding, claim_evidence: { ...finding.claim_evidence!,
    sql_observation: trace } }))["SQL driver source"]).toContain("Unknown");
  expect(Object.fromEntries(sqlEvidenceRows(finding))["SQL driver source"]).toContain("historical report");
});

function sourceAcquisition() {
  return {
    version: 1, status: "completed", stop_reason: "source_goal_reached",
    source: { file: driverTrace.file, source_sha256: driverTrace.source_sha256, sink_span: [3, 0, 3, 32] },
    facts: [
      { id: "request_input_source", method: "fastapi_ast_binding", sources: [{ parameter: "user_id", channel: "query", span: [2, 4, 2, 16] }] },
      { id: "local_input_flow", method: "python_ast_straight_line", locations: [[2, 4, 2, 16], [3, 18, 3, 25]] },
      { id: "sql_value_position", method: "postgresql_ast_slot_context", slots: [{ index: 0, role: "value" }] },
      { id: "value_constraints", method: "python_ast_constraints", constraints: [{ slot: 0, kind: "declared_type", type: "str", span: [2, 13, 2, 16] }] },
    ],
    attempts: [
      { action: "locate_source", result: "established", reason: "source_snapshot_matched", produced: [] },
      { action: "trace_request_input", result: "established", reason: "request_flow_established", produced: ["request_input_source", "local_input_flow"] },
      { action: "inspect_sql_slots", result: "established", reason: "sql_value_positions_established", produced: ["sql_value_position"] },
      { action: "collect_value_constraints", result: "established", reason: "value_constraints_recorded", produced: ["value_constraints"] },
    ], budget: { max_steps: 4, steps: 4, work_units: 100 },
  };
}

function acquiredReview(acquisition: unknown) {
  return { ...record, observations: [{ ...record.observations[0], evidence: { sql_observation: driverTrace },
    state: "source_evidence_collected", next_action: "review_runtime_contract", acquisition,
    missing_evidence: ["runtime_reachability", "attacker_control", "expected_query_contract"],
  }] };
}

it("reports dependent evidence actions and the remaining runtime contract", () => {
  const saved = acquiredReview(sourceAcquisition()), before = JSON.stringify(saved);
  const review = patternReview(saved)!;
  const rows = Object.fromEntries(review.observations[0].rows);
  expect(rows["Review state"]).toContain("Supported source evidence collected");
  expect(rows["Next step"]).toContain("Review the runtime contract");
  expect(rows["Source fact: request input source"]).toContain("query parameter user_id");
  expect(rows["Investigation: Trace request input"]).toContain("established");
  expect(rows["Missing evidence"]).toContain("attacker control");
  expect(rows["Source investigation"]).toContain("runtime exploitability and repair behavior remain unverified");
  expect(JSON.stringify(saved)).toBe(before);
});

// Keep this corpus aligned with tests/test_evidence_record.py. It covers Python
// identifiers, code-point bounds and Unicode forms that JS otherwise accepts.
it.each(["имя", "变量", "é", "e\u0301", "_данные2", "℘", "ᢅ", "a·", "𐐀".repeat(128), "a".repeat(128)])(
  "preserves Unicode Python input identifiers in both renderers: %s", parameter => {
    const value = sourceAcquisition();
    value.facts[0].sources![0].parameter = parameter;
    expect(normalizeAcquisition(value, driverTrace)).toEqual(value);
    expect(browserNormalizeAcquisition(value, driverTrace)).toEqual(value);
    const rows = Object.fromEntries(patternReview(acquiredReview(value))!.observations[0].rows);
    expect(rows["Source fact: request input source"]).toContain(`query parameter ${parameter} at line 2`);
    expect(browserAcquisitionRows(value, driverTrace)).toEqual(acquisitionRows(value, driverTrace));
  });

it.each(["", "2name", "name\n", "name\r", "a\u200c", "a\u200d", "😀", "a".repeat(129),
  "𐐀".repeat(129), "\u0301name", "<script>"])("rejects invalid or oversized input identifiers: %s", parameter => {
  const value = sourceAcquisition();
  value.facts[0].sources![0].parameter = parameter;
  expect(normalizeAcquisition(value, driverTrace)).toBeNull();
  expect(browserNormalizeAcquisition(value, driverTrace)).toBeNull();
  expect(patternReview(acquiredReview(value))!.observations).toHaveLength(0);
});

it("keeps diagnostic names ASCII when source identifiers are Unicode", () => {
  const value = sourceAcquisition();
  Object.assign(value.attempts[1], { detail: "имя" });
  expect(normalizeAcquisition(value, driverTrace)).toBeNull();
  expect(browserNormalizeAcquisition(value, driverTrace)).toBeNull();
});

it.each([
  (v: ReturnType<typeof sourceAcquisition>) => { v.source.file = "another.py"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.source.source_sha256 = "b".repeat(64); },
  (v: ReturnType<typeof sourceAcquisition>) => { v.source.sink_span = [3, 32, 3, 0]; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.status = "verified"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.stop_reason = "collector_error: private SQL"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[0].method = "model_guess"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[0].sources![0].parameter = "<script>"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[1].locations = Array(129).fill([2, 0, 2, 1]); },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[2].slots![0].role = "identifier"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[2].slots![0].index = 1; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[3].constraints![0].slot = 1; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.facts[3].constraints![0].kind = "int_conversion"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.attempts[1].produced = []; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.attempts[1].reason = "request_flow_not_established"; },
  (v: ReturnType<typeof sourceAcquisition>) => { v.attempts.reverse(); },
  (v: ReturnType<typeof sourceAcquisition>) => { v.budget.steps = 3; },
])("rejects forged acquisitions in web and browser without promoting the review %#", mutate => {
  const value = sourceAcquisition(); mutate(value);
  expect(normalizeAcquisition(value, driverTrace)).toBeNull();
  expect(browserNormalizeAcquisition(value, driverTrace)).toBeNull();
  const review = patternReview(acquiredReview(value))!;
  expect(review.observations).toHaveLength(0);
  expect(Object.fromEntries(review.rows)["Observation display incomplete"]).toContain("1 records");
});

it("keeps the standalone browser acquisition contract aligned with web rendering", () => {
  const value = sourceAcquisition();
  expect(browserNormalizeAcquisition(value, driverTrace)).toEqual(normalizeAcquisition(value, driverTrace));
  expect(browserAcquisitionRows(value, driverTrace)).toEqual(acquisitionRows(value, driverTrace));
  expect(normalizeAcquisition(value, { ...driverTrace, driver_status: "unknown" })).toBeNull();
  expect(browserNormalizeAcquisition(value, { ...driverTrace, driver_status: "unknown" })).toBeNull();
  value.status = "unsupported"; value.stop_reason = "no_further_action";
  value.facts.splice(2, 1);
  value.attempts[2] = { action: "inspect_sql_slots", result: "unknown", reason: "sql_slots_not_established", produced: [] };
  const unknown: Record<string, unknown> = { ...driverTrace, driver_status: "unknown" };
  delete unknown.driver_provenance;
  expect(normalizeAcquisition(value, unknown)).not.toBeNull();
  expect(browserNormalizeAcquisition(value, unknown)).toEqual(normalizeAcquisition(value, unknown));
});

it("retains the aggregate reason when evidence acquisition is incomplete", () => {
  const review = patternReview({ ...record, status: "partial", stop_reason: "evidence_collection_incomplete" })!;
  expect(Object.fromEntries(review.rows)["Pattern review"]).toContain("evidence_collection_incomplete");
});

function syntheticReview() {
  const source = acquiredReview(sourceAcquisition());
  const observation = { ...source.observations[0], state: "synthetic_recipe_verified", next_action: "review_project_runtime_contract",
    missing_evidence: ["runtime_behavior_contract", "intended_value_type", "caller_authorization", "route_reachability"] };
  const synthetic_contract = {
    version: 1, scope: "synthetic_recipe", contract_id: "sql-value-parameterization-python-psycopg3", contract_revision: 1,
    status: "passed", reason: "synthetic_contract_passed", evidence_sha256: "d".repeat(64), synthetic_recipe_verified: true,
    runtime_verified: false, customer_project_verified: false, automatic_patch: false, reused: false,
    source: { archive_sha256: source.source.archive_sha256, source_sha256: driverTrace.source_sha256,
      observation_id: observation.id, engine_version: source.source.engine_version, catalog_sha256: source.catalog!.sha256 },
    proof: { fixture_sha256: "8c856f7ededaa7fc4bf8c8cbb56819a30eb3f9553209e222e13ad7e4926b9517",
      schema_sha256: "9ca4174618e52ccbafebba9d1b5b6151f6ecdd1d5c67ba9f3b7f4706e2ff91a2", psycopg_version: "3.3.5",
      postgresql_version: 170011, executions: 27, cases_per_stage: 9, before_row_ids: [1, 2, 3, 4, 5, 6, 7, 8, 9],
      after_row_ids: [9], mutation_row_ids: [1, 2, 3, 4, 5, 6, 7, 8, 9], rollback_completed: true, temporary_table_absent: true },
  };
  return { ...source, mode: "deterministic_evidence", observations: [{ ...observation, synthetic_contract }] };
}

const [browserNormalizeSynthetic, browserSyntheticRows] = runInNewContext(
  `${browserContract}; [normalizeSyntheticContract, syntheticContractRows]`, { structuredClone });

it("displays saved synthetic controls without upgrading customer project verification", () => {
  const saved = syntheticReview(), before = JSON.stringify(saved), observation = saved.observations[0];
  const normalized = normalizeSyntheticContract(observation.synthetic_contract, observation, saved.source, saved.catalog)!;
  expect(normalized).toEqual(observation.synthetic_contract);
  expect(browserNormalizeSynthetic(observation.synthetic_contract, observation, saved.source, saved.catalog)).toEqual(normalized);
  expect(browserSyntheticRows(normalized)).toEqual(syntheticContractRows(normalized));
  const review = patternReview(saved)!, rows = Object.fromEntries(review.observations[0].rows);
  expect(rows["Synthetic recipe contract"]).toContain("Saved synthetic evidence: passed");
  expect(rows["Before / after / mutation"]).toContain("9 / 1 / 9");
  expect(rows["Fixture cleanup"]).toContain("rollback");
  expect(rows["Review state"]).toContain("customer project runtime behavior and repair preconditions remain unverified");
  expect(rows["Customer project verification"]).toContain("Customer project runtime tests not run");
  expect(rows["Next step"]).toContain("Review the customer project runtime contract");
  expect(rows["Missing evidence"]).toContain("runtime behavior contract");
  expect(Object.fromEntries(review.rows)["Verification and changes"]).toContain("Customer project runtime tests not run");
  expect(JSON.stringify(saved)).toBe(before);
});

type SyntheticReview = ReturnType<typeof syntheticReview>;
it.each([
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.scope = "customer_project"; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.runtime_verified = true; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.customer_project_verified = true; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.automatic_patch = true; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.evidence_sha256 += "\n"; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.fixture_sha256 = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.schema_sha256 = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.before_row_ids = []; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.after_row_ids = [1]; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.mutation_row_ids = [9]; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.executions = 26; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.rollback_completed = false; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.temporary_table_absent = false; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.psycopg_version = "3.٣.٥"; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.proof.postgresql_version = 1; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.source.archive_sha256 = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.source.source_sha256 = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.source.observation_id = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.source.catalog_sha256 = "b".repeat(64); },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.source.engine_version += "-other"; },
  (v: SyntheticReview) => { v.observations[0].synthetic_contract.reason = "private error text"; },
  (v: SyntheticReview) => { v.observations[0].missing_evidence.pop(); },
  (v: SyntheticReview) => { v.observations[0].acquisition = { ...sourceAcquisition(), status: "unsupported" }; },
  (v: SyntheticReview) => { v.observations[0].evidence.sql_observation.sink_method = "executemany"; },
  (v: SyntheticReview) => { v.observations[0].recipe = { ...v.observations[0].recipe, id: "another-recipe" }; },
])("rejects inconsistent synthetic proof across both renderers %#", mutate => {
  const saved = structuredClone(syntheticReview()); mutate(saved);
  const observation = saved.observations[0];
  expect(normalizeSyntheticContract(observation.synthetic_contract, observation, saved.source, saved.catalog)).toBeNull();
  expect(browserNormalizeSynthetic(observation.synthetic_contract, observation, saved.source, saved.catalog)).toBeNull();
  const review = patternReview(saved)!;
  expect(review.observations).toHaveLength(0);
  expect(JSON.stringify(review)).not.toContain("Saved synthetic evidence: passed");
});

it.each(["failed", "unavailable"])("keeps %s synthetic attempts distinct from passed recipe evidence", status => {
  const saved = syntheticReview(), observation = saved.observations[0];
  Object.assign(observation, { state: "source_evidence_collected", next_action: "review_runtime_contract" });
  Object.assign(observation.synthetic_contract, { status, reason: status === "failed" ? "synthetic_contract_failed" : "execution_timeout",
    synthetic_recipe_verified: false, proof: null });
  const normalized = normalizeSyntheticContract(observation.synthetic_contract, observation, saved.source, saved.catalog)!;
  expect(normalized).not.toBeNull();
  expect(browserNormalizeSynthetic(observation.synthetic_contract, observation, saved.source, saved.catalog)).toEqual(normalized);
  const rows = Object.fromEntries(patternReview(saved)!.observations[0].rows);
  expect(rows["Synthetic recipe contract"]).toContain(`Saved synthetic evidence: ${status}`);
  expect(rows["Before / after / mutation"]).toBeUndefined();
  expect(rows["Review state"]).toContain("Supported source evidence collected");
  expect(rows["Customer project verification"]).toContain("No automatic patch applied");
});

it("renders the synthetic state in the standalone browser and hides inconsistent proof", () => {
  const markup = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  const renderSource = browserSource.slice(browserSource.indexOf("function renderSecurityAgent(agent)"),
    browserSource.indexOf("function renderRuleCoverage(coverage)"));
  const render = runInNewContext(`${browserContract}; ${renderSource}; renderSecurityAgent`, {
    structuredClone,
    byId: (id: string) => document.getElementById(id),
    text: (value: unknown, fallback = "Not reported") => typeof value === "string" && value ? value : fallback,
    node: (tag: string, content?: string) => { const el = document.createElement(tag); el.textContent = content ?? ""; return el; },
    renderDefinitions: (container: HTMLElement, rows: [string, string][]) => {
      for (const [key, value] of rows) { const el = document.createElement("p"); el.textContent = `${key}: ${value}`; container.append(el); }
    },
  });
  document.body.innerHTML = markup;
  const saved = syntheticReview(); render(saved);
  expect(document.getElementById("security-agent-details")!.hidden).toBe(false);
  expect(document.body.textContent).toContain("Saved synthetic evidence: passed");
  expect(document.body.textContent).toContain("Customer project runtime tests not run");
  expect(document.body.textContent).toContain("Review the customer project runtime contract");
  saved.observations[0].synthetic_contract.proof.after_row_ids = [];
  render(saved);
  expect(document.body.textContent).not.toContain("Saved synthetic evidence: passed");
  expect(document.body.textContent).toContain("1 records could not be displayed");
});
