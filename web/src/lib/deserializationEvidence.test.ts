import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import reports from "../../../tests/fixtures/deserialization-agent.json";
import { normalizeAcquisition, normalizeDeserializationObservation, patternReview } from "./securityAgent";

const browserSource = readFileSync("../browser/src/app.js", "utf8");
const contract = browserSource.slice(browserSource.indexOf("function normalizeAcquisition("),
  browserSource.indexOf("function renderSecurityAgent(agent)"));
const [browserAcquisition, browserTrace] = runInNewContext(
  `${contract}; [normalizeAcquisition, normalizeDeserializationObservation]`, { structuredClone });

function saved() {
  const trace = { version: 1, method: "python_ast_import_resolved", file: "app.py", source_sha256: "a".repeat(64),
    sink_line: 8, sink_span: [8, 11, 8, 31], sink_method: "loads", loader: "pickle.loads", input_control_status: "not_checked" };
  const acquisition = { version: 2, status: "completed", stop_reason: "source_goal_reached",
    source: { file: trace.file, source_sha256: trace.source_sha256, sink_span: [...trace.sink_span] },
    facts: [
      { id: "request_input_source", method: "fastapi_ast_binding", sources: [{ parameter: "body", channel: "body", span: [7, 14, 7, 25] }] },
      { id: "local_input_flow", method: "python_ast_straight_line", locations: [[7, 14, 7, 25], [8, 24, 8, 28], [...trace.sink_span]] },
    ], attempts: [
      { action: "locate_source", result: "established", reason: "source_snapshot_matched", produced: [] as string[] },
      { action: "trace_request_input", result: "established", reason: "request_flow_established", produced: ["request_input_source", "local_input_flow"] },
    ], budget: { max_steps: 2, steps: 2, work_units: 100 },
  };
  return { version: 1, mode: "deterministic_static", status: "completed", stop_reason: "bounded_review_completed",
    runtime_verified: false, automatic_patch: false, plan: [], budget: {}, observations: [{
      id: "b".repeat(64), pattern_id: "python-unsafe-deserialization", pattern_revision: 2,
      rule_id: "unsafe-deserialization", file: trace.file, line: trace.sink_line,
      state: "source_evidence_collected", next_action: "review_runtime_contract",
      recipe: { automatic_apply: false, status: "not_available" },
      missing_evidence: ["input_trust_boundary", "loader_runtime_contract"],
      evidence: { deserialization_observation: trace }, acquisition,
    }] };
}

it("replays source evidence with identical strict browser and web validation", () => {
  const value = saved(), observation = value.observations[0], before = JSON.stringify(value);
  const trace = observation.evidence.deserialization_observation;
  expect(normalizeDeserializationObservation(trace)).toEqual(trace);
  expect(browserTrace(trace)).toEqual(trace);
  expect(normalizeAcquisition(observation.acquisition, trace)).toEqual(observation.acquisition);
  expect(browserAcquisition(observation.acquisition, trace)).toEqual(observation.acquisition);
  const rows = Object.fromEntries(patternReview(value)!.observations[0].rows);
  expect(rows["Deserialization source SHA-256"]).toBe(trace.source_sha256);
  expect(rows["Source fact: request input source"]).toContain("body parameter body");
  expect(rows["Next step"]).toContain("input trust, loader options and expected object types");
  expect(rows["Missing evidence"]).toBe("input trust boundary; loader runtime contract");
  expect(rows["SQL source trace"]).toBeUndefined();
  expect(rows["SQL driver source"]).toBeUndefined();
  expect(JSON.stringify(value)).toBe(before);
});

it.each([
  { version: true }, { version: 2 }, { loader: "yaml.load" }, { method: "model_guess" },
  { source_sha256: "a".repeat(64) + "\n" }, { sink_line: true }, { sink_span: [8, 11, 8, 11] },
  { sink_span: [7, 11, 8, 31] }, { driver_status: "source_resolved" }, { input_control_status: "verified" },
])("rejects forged deserialization traces consistently: %j", invalid => {
  const observation = saved().observations[0], trace = { ...observation.evidence.deserialization_observation, ...invalid };
  expect(normalizeDeserializationObservation(trace)).toBeNull();
  expect(browserTrace(trace)).toBeNull();
  expect(normalizeAcquisition(observation.acquisition, trace)).toBeNull();
  expect(browserAcquisition(observation.acquisition, trace)).toBeNull();
});

type Saved = ReturnType<typeof saved>;
it.each([
  ["SQL schema version", (v: Saved) => { v.observations[0].acquisition.version = 1; }],
  ["another file", (v: Saved) => { v.observations[0].acquisition.source.file = "other.py"; }],
  ["another hash", (v: Saved) => { v.observations[0].acquisition.source.source_sha256 = "c".repeat(64); }],
  ["another call on the same line", (v: Saved) => { v.observations[0].acquisition.source.sink_span[1]++; }],
  ["query channel", (v: Saved) => { v.observations[0].acquisition.facts[0].sources![0].channel = "query"; }],
  ["multiple origins", (v: Saved) => { v.observations[0].acquisition.facts[0].sources!.push({ parameter: "other", channel: "body", span: [7, 27, 7, 38] }); }],
  ["flow without origin", (v: Saved) => { v.observations[0].acquisition.facts[1].locations!.shift(); }],
  ["flow without sink", (v: Saved) => { v.observations[0].acquisition.facts[1].locations!.pop(); }],
  ["duplicate locations", (v: Saved) => { v.observations[0].acquisition.facts[1].locations!.splice(1, 0, [7, 14, 7, 25]); }],
  ["budget expansion", (v: Saved) => { v.observations[0].acquisition.budget.max_steps = 4; }],
  ["SQL action", (v: Saved) => { v.observations[0].acquisition.attempts[1].action = "inspect_sql_slots"; }],
  ["failed locate", (v: Saved) => { v.observations[0].acquisition.attempts[0].result = "unknown"; }],
  ["missing fact production", (v: Saved) => { v.observations[0].acquisition.attempts[1].produced.pop(); }],
] as const)("rejects source/action forgery in both renderers: %s", (_, mutate) => {
  const value = saved(); mutate(value);
  const observation = value.observations[0], trace = observation.evidence.deserialization_observation;
  expect(normalizeAcquisition(observation.acquisition, trace)).toBeNull();
  expect(browserAcquisition(observation.acquisition, trace)).toBeNull();
  expect(patternReview(value)!.observations).toEqual([]);
});

it("keeps budget exhaustion distinct from completed source evidence", () => {
  const value = saved(), observation = value.observations[0], record = observation.acquisition;
  Object.assign(record, { status: "partial", stop_reason: "budget_exhausted", facts: [], attempts: [] });
  record.budget.steps = 0;
  Object.assign(observation, { state: "needs_evidence", next_action: "manual_review" });
  expect(normalizeAcquisition(record, observation.evidence.deserialization_observation)).toEqual(record);
  expect(browserAcquisition(record, observation.evidence.deserialization_observation)).toEqual(record);
  expect(Object.fromEntries(patternReview(value)!.observations[0].rows)["Source investigation"]).toContain("partial; budget exhausted");
});

const renderSource = browserSource.slice(browserSource.indexOf("function renderSecurityAgent(agent)"),
  browserSource.indexOf("function renderRuleCoverage(coverage)"));
const renderBrowser = runInNewContext(`${contract}; ${renderSource}; renderSecurityAgent`, {
  structuredClone,
  byId: (id: string) => document.getElementById(id),
  text: (value: unknown, fallback = "Not reported") => typeof value === "string" && value ? value : fallback,
  node: (tag: string, content?: string) => { const el = document.createElement(tag); el.textContent = content ?? ""; return el; },
  renderDefinitions: (container: HTMLElement, rows: [string, string][]) => {
    for (const [key, value] of rows) { const el = document.createElement("p"); el.textContent = `${key}: ${value}`; container.append(el); }
  },
});

it.each(["input_trust_boundary", "loader_runtime_contract"])("cannot erase the remaining runtime prerequisite %s", gap => {
  const value = saved();
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(value);
  expect(document.body.textContent).toContain("body parameter body");
  expect(document.body.textContent).toContain("Deserialization source SHA-256");
  expect(document.body.textContent).not.toContain("SQL driver");
  value.observations[0].missing_evidence = value.observations[0].missing_evidence.filter(key => key !== gap);
  expect(patternReview(value)!.observations).toEqual([]);
  renderBrowser(value);
  expect(document.body.textContent).not.toContain("body parameter body");
  expect(document.body.textContent).toContain("1 records could not be displayed");
});


it.each(reports)("replays the real $name scanner report in web and standalone browser", ({ report, name }) => {
  const before = JSON.stringify(report), agent = report.security_agent;
  const review = patternReview(agent)!;
  expect(review.observations).toHaveLength(agent.observations.length);
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(agent);
  expect(document.body.textContent).toContain("input trust boundary");
  expect(document.body.textContent).toContain("loader runtime contract");
  expect(document.body.textContent).not.toContain("SQL driver");
  expect(document.body.textContent).not.toContain("records could not be displayed");
  if (name === "completed") {
    expect(document.body.textContent).toContain("body parameter payload");
    expect(Object.fromEntries(review.observations[0].rows)["Source investigation"]).toContain("completed");
  } else {
    expect(document.body.textContent).not.toContain("body parameter payload");
    expect(Object.fromEntries(review.observations[0].rows)["Source investigation"]).toContain("unsupported");
  }
  expect(JSON.stringify(report)).toBe(before);
});
