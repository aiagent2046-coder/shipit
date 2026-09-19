import { expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import reports from "../../../tests/fixtures/deserialization-agent.json";
import replayCases from "../../../tests/fixtures/deserialization-agent-replay.json";
import { normalizeAcquisition, normalizeDeserializationObservation, patternReview } from "./securityAgent";

const browserSource = readFileSync("../browser/src/app.js", "utf8");
const contract = browserSource.slice(browserSource.indexOf("function normalizeAcquisition("),
  browserSource.indexOf("function renderSecurityAgent(agent)"));
const [browserAcquisition, browserTrace] = runInNewContext(
  `${contract}; [normalizeAcquisition, normalizeDeserializationObservation]`, { structuredClone, sha256 });

function saved() {
  return structuredClone(reports[0].report.security_agent);
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
  expect(rows["Source fact: request input source"]).toContain("body parameter payload");
  expect(rows["Next step"]).toContain("input trust, loader options and expected object types");
  expect(rows["Missing evidence"]).toBe("input trust boundary; loader runtime contract");
  expect(rows["SQL source trace"]).toBeUndefined();
  expect(rows["SQL driver source"]).toBeUndefined();
  expect(JSON.stringify(value)).toBe(before);
});

it.each([
  { version: true }, { version: 2 }, { loader: "yaml.load" }, { method: "model_guess" },
  { source_sha256: "a".repeat(64) + "\n" }, { sink_line: true }, { sink_span: [8, 11, 8, 11] },
  { sink_span: [6, 11, 8, 31] }, { driver_status: "source_resolved" }, { input_control_status: "verified" },
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
  ["duplicate locations", (v: Saved) => { v.observations[0].acquisition.facts[1].locations!.splice(1, 0, [...v.observations[0].acquisition.facts[1].locations![0]]); }],
  ["budget expansion", (v: Saved) => { v.observations[0].acquisition.budget.max_steps = 4; }],
  ["SQL action", (v: Saved) => { v.observations[0].acquisition.attempts[1].action = "inspect_sql_slots"; }],
  ["failed locate", (v: Saved) => { v.observations[0].acquisition.attempts[0].result = "unknown"; }],
  ["missing fact production", (v: Saved) => { v.observations[0].acquisition.attempts[1].produced.pop(); }],
] as const)("rejects source/action forgery in both renderers: %s", (_, mutate) => {
  const value = saved(); mutate(value);
  const observation = value.observations[0], trace = observation.evidence.deserialization_observation;
  expect(normalizeAcquisition(observation.acquisition, trace)).toBeNull();
  expect(browserAcquisition(observation.acquisition, trace)).toBeNull();
  expectRevoked(value);
});

it("keeps budget exhaustion distinct from completed source evidence", () => {
  const value = saved(), observation = value.observations[0], record = observation.acquisition;
  Object.assign(record, { status: "partial", stop_reason: "budget_exhausted", facts: [], attempts: [] });
  record.budget.steps = 0;
  Object.assign(observation, { state: "needs_evidence", next_action: "manual_review" });
  expect(normalizeAcquisition(record, observation.evidence.deserialization_observation)).toEqual(record);
  expect(browserAcquisition(record, observation.evidence.deserialization_observation)).toEqual(record);
  // Editing a completed saved run into a partial one also invalidates its receipt.
  expectRevoked(value);
});

const renderSource = browserSource.slice(browserSource.indexOf("function renderSecurityAgent(agent)"),
  browserSource.indexOf("function renderRuleCoverage(coverage)"));
const renderBrowser = runInNewContext(`${contract}; ${renderSource}; renderSecurityAgent`, {
  structuredClone, sha256,
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
  expect(document.body.textContent).toContain("body parameter payload");
  expect(document.body.textContent).toContain("Deserialization source SHA-256");
  expect(document.body.textContent).not.toContain("SQL driver");
  value.observations[0].missing_evidence = value.observations[0].missing_evidence.filter(key => key !== gap);
  expectRevoked(value);
  renderBrowser(value);
  expect(document.body.textContent).not.toContain("body parameter payload");
  expect(document.body.textContent).toContain("needs evidence");
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

function expectRevoked(value: unknown) {
  const before = JSON.stringify(value), review = patternReview(value)!;
  expect(review.status).toBe("partial");
  expect(review.rows[0][1]).toContain("source_evidence_invalid");
  expect(review.observations).toHaveLength(1);
  const rows = Object.fromEntries(review.observations[0].rows);
  expect(rows["Source fact: request input source"]).toBeUndefined();
  expect(rows["Source fact: local input flow"]).toBeUndefined();
  expect(rows["Source investigation"]).toBeUndefined();
  expect(rows["Review state"]).toContain("Needs evidence");
  expect(rows["Missing evidence"]).toBe("request input source; local input flow; input trust boundary; loader runtime contract");
  expect(rows["Next step"]).toContain("Manual review");
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(value);
  expect(document.getElementById("security-agent-summary")!.textContent).toContain("partial");
  expect(document.body.textContent).toContain("source evidence invalid");
  expect(document.body.textContent).toContain("needs evidence");
  expect(document.body.textContent).toContain(rows["Missing evidence"]);
  expect(document.body.textContent).not.toContain("Source fact:");
  expect(document.body.textContent).not.toContain("Source investigation:");
  expect(document.body.textContent).not.toContain("records could not be displayed");
  expect(JSON.stringify(value)).toBe(before);
}

it.each(replayCases)("matches native replay validation: $name", scenario => {
  const value = saved();
  for (const change of scenario.changes) {
    let target: unknown = value;
    for (const key of change.path.slice(0, -1)) target = (target as Record<string, unknown>)[key];
    const record = target as Record<string, unknown>, key = change.path.at(-1)!;
    if ("delete" in change) delete record[key];
    else record[key] = structuredClone(change.value);
  }
  if (!scenario.valid) {
    expectRevoked(value);
    return;
  }
  const before = JSON.stringify(value), review = patternReview(value)!;
  expect(review.status).toBe(scenario.status);
  expect(review.observations).toHaveLength(1);
  const rows = Object.fromEntries(review.observations[0].rows);
  expect(rows["Source investigation"]).toContain(scenario.acquisition_status);
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(value);
  expect(document.body.textContent).toContain(rows["Source investigation"]);
  expect(document.body.textContent).not.toContain("source evidence invalid");
  if (scenario.acquisition_status === "completed") {
    expect(rows["Source fact: request input source"]).toContain("body parameter данные");
    expect(document.body.textContent).toContain("body parameter данные");
    expect(document.body.textContent).toContain("src/загрузка_🔒.py");
  } else {
    expect(rows["Missing evidence"]).toContain("request input source; local input flow");
    expect(rows["Source fact: request input source"]).toBeUndefined();
  }
  expect(JSON.stringify(value)).toBe(before);
});

it("preserves historical manual candidates without source receipts", () => {
  const value = saved(), observation = value.observations[0] as Record<string, unknown>;
  delete observation.acquisition;
  delete observation.agent_chain;
  observation.evidence = {};
  observation.state = "needs_evidence";
  observation.next_action = "manual_review";
  observation.missing_evidence = ["input_trust_boundary", "loader_runtime_contract"];
  const review = patternReview(value)!;
  expect(review.status).toBe("completed");
  expect(review.observations).toHaveLength(1);
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(value);
  expect(document.body.textContent).toContain("needs evidence");
  expect(document.body.textContent).not.toContain("source evidence invalid");
  expect(document.body.textContent).not.toContain("Source fact:");
});
