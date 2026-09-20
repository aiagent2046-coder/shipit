import { expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import reports from "../../../tests/fixtures/deserialization-file-agent.json";
import savedRecords from "../../../tests/fixtures/deserialization-file-record.json";
import { normalizeAcquisition, normalizeDeserializationObservation, patternReview } from "./securityAgent";

const browserSource = readFileSync("../browser/src/app.js", "utf8");
const contract = browserSource.slice(browserSource.indexOf("function normalizeAcquisition("),
  browserSource.indexOf("function renderSecurityAgent(agent)"));
const [browserAcquisition, browserTrace] = runInNewContext(
  `${contract}; [normalizeAcquisition, normalizeDeserializationObservation]`, { structuredClone, sha256 });
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
function browserText(agent: unknown) {
  document.body.innerHTML = '<details id="security-agent-details"><summary id="security-agent-summary"></summary><div id="security-agent"></div></details>';
  renderBrowser(agent);
  return document.body.textContent!;
}

it.each(reports)("replays the $name scanner file report without inventing request input or trust", ({ report, name }) => {
  const agent = report.security_agent, before = JSON.stringify(report), review = patternReview(agent)!;
  expect(review.observations).toHaveLength(2);
  expect(review.status).toBe(agent.status);
  const rendered = browserText(agent);
  expect(rendered).not.toContain("body parameter");
  expect(rendered).not.toContain("SQL driver");
  expect(rendered).not.toContain("pickle.loads()");
  expect(rendered).not.toContain("records could not be displayed");
  for (const [index, observation] of agent.observations.entries()) {
    const trace = observation.evidence.deserialization_observation;
    expect(normalizeDeserializationObservation(trace)).toEqual(trace);
    expect(browserTrace(trace)).toEqual(trace);
    expect(normalizeAcquisition(observation.acquisition, trace)).toEqual(observation.acquisition);
    expect(browserAcquisition(observation.acquisition, trace)).toEqual(observation.acquisition);
    const rows = Object.fromEntries(review.observations[index].rows);
    expect(rows["Deserialization source trace"]).toContain(`pickle.load() at line ${observation.line}`);
    expect(rows["Missing evidence"]).toContain("Calling code and origin of the file (not checked)");
    expect(rows["Missing evidence"]).toContain("input trust boundary; loader runtime contract");
    expect(rows["Source fact: request input source"]).toBeUndefined();
    if (name === "completed") {
      expect(rows["Source fact: file input source"]).toContain(`Function ${index ? "read_secondary" : "read_primary"}`);
      expect(rows["Source fact: file input source"]).toContain('open(..., "rb")');
      expect(rows["Source fact: file input source"]).toContain("input trust were not established");
      expect(rows["Next step"]).toContain("Review caller-supplied paths and file producers");
      expect(rows["Next step"]).toContain("reject unsupported serialization formats");
      expect(rendered).toContain(rows["Source fact: file input source"]);
      expect(rendered).toContain(rows["Next step"]);
    } else {
      expect(rows["Source fact: file input source"]).toBeUndefined();
      expect(rows["Review state"]).toContain("Needs evidence");
      expect(rendered).not.toContain("Source fact: file input source");
    }
  }
  expect(JSON.stringify(report)).toBe(before);
});

type Change = { path: (string | number)[]; value?: unknown; delete?: boolean };
function applyChanges(value: unknown, changes: Change[]) {
  for (const change of changes) {
    let target = value as Record<string | number, unknown>;
    for (const key of change.path.slice(0, -1)) target = target[key] as Record<string | number, unknown>;
    const key = change.path.at(-1)!;
    if (change.delete) delete target[key]; else target[key] = structuredClone(change.value);
  }
}
it.each(savedRecords.cases)("matches Python on file acquisition replay: $name", ({ changes, valid }) => {
  const record = structuredClone(savedRecords.record), trace = savedRecords.trace;
  applyChanges(record, changes);
  const before = JSON.stringify(record);
  expect(normalizeAcquisition(record, trace)).toEqual(valid ? record : null);
  expect(browserAcquisition(record, trace)).toEqual(valid ? record : null);
  expect(JSON.stringify(record)).toBe(before);
});

it.each([
  { sink_method: "loads" }, { loader: "pickle.loads" }, { sink_method: ["load"] },
  { loader: "dill.load" }, { input_control_status: "verified" },
])("rejects file-loader schema confusion: %j", invalid => {
  const trace = { ...savedRecords.trace, ...invalid };
  expect(normalizeDeserializationObservation(trace)).toBeNull();
  expect(browserTrace(trace)).toBeNull();
  expect(normalizeAcquisition(savedRecords.record, trace)).toBeNull();
  expect(browserAcquisition(savedRecords.record, trace)).toBeNull();
});

it.each(["request_input_source", "input_trust_boundary", "loader_runtime_contract", "receipt"])(
  "revokes file evidence when the remaining prerequisite or receipt is removed: %s", gap => {
    const value = structuredClone(reports[0].report.security_agent);
    for (const observation of value.observations) {
      if (gap === "receipt") Object.assign(observation, { agent_chain: null });
      else observation.missing_evidence = observation.missing_evidence.filter(key => key !== gap);
    }
    const before = JSON.stringify(value), review = patternReview(value)!;
    expect(review.status).toBe("partial");
    expect(review.observations).toHaveLength(2);
    for (const observation of review.observations) {
      const rows = Object.fromEntries(observation.rows);
      expect(rows["Source fact: file input source"]).toBeUndefined();
      expect(rows["Source investigation"]).toBeUndefined();
      expect(rows["Review state"]).toContain("Needs evidence");
      expect(rows["Missing evidence"]).toContain("Calling code and origin of the file (not checked)");
      expect(rows["Missing evidence"]).toContain("local input flow; input trust boundary; loader runtime contract");
    }
    const rendered = browserText(value);
    expect(rendered).not.toContain("Source fact: file input source");
    expect(rendered).toContain("source evidence invalid");
    expect(JSON.stringify(value)).toBe(before);
  });

it("cannot exchange acquisitions between two load calls in the same source file", () => {
  const [first, second] = reports[0].report.security_agent.observations;
  expect(normalizeAcquisition(first.acquisition, second.evidence.deserialization_observation)).toBeNull();
  expect(browserAcquisition(first.acquisition, second.evidence.deserialization_observation)).toBeNull();
});
