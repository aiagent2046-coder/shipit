import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { jsSqlReview } from "./jsSqlReview";
import { sha256 } from "@noble/hashes/sha2.js";
import records from "../../../tests/fixtures/js-sql-review-records.json";

// These receipts are produced by Python _observation, not by this UI's hashing code.
function fixture(name = "fixed") {
  return structuredClone(records.find(record => record.name === name)!.review);
}
const source = fixture().source;
const app = readFileSync("../browser/src/app.js", "utf8");
const browser = runInNewContext(app.slice(app.indexOf("function jsSqlReview("), app.indexOf("function renderSecurityAgent(agent)"))
  + "; jsSqlReview", { sha256 });

it("keeps ordinary browser and web source views equivalent and bounded", () => {
  const record = fixture();
  expect(JSON.stringify(browser(record, source))).toBe(JSON.stringify(jsSqlReview(record, source)));
  const view = jsSqlReview(record, source)!;
  expect(view.observations).toHaveLength(1);
  expect(view.observations[0].file).toBe(record.observations[0].file);
  expect(JSON.stringify(view)).toContain("original finding is retained");
  expect(JSON.stringify(view)).toContain("presence alone does not establish parameter binding");
});
it.each(records)("accepts genuine Python $name receipts in both UIs", ({ review }) => {
  const view = jsSqlReview(review, review.source);
  expect(view).not.toBeNull();
  expect(JSON.stringify(browser(review, review.source))).toBe(JSON.stringify(view));
});
it.each(["source", "runtime", "unknown", "task", "budget", "reason", "coverage"])("rejects malformed %s claims in both views", kind => {
  const record = fixture();
  if (kind === "source") record.source = { ...source, archive_sha256: "c".repeat(64) };
  if (kind === "runtime") record.observations[0].analysis.runtime_verified = true;
  if (kind === "unknown") record.observations[0].analysis.fragments[0] = { line: 2, kind: "unknown", reason: "unresolved_expression" };
  if (kind === "task") record.observations[0].tasks[1].depends_on = [];
  if (kind === "budget") record.budget.processed = 33;
  if (kind === "reason") record.observations[0].analysis.reason = "safe";
  if (kind === "coverage") record.coverage_partial = true;
  expect(jsSqlReview(record, source)).toBeNull();
  expect(browser(record, source)).toBeNull();
});
it.each(["source_digest", "final_receipt", "id", "promotion"])("rejects changed %s with old receipts", kind => {
  const record = fixture(kind === "promotion" ? "dynamic" : "fixed");
  const item = record.observations[0];
  if (kind === "source_digest") item.analysis.source_sha256 = "c".repeat(64);
  if (kind === "final_receipt") item.tasks[2].output_sha256 = "0".repeat(64);
  if (kind === "id") item.id = "0".repeat(64);
  if (kind === "promotion") {
    item.state = item.analysis.verdict = "fixed_sql_fragments";
    item.analysis.reason = "proven_fixed";
    item.analysis.fragments = [{ line: 2, kind: "fixed_const", reason: "stable_const" }];
  }
  expect(jsSqlReview(record, source)).toBeNull();
  expect(browser(record, source)).toBeNull();
});
it.each(["state", "parameter_argument", "reason"])("rejects non-string %s without coercion or throwing", field => {
  for (const invalid of [["present"], { toString: null, valueOf: null }]) {
    const record = fixture();
    const target = field === "state" ? record.observations[0] : record.observations[0].analysis;
    Object.assign(target, { [field]: invalid });
    expect(jsSqlReview(record, source)).toBeNull();
    expect(browser(record, source)).toBeNull();
  }
});
it("renders a hostile path as text in the ordinary browser with zero Python observations", () => {
  document.body.innerHTML = '<details id="security-agent-details"></details><div id="security-agent"></div><summary id="security-agent-summary"></summary>';
  const node = (tag: string, text = "", className = "") => {
    const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
  };
  const render = runInNewContext(app.slice(app.indexOf("function jsSqlReview("), app.indexOf("function renderRuleCoverage("))
    + "; renderSecurityAgent", {
    sha256,
    byId: (id: string) => document.getElementById(id), node,
    text: (v: unknown, fallback = "") => typeof v === "string" ? v : fallback,
    renderDefinitions: (parent: HTMLElement, rows: [string, string][]) => {
      for (const [label, value] of rows) parent.append(node("p", label + ": " + value));
    },
  });
  render({ version: 1, mode: "deterministic_static", runtime_verified: false, automatic_patch: false,
    status: "completed", source, observations: [], js_sql_review: fixture() });
  expect(document.querySelector("#security-agent img")).toBeNull();
  expect(document.querySelector("#security-agent")!.textContent).toContain(fixture().observations[0].file);
  expect(document.querySelector("#security-agent-summary")!.textContent).toContain("JavaScript SQL: 1");
});
