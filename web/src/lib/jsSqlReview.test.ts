import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { jsSqlReview } from "./jsSqlReview";

const source = { archive_sha256: "a".repeat(64), engine_version: "test" };
function fixture() {
  const tasks = ["detector", "researcher", "verifier"].map((agent, i) => ({ agent, status: "completed",
    input_sha256: String(i + 1).repeat(64), output_sha256: String(i + 2).repeat(64),
    depends_on: i ? [String(i + 1).repeat(64)] : [] }));
  return { version: 1, source, status: "completed", coverage_partial: false,
    budget: { max_candidates: 32, candidates_found: 1, processed: 1, omitted: 0 },
    runtime_verified: false, automatic_patch: false, model_calls: 0,
    observations: [{ id: "sql-1", file: '<img src=x onerror="alert(1)">.ts', line: 3,
      state: "fixed_sql_fragments", tasks,
      analysis: { version: 1, file: '<img src=x onerror="alert(1)">.ts', source_sha256: "b".repeat(64),
        sink_line: 3, sink_column: 1, sink_method: "query", verdict: "fixed_sql_fragments",
        parameter_argument: "present", fragments: [{ line: 2, kind: "fixed_helper", reason: "single_return_literal_args" }],
        reason: "proven_fixed", runtime_verified: false } }] };
}
const app = readFileSync("../browser/src/app.js", "utf8");
const browser = runInNewContext(app.slice(app.indexOf("function jsSqlReview("), app.indexOf("function renderSecurityAgent(agent)"))
  + "; jsSqlReview");

it("keeps ordinary browser and web source views equivalent and bounded", () => {
  const record = fixture();
  expect(JSON.stringify(browser(record, source))).toBe(JSON.stringify(jsSqlReview(record, source)));
  const view = jsSqlReview(record, source)!;
  expect(view.observations).toHaveLength(1);
  expect(view.observations[0].file).toBe(record.observations[0].file);
  expect(JSON.stringify(view)).toContain("original finding is retained");
  expect(JSON.stringify(view)).toContain("presence alone does not establish parameter binding");
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
it("renders a hostile path as text in the ordinary browser with zero Python observations", () => {
  document.body.innerHTML = '<details id="security-agent-details"></details><div id="security-agent"></div><summary id="security-agent-summary"></summary>';
  const node = (tag: string, text = "", className = "") => {
    const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
  };
  const render = runInNewContext(app.slice(app.indexOf("function jsSqlReview("), app.indexOf("function renderRuleCoverage("))
    + "; renderSecurityAgent", {
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
