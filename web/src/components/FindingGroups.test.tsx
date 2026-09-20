import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { FindingsList, SeveritySummary } from "./FindingsList";
import { relatedFindingGroups } from "@/lib/findingGroups";
import { deserializationEvidenceRows, normalizeDeserializationObservation } from "@/lib/securityAgent";
import type { Finding } from "@/lib/types";

afterEach(cleanup);
const source = readFileSync("../browser/src/app.js", "utf8");
const browserGroups: typeof relatedFindingGroups = runInNewContext(
  `${source.slice(source.indexOf("function relatedFindingGroups("), source.indexOf("function renderFindingGroups("))}; relatedFindingGroups`,
  { normalizeDeserializationObservation });
const renderBrowserGroups: (findings: Finding[]) => HTMLElement[] = runInNewContext(
  `${source.slice(source.indexOf("function renderDefinitions("), source.indexOf("function renderReport("))}; renderFindingGroups`, {
    normalizeDeserializationObservation, deserializationEvidenceRows,
    node: (tag: string, content?: string, className?: string) => {
      const element = document.createElement(tag);
      if (content !== undefined) element.textContent = String(content);
      if (className) element.className = className;
      return element;
    },
    text: (value: unknown, fallback = "") => typeof value === "string" || typeof value === "number" ? String(value) : fallback,
    readable: String,
  });

function finding(line: number, confidence = .8): Finding {
  return { rule_id: "unsafe-deserialization", source: "static", severity: "high", confidence,
    category: "Security", file: "model/checkpoints.py", line, context: "code",
    title: `Pickle loader at ${line}`, explanation: `Original explanation ${line}`,
    fix_hint: `Original suggestion ${line}`, verification_status: "unverified", verification_method: "source_pattern",
    claim_evidence: { version: 1, source_check: { kind: "static_rule" }, observation: null,
      required_conditions: null, conditions_status: "not_checked", consequence_status: "not_checked",
      deserialization_observation: { version: 1, method: "python_ast_import_resolved", file: "model/checkpoints.py",
        source_sha256: "a".repeat(64), sink_line: line, sink_span: [line, 8, line, 24],
        sink_method: "load", loader: "pickle.load", input_control_status: "not_checked" } } };
}

it("renders both complete cards and retains confidence, evidence, source counts and the export record", () => {
  const findings = [finding(77, .8), finding(128, .6)], before = JSON.stringify(findings);
  render(<><FindingsList findings={findings} /><SeveritySummary findings={findings} /></>);
  expect(screen.getByText("Pickle file loading · 2 locations")).toBeTruthy();
  expect(screen.getByText("2 high")).toBeTruthy();
  for (const line of [77, 128]) {
    expect(screen.getByText(new RegExp(`model/checkpoints.py:${line}`))).toBeTruthy();
    expect(screen.getByText(`Original explanation ${line}`)).toBeTruthy();
    expect(screen.getByText(`Original suggestion ${line}`)).toBeTruthy();
  }
  for (const group of [relatedFindingGroups(findings), browserGroups(findings)]) {
    expect(group).toHaveLength(1);
    expect(group[0][0]).toBe(findings[0]);
    expect(group[0][1]).toBe(findings[1]);
    expect(group[0].map(f => f.confidence)).toEqual([.8, .6]);
    expect(group[0].map(f => f.verification_status)).toEqual(["unverified", "unverified"]);
  }
  expect(JSON.stringify(findings)).toBe(before);
});

it.each(["source", "context", "source context", "severity", "file", "line", "hash", "loader", "missing", "invalid"])(
  "keeps %s differences or invalid evidence separate in web and browser", difference => {
    const rows = [finding(77), finding(128)], second = rows[1];
    const trace = second.claim_evidence!.deserialization_observation as Record<string, unknown>;
    if (difference === "source") second.source = "llm";
    if (difference === "context") second.context = "test_file";
    if (difference === "source context") second.claim_evidence!.source_context = { kind: "doc_example", uri_scheme: "", uri_kind: "" };
    if (difference === "severity") second.severity = "medium";
    if (difference === "file") second.file = "another.py";
    if (difference === "line") second.line = 129;
    if (difference === "hash") trace.source_sha256 = "b".repeat(64);
    if (difference === "loader") Object.assign(trace, { loader: "pickle.loads", sink_method: "loads" });
    if (difference === "missing") delete second.claim_evidence!.deserialization_observation;
    if (difference === "invalid") trace.method = "model_guess";
    expect(relatedFindingGroups(rows)).toEqual([[rows[0]], [rows[1]]]);
    expect(browserGroups(rows)).toEqual([[rows[0]], [rows[1]]]);
  });

it("keeps contextual cards in their section and same-line occurrences independently visible", () => {
  const rows = [finding(77), finding(77), { ...finding(128), context: "test_file" }];
  Object.assign(rows[1].claim_evidence!.deserialization_observation as object, { sink_span: [77, 30, 77, 46] });
  const { container } = render(<FindingsList findings={rows} />);
  expect(screen.getByText("Pickle file loading · 2 locations")).toBeTruthy();
  expect(screen.getByRole("region", { name: "In tests, examples and scaffolding" }).textContent).toContain(":128");
  expect(container.querySelectorAll("li li")).toHaveLength(2);
});

it("does not relabel duplicate records at one source span as additional locations", () => {
  const rows = [finding(77), finding(77)];
  expect(relatedFindingGroups(rows)).toEqual([[rows[0]], [rows[1]]]);
  expect(browserGroups(rows)).toEqual([[rows[0]], [rows[1]]]);
});

it("renders standalone browser cards with each original location, confidence and source evidence", () => {
  const rows = [finding(77, .8), finding(128, .6)], before = JSON.stringify(rows);
  const groups = renderBrowserGroups(rows);
  expect(groups).toHaveLength(1);
  expect(groups[0].tagName).toBe("DETAILS");
  expect(groups[0].querySelector(":scope > summary")!.textContent).toBe("Pickle file loading · 2 locations");
  const cards = groups[0].querySelectorAll("article");
  expect(cards).toHaveLength(2);
  for (const [index, row] of rows.entries()) {
    expect(cards[index].textContent).toContain(`${row.file}:${row.line}`);
    expect(cards[index].textContent).toContain(`Detector confidence: ${row.confidence.toFixed(2)}`);
    expect(cards[index].textContent).toContain("Verification: unverified");
    expect(cards[index].querySelector("details summary")!.textContent).toBe("Evidence and conditions");
    expect(cards[index].querySelector("details")!.textContent).toContain(`pickle.load() at line ${row.line}`);
    expect(cards[index].querySelector("details")!.textContent).toContain("a".repeat(64));
  }
  expect(JSON.stringify(rows)).toBe(before);
});
