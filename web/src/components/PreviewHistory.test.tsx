import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { PreviewHistory, SeveritySummary } from "./FindingsList";
import type { Finding, Score } from "@/lib/types";

afterEach(cleanup);

const prior: Finding = {
  rule_id: "llm-security", title: "Original claim <script>unsafe()</script>",
  severity: "high", confidence: 0.8, source: "llm", category: "Security",
  fix_hint: "Old suggestion", file: "src/config.ts", line: 5,
  claim_evidence: { version: 1,
    source_check: { kind: "quote_match", line_start: 5, line_end: 6 },
    observation: "Original interpretation", required_conditions: ["Unchecked condition"],
    conditions_status: "not_checked", consequence_status: "not_checked" },
};
const score: Score = { total: 7, categories: {}, basis: "static+llm",
  preview_history: { version: 1, preview_audit_id: "preview-id", content_hash: "digest",
    engine_version: "same-engine", model: "preview-model", total: 2, matched_count: 1,
    retained_findings: [prior], status: "not_reassessed" } };

describe("free audit history", () => {
  it("keeps original evidence and collapsed advice without current impact badges", () => {
    const { container } = render(<><PreviewHistory score={score} /><SeveritySummary findings={[]} /></>);
    const section = screen.getByRole("region", { name: "Free audit history" });
    expect(section.textContent).toContain("1 unchanged observations");
    expect(section.textContent).toContain("1 other preview observations");
    expect(section.textContent).toContain("Not repeated does not mean fixed, disproved or confirmed");
    expect(section.textContent).toContain("preview-model");
    expect(section.textContent).toContain("Quoted text matched in source lines 5–6");
    expect(within(section).getByText("Old suggestion").closest("details")).not.toBeNull();
    expect(screen.queryByText("Potential high impact")).toBeNull();
    expect(screen.getByText("No source observations recorded")).toBeTruthy();
    expect(container.querySelector("script")).toBeNull();
  });

  it("does not invent history for an older report", () => {
    const { container } = render(<PreviewHistory score={{ total: 7, categories: {} }} />);
    expect(container.textContent).toBe("");
  });

  it("keeps the test context visible in retained history", () => {
    render(<PreviewHistory score={{ ...score, preview_history: { ...score.preview_history!,
      retained_findings: [{ ...prior, file: "repo/tests/fixtures/shell_injection.py" }] } }} />);
    expect(screen.getByText(/Previous preview — not reassessed · Test\/example context/)).toBeTruthy();
    expect(screen.queryByText("Potential high impact")).toBeNull();
  });

  it("shows matching observations without duplicating their cards", () => {
    render(<PreviewHistory score={{ ...score, preview_history: { ...score.preview_history!,
      matched_count: 2, retained_findings: [] } }} />);
    expect(screen.getByRole("region").textContent).toContain("2 unchanged observations");
    expect(screen.queryByText("Old suggestion")).toBeNull();
  });

  it("distinguishes cached analysis from newly performed model work", () => {
    render(<PreviewHistory score={{ ...score, analysis_reused_from: "existing-paid-audit" }} />);
    expect(screen.getByText(/adding this history made no new LLM calls/)).toBeTruthy();
  });
});
