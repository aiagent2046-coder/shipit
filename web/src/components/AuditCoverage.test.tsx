import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { AuditCoverage } from "./AuditCoverage";
import { FindingsList, SeveritySummary } from "./FindingsList";
import type { Finding, Score, ScanManifest } from "@/lib/types";

afterEach(cleanup);

const finding: Finding = {
  rule_id: "llm-auth", category: "Auth", title: "Unproven double grant",
  severity: "critical", confidence: 1, source: "llm",
};

const manifest: ScanManifest = {
  archive_sha256: "a".repeat(64), commit_sha: null, engine_version: "test", archive_files: 2,
  static_checks: [], static_limits: {}, inventory: {}, model: null, model_calls: 0,
  rubrics_completed: [], llm_candidate_files: 2, llm_submitted_files: 1, llm_files_not_submitted: 1,
  limitations: [], runtime_verified: false,
};

describe("audit evidence", () => {
  it("keeps quote checks separate from model conditions and consequences", () => {
    const { container } = render(<FindingsList findings={[{ ...finding,
      explanation: "Another account might be readable.",
      claim_evidence: { version: 1,
        source_check: { kind: "quote_match", line_start: 10, line_end: 14 },
        observation: "The handler reads a row by ID.",
        required_conditions: ["<script>not executable</script>", "An unauthorized caller can reach the handler."],
        conditions_status: "not_checked", consequence_status: "not_checked" },
    }]} />);
    expect(screen.getByText(/Quoted text matched in source lines 10–14/)).toBeTruthy();
    expect(screen.getByText("Model interpretation — unverified")).toBeTruthy();
    expect(screen.getByText("Required conditions — not checked")).toBeTruthy();
    expect(screen.getByText(/An unauthorized caller/).closest("details")).toBeNull();
    expect(screen.getByText("No independent verification recorded.")).toBeTruthy();
    expect(screen.getByText("Possible consequence — unverified:")).toBeTruthy();
    expect(container.querySelector("script")).toBeNull();
  });

  it("does not invent checks or satisfied conditions for an older finding", () => {
    render(<FindingsList findings={[finding]} />);
    expect(screen.getByText("Not recorded for this finding; do not assume the cited code was verified.")).toBeTruthy();
    expect(screen.getByText("Not recorded; do not assume the conditions for harm are satisfied.")).toBeTruthy();
  });

  it.each([
    ["billing", 0, "Model review unavailable", "billing or quota"],
    ["provider", 2, "Model review incomplete", "request failed"],
    ["cost_cap_exceeded", 1, "Model review incomplete", "spending limit"],
    ["input_truncated", 1, "Model review may be incomplete", "possible input truncation"],
  ] as const)("shows %s outside collapsed scan details", (reason, calls, title, detail) => {
    render(<AuditCoverage score={{ total: 0, categories: {}, basis: calls ? "static+llm" : "static_only",
      scan_manifest: { ...manifest, model_calls: calls, limitations: [reason] } }} findings={[]} />);
    const notice = screen.getByRole("complementary", { name: "Model review status" });
    expect(notice.textContent).toContain(title);
    expect(notice.textContent).toContain(detail);
    expect(notice.closest("details")).toBeNull();
  });

  it.each(["static+preview", "static+llm"] as const)("does not report a failure for successful %s", (basis) => {
    render(<AuditCoverage score={{ total: 0, categories: {}, basis,
      scan_manifest: { ...manifest, model_calls: 1 } }} findings={[]} />);
    expect(screen.queryByRole("complementary", { name: "Model review status" })).toBeNull();
    expect(screen.getByText(manifest.archive_sha256).getAttribute("translate")).toBe("no");
  });

  it("counts the paid report's 26 source observations separately from its 49 examples", () => {
    const source = (["high", "medium", "low"] as const).flatMap((severity, i) =>
      Array.from({ length: [4, 10, 12][i] }, () => ({ ...finding, severity, file: "app.py" })));
    const examples = Array.from({ length: 49 }, () => ({ ...finding, file: "tests/a.py" }));
    render(<SeveritySummary findings={[...source, ...examples]} />);
    expect(screen.getByText("4 high")).toBeTruthy();
    expect(screen.getByText("10 medium")).toBeTruthy();
    expect(screen.getByText("12 low")).toBeTruthy();
    expect(screen.queryByText(/critical/)).toBeNull();
  });

  it("does not turn a grouped row's highest severity into every member's severity", () => {
    render(<SeveritySummary findings={[{ ...finding, severity: "high",
      occurrence_titles: ["A", "B"], occurrence_severities: ["high", "medium"] }]} />);
    expect(screen.getByText("1 high")).toBeTruthy();
    expect(screen.getByText("1 medium")).toBeTruthy();
  });
  it.each(["static_only", "static+preview", "static+llm", "static+partial", undefined] as const)(
    "does not publish readiness or confirmation for %s", (basis) => {
      const score: Score = { total: 4.9, categories: { Auth: 8.9 }, basis };
      const { container } = render(<>
        <AuditCoverage score={score} findings={[finding]} />
        <FindingsList findings={[finding]} />
      </>);
      expect(screen.getByText("Model hypothesis — unverified")).toBeTruthy();
      expect(screen.getByText("Potential critical impact")).toBeTruthy();
      expect(container.textContent).not.toContain("4.9");
      expect(container.textContent).not.toContain("8.9");
      expect(container.textContent).not.toContain("nothing serious found");
      expect(container.textContent).not.toContain("Fix before launch");
    },
  );

  it("keeps skipped coverage distinct from partial coverage and findings", () => {
    render(<AuditCoverage score={{ total: 10, categories: {}, basis: "static_only" }}
      findings={[finding]} />);
    expect(screen.getByText("Not surveyed — see findings · 1 unverified finding")).toBeTruthy();
    expect(screen.getByText("Not checked")).toBeTruthy();
    expect(screen.getAllByText("Partly checked")).toHaveLength(4);
  });

  it("does not reassure users when no findings were emitted", () => {
    const { container } = render(<FindingsList findings={[]} />);
    expect(container.textContent).toContain("Absence of findings does not establish safety");
    expect(container.textContent).not.toContain("clean bill");
  });

  it("marks older static findings as having no recorded verification", () => {
    render(<FindingsList findings={[{ ...finding, rule_id: "aws-access-key-id", source: undefined }]} />);
    expect(screen.getByText("Legacy finding — verification not recorded")).toBeTruthy();
  });

  it("separates fixtures without hiding credentials or classifying migrations as examples", () => {
    render(<FindingsList findings={[
      { ...finding, title: "Fixture secret", file: "smoke/sample/key.ts" },
      { ...finding, title: "Migration secret", file: "examples/migrations/0001.sql" },
    ]} />);
    const examples = screen.getByRole("region", { name: "In tests, examples and scaffolding" });
    expect(within(examples).getByText("Fixture secret")).toBeTruthy();
    expect(within(examples).queryByText("Migration secret")).toBeNull();
    expect(screen.getByText("Migration secret")).toBeTruthy();
  });
});
