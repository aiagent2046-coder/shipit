import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { AuditCoverage } from "./AuditCoverage";
import { FindingsList, SeveritySummary } from "./FindingsList";
import type { Finding, Score, ScanManifest } from "@/lib/types";
import { findingCounts, sourceSeverityCounts } from "@/lib/evidence";

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
  it("shows a grouped handler-label disagreement beside the model evidence with escaped originals", () => {
    const { container } = render(<FindingsList findings={[{ ...finding, claim_evidence: {
      version: 1, source_check: { kind: "not_recorded" }, observation: null, required_conditions: null,
      conditions_status: "not_checked", consequence_status: "not_checked",
      source_issue_identity: { handler: "send" }, grouped_originals: [
        { title: "Send can leave loading active" }, { title: "<script>Suggest original</script>" }],
      grouped_claim_scope: { mechanism: "react_network_rejection_cleanup", scope: "<img src=x onerror=alert(1)>",
        consequences: "Untrusted consequence", title_source_disagreements: [{
          original_index: 1, result: "different_handler_label", source_handler: "send" }] },
    } }]} />);
    expect(screen.getByText("Grouped hypothesis scope").closest("details")).toBeNull();
    expect(screen.getByText("Handler label needs review").closest("details")).toBeNull();
    expect(screen.getByText(/Original 2 uses a different handler label/).textContent)
      .toContain("Bound source handler: send");
    expect(container.textContent).toContain("<script>Suggest original</script>");
    expect(container.textContent).not.toContain("Untrusted consequence");
    expect(container.querySelector("script, img")).toBeNull();
  });

  it("shows legacy Free and Pro acceptance counts independently above the collapsed technical record", () => {
    const free: Score = { total: 9.3, categories: { Security: 9.2 }, basis: "static+preview",
      scan_manifest: { ...manifest, model_calls: 1, model_findings: [{ model: "preview", responses: 1,
        invalid_responses: 0, empty_responses: 0, received: 11, accepted: 1, rejected: 10,
        merged: 0, saved: 1, rejection_reasons: { source_quote_or_location_mismatch: 9, self_cancelled: 1 } }] } };
    const paid: Score = { total: 4.9, categories: { Frontend: 3 }, basis: "static+llm",
      free_baseline: { version: 1, origin: "included", status: "completed", score: free, findings: [] },
      scan_manifest: { ...manifest, model_calls: 8, model_findings: [{ model: "paid", responses: 8,
        invalid_responses: 0, empty_responses: 0, received: 59, accepted: 55, rejected: 4,
        merged: 13, saved: 42, rejection_reasons: { self_cancelled: 4 } }] } };
    const { container } = render(<>
      <section aria-label="Free audit"><AuditCoverage score={free} findings={[]} /></section>
      <section aria-label="Pro audit"><AuditCoverage score={paid} findings={[]} /></section>
    </>);
    const freeNotice = within(screen.getByRole("region", { name: "Free audit" }))
      .getByRole("complementary", { name: "Model observation acceptance" });
    const paidNotice = within(screen.getByRole("region", { name: "Pro audit" }))
      .getByRole("complementary", { name: "Model observation acceptance" });
    expect(freeNotice.textContent).toContain("Model observations accepted: 1 of 11");
    expect(freeNotice.textContent).toContain("9 could not be matched to the cited source");
    expect(paidNotice.textContent).toContain("Model observations accepted: 55 of 59");
    expect(paidNotice.textContent).toContain("4 were withdrawn by the model");
    expect(paidNotice.textContent).not.toContain("could not be matched");
    for (const notice of [freeNotice, paidNotice]) {
      expect(notice.closest("details")).toBeNull();
      expect(notice.textContent).toContain("does not verify conclusions or establish project safety");
    }
    expect(container.textContent).not.toContain("9.3");
    expect(container.textContent).not.toContain("4.9");
  });

  it("keeps safe rejection diagnostics inside Scan record and excludes unsafe metadata", () => {
    const { container } = render(<AuditCoverage findings={[]} score={{ total: 0, categories: {},
      scan_manifest: { ...manifest, rejection_diagnostics: { version: 1, omitted: 2, items: [{
        response: 1, rubric: "web", item: 2, reason: "source_quote_or_location_mismatch",
        detail: "quote_mismatch", file_ref: "sha256:" + "b".repeat(64), line_start: 10, line_end: 12,
        evidence: "<script>private source</script>", path: "/private/source.ts", title: "private claim",
      }, { response: 1, rubric: "web", item: 3, reason: "self_cancelled", detail: "self_cancelled",
        file_ref: "<img src=x onerror=alert(1)>", line_start: "<script>unsafe</script>", line_end: null,
      }] } } } as unknown as Score} />);
    const diagnostic = screen.getByText(/Reason: source_quote_or_location_mismatch; detail: quote_mismatch/);
    expect(diagnostic.closest("details")?.querySelector("summary")?.textContent).toBe("Scan record");
    expect(screen.getByText(/2 records shown; 2 omitted/).closest("details")).not.toBeNull();
    expect(screen.getByText(/entry: 3/).textContent).toContain("File reference: Not recorded");
    expect(container.querySelector("script, img")).toBeNull();
    expect(container.textContent).not.toMatch(/private source|private claim|private\/source|onerror|unsafe/);
  });

  it("does not substitute zero acceptance when an older report has no processing record", () => {
    render(<AuditCoverage score={{ total: 9.3, categories: {}, scan_manifest: manifest }} findings={[]} />);
    expect(screen.queryByRole("complementary", { name: "Model observation acceptance" })).toBeNull();
    expect(screen.getByText("Model finding processing").nextElementSibling?.textContent)
      .toBe("Not recorded for this audit");
    expect(screen.queryByText(/Model observations accepted: 0/)).toBeNull();
  });

  it("shows automatic function evidence with unresolved candidate limits", () => {
    const source_facts: NonNullable<ScanManifest["source_facts"]> = {
      scope: "Syntax only", facts: [], parsed_files: 1, excluded_files: 0, limitations: [],
      functions: { scope: "Name candidates; runtime binding not verified", indexed_functions: 2,
        parsed_files: 1, excluded_files: 0, limitations: ["record_limit_reached"],
        records: [{ file: "<unsafe>.py", line: 3, line_end: 7, scope: "grant",
          checks: [{ kind: "completed_status_return", result: "observed" }],
          candidates: [{ file: "db.py", line: 2000, binding: "name_candidate_not_resolved" }],
          call_names: [] }] },
    };
    const { container } = render(<AuditCoverage score={{ total: 0, categories: {}, basis: "static_only",
      scan_manifest: { ...manifest, source_facts } }} findings={[]} />);
    expect(screen.getByText("Function evidence 1")).toBeTruthy();
    expect(container.textContent).toContain("Candidate (binding not resolved)");
    expect(container.textContent).toContain("record_limit_reached");
    expect(container.querySelector("unsafe")).toBeNull();
    expect(findingCounts([])).toEqual({ source: 0, examples: 0 });
  });

  it("retains contradicted premises separately without critical badges or actionable fixes", () => {
    const contradicted: Finding = { ...finding, title: "UPDATE without WHERE",
      fix_hint: "<script>old advice</script>",
      claim_evidence: { version: 1, source_check: { kind: "quote_match", line_start: 1, line_end: 3 },
        observation: null, required_conditions: null, conditions_status: "not_checked",
        consequence_status: "not_checked", syntax_check: { kind: "sql_update_where", result: "contradicted",
          claim: "The cited UPDATE has no WHERE.", detail: "Its own WHERE is present; safety was not tested.",
          line_start: 1, line_end: 3 } },
    };
    const { container } = render(<FindingsList findings={[contradicted]} />);
    const section = screen.getByRole("region", { name: "Contradicted syntax premises" });
    expect(within(section).getAllByText("UPDATE without WHERE").length).toBeGreaterThan(0);
    expect(screen.queryByText("Potential critical impact")).toBeNull();
    expect(screen.getByText("<script>old advice</script>").closest("details")).not.toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(findingCounts([contradicted])).toEqual({ source: 0, examples: 0 });
    expect(sourceSeverityCounts([contradicted]).critical).toBe(0);
  });

  it("does not turn an observed syntax pattern into confirmed harm", () => {
    render(<FindingsList findings={[{ ...finding,
      claim_evidence: { version: 1, source_check: { kind: "quote_match", line_start: 1, line_end: 3 },
        observation: null, required_conditions: null, conditions_status: "not_checked",
        consequence_status: "not_checked", syntax_check: { kind: "react_hook_order", result: "observed",
          claim: "A hook follows a conditional return.", detail: "Render paths were not tested." } },
    }]} />);
    expect(screen.getByText("Syntax pattern observed")).toBeTruthy();
    expect(screen.getByText("No independent verification recorded.")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Contradicted syntax premises" })).toBeNull();
  });

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
