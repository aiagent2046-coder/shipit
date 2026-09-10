import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { FindingsList, PreviewHistory, SeveritySummary } from "./FindingsList";
import type { Finding, Score, SourceAssessment } from "@/lib/types";

afterEach(cleanup);

const assessment: SourceAssessment = {
  kind: "credential_transport_only", result: "unsupported", whole_finding: true,
  detail: "Source shows a provider credential field, not a demonstrated disclosure path.",
  file: "server/oauth.ts", line_start: 8, line_end: 12, source_sha256: "a".repeat(64),
  method: "source_ast", source_binding: { provider: "github", field: "client_secret" },
};

const finding: Finding = {
  rule_id: "llm-auth", source: "llm", title: "Client secret leaks during OAuth exchange",
  severity: "high", confidence: .9, category: "Auth", file: "server/oauth.ts", line: 8,
  explanation: "Original allegation <script>shouldNotExecute()</script>",
  fix_hint: "Original suggestion to remove provider authentication.",
  claim_evidence: { version: 1, source_check: { kind: "quote_match", line_start: 8, line_end: 12 },
    observation: "Original model interpretation", required_conditions: ["An untrusted party obtains the credential."],
    conditions_status: "not_checked", consequence_status: "not_checked", source_assessments: [assessment] },
};

it("places unsupported transport in a neutral section with original advice retained as an unverified claim", () => {
  const before = JSON.stringify(finding);
  const { container } = render(<><FindingsList findings={[finding]} /><SeveritySummary findings={[finding]} /></>);
  const section = screen.getByRole("region", { name: "Credential transport hypotheses" });
  const card = within(section).getByRole("listitem");
  expect(within(card).getByText("Credential transport — exposure not established", { selector: "p.font-medium" })).toBeTruthy();
  expect(within(card).getByText("Needs exposure evidence", { selector: "span" })).toBeTruthy();
  expect(within(card).queryByText("Potential high impact")).toBeNull();
  expect(within(section).queryByText("Syntax premise contradicted")).toBeNull();
  expect(within(card).getByText(/This transport-only hypothesis is excluded from the score/)).toBeTruthy();
  for (const original of [finding.title, finding.explanation!, finding.fix_hint!]) {
    expect(within(card).getByText(original).closest("details")).not.toBeNull();
  }
  expect(card.textContent).toContain(assessment.detail);
  expect(card.textContent).toContain(assessment.source_sha256);
  expect(screen.getByText("No source observations recorded")).toBeTruthy();
  expect(container.querySelector("script")).toBeNull();
  expect(JSON.stringify(finding)).toBe(before);
});

it("preserves independent exposure allegations when assessment metadata is incomplete or covers only one claim", () => {
  for (const override of [{ source_binding: {} }, { whole_finding: false }, { result: "unknown" }]) {
    const candidate = { ...finding, claim_evidence: { ...finding.claim_evidence!,
      source_assessments: [{ ...assessment, ...override }] } } as Finding;
    const { unmount } = render(<FindingsList findings={[candidate]} />);
    expect(screen.queryByRole("region", { name: "Credential transport hypotheses" })).toBeNull();
    expect(screen.getByText("Potential high impact")).toBeTruthy();
    expect(screen.getAllByText(candidate.title).length).toBeGreaterThan(0);
    unmount();
  }
});

it("shows generic source contradictions through the partial renderer while retaining the unresolved impact", () => {
  const partial: Finding = { ...finding, claim_evidence: { ...finding.claim_evidence!,
    source_assessments: [{ ...assessment, kind: "memory_limit", result: "contradicted", whole_finding: false }] } };
  render(<><FindingsList findings={[partial]} /><SeveritySummary findings={[partial]} /></>);
  const card = screen.getByText("Source checks contradict part of this finding").closest("li")!;
  expect(within(card).getByText("Assessment needs review", { selector: "span" })).toBeTruthy();
  expect(within(card).queryByText("Potential high impact")).toBeNull();
  expect(card.textContent).toContain("original model severity is retained in the score pending review");
  expect(within(card).getByText(finding.title).closest("details")).not.toBeNull();
  expect(screen.getByText("1 high")).toBeTruthy();
  expect(screen.queryByRole("region", { name: "Credential transport hypotheses" })).toBeNull();
});

it.each(["unsupported", "contradicted"] as const)("keeps historical originals and visible %s metadata without imposing a current assessment", result => {
  const historical: Finding = { ...finding, claim_evidence: { ...finding.claim_evidence!,
    source_assessments: [{ ...assessment, result }] } };
  const score: Score = { total: 4.6, categories: {}, free_baseline: {
    version: 1, origin: "reused", status: "completed", findings: [historical],
    score: { total: 5.1, categories: { Auth: 6.3 }, basis: "static+preview" },
  }, preview_history: { version: 1, preview_audit_id: "prior", content_hash: "same", engine_version: "old",
    model: "preview", total: 5.1, matched_count: 0, retained_findings: [historical], status: "not_reassessed" } };
  const before = JSON.stringify(score);
  render(<PreviewHistory score={score} />);
  for (const name of ["Included free audit", "Free audit history"]) {
    const section = screen.getByRole("region", { name });
    expect(within(section).getByText(finding.title, { selector: "p.font-medium" })).toBeTruthy();
    expect(within(section).getByText(finding.explanation!, { exact: false })).toBeTruthy();
    expect(within(section).getByText(finding.fix_hint!).closest("details")).not.toBeNull();
    expect(section.textContent).toContain(assessment.detail);
    expect(within(section).queryByText("Needs exposure evidence")).toBeNull();
    expect(within(section).queryByText("Credential transport — exposure not established")).toBeNull();
    expect(within(section).queryByText("Source checks contradict part of this finding")).toBeNull();
    expect(section.textContent).not.toContain("This transport-only hypothesis is excluded from the score");
    expect(within(section).queryByText("Assessment needs review")).toBeNull();
  }
  expect(JSON.stringify(score)).toBe(before);
});
