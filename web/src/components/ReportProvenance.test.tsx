import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { AuditCoverage } from "./AuditCoverage";
import { PreviewHistory } from "./FindingsList";
import { manifestRows, observationSummary, reviewContributionRows } from "@/lib/evidence";
import type { Finding, ScanManifest, Score } from "@/lib/types";

afterEach(cleanup);
const f: Finding = { rule_id: "connection-string-password", title: "Example", severity: "low",
  confidence: 0.8, source: "static", category: "Security", fix_hint: "Check context" };
function stage(submitted: number, calls: number, saved = 0): Score {
  const m: ScanManifest = { archive_sha256: "same", commit_sha: null, engine_version: "test", archive_files: 588,
    static_checks: [], static_limits: {}, inventory: {}, model: "fake", model_calls: calls,
    model_findings: [{ model: "fake", responses: calls, invalid_responses: 0, empty_responses: calls,
      received: saved, rejected: 0, accepted: saved, merged: 0, saved, rejection_reasons: {} }],
    rubrics_completed: [], llm_candidate_files: 495, llm_submitted_files: submitted,
    llm_files_not_submitted: 495 - submitted, limitations: [], runtime_verified: false };
  return { total: 0, categories: {}, scan_manifest: m };
}

it("preserves static provenance in the full free audit and shows both model stages including zero", () => {
  const score: Score = { ...stage(273, 8), free_baseline: { version: 1, origin: "included", status: "completed",
    score: stage(92, 1), findings: [f] } };
  render(<><AuditCoverage score={score} findings={[f]} /><PreviewHistory score={score} /></>);
  const free = screen.getByRole("region", { name: "Included free audit" });
  expect(free.textContent).toContain("Static signal — unverified");
  expect(free.textContent).not.toContain("Free-model result");
  expect(free.textContent).not.toContain("Free-model suggestion");
  const contribution = screen.getByRole("region", { name: "Model review contribution" });
  expect(within(contribution).getByRole("row", { name: "Retained model hypotheses 0 0" })).toBeTruthy();
  expect(contribution.textContent).toContain("not counts of new or confirmed problems");
  expect(contribution.textContent).toContain("Zero retained hypotheses does not establish safety");
});

it("includes informational and contradicted observations without inflating unresolved totals", () => {
  expect(observationSummary([f, { ...f, context: "test_file", occurrence_titles: ["a", "b"] },
    { ...f, rule_id: "no-dockerfile", context: "deployment_inventory" },
    { ...f, source: "llm", claim_evidence: { version: 1, syntax_check: { result: "contradicted" } } } as Finding,
  ])).toBe("5 observations: 1 in source, 2 in tests/examples, 1 informational, 1 with contradicted syntax premises.");
});

it("does not invent missing work or file exclusion reasons for older reports", () => {
  const score: Score = { ...stage(273, 8, 2), analysis_reused_from: "stored", free_baseline: {
    version: 1, origin: "included", status: "unavailable", score: null, findings: [] } };
  expect(reviewContributionRows(score)[2]).toEqual(["Retained model hypotheses", "Not recorded", "2"]);
  expect(manifestRows(score)).toContainEqual(["File exclusion reasons", "Not recorded for this audit"]);
  render(<AuditCoverage score={score} findings={[]} />);
  expect(screen.getByText(/counts describe the stored review/)).toBeTruthy();
  score.scan_manifest!.model_findings = undefined;
  expect(reviewContributionRows(score)[2][2]).toBe("Not recorded");
  expect(reviewContributionRows({ total: 0, categories: {} })).toEqual([]);
});

it("shows recorded exclusion categories", () => {
  const score = stage(273, 8);
  score.scan_manifest!.llm_selection_exclusions = { no_rubric_match: 200, selection_budget: 20,
    request_window: 2, rubric_not_reached: 0 };
  const rows = manifestRows(score);
  expect(rows).toContainEqual(["Files not submitted: Removed to fit the request window", "2"]);
  expect(rows.some(([label]) => label === "File exclusion reasons")).toBe(false);
});
