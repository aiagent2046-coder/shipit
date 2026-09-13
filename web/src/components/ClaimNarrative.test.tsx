import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { FindingsList } from "./FindingsList";
import { claimEvidenceRows, narrativeProjection } from "@/lib/evidence";
import type { Finding } from "@/lib/types";
import fixtures from "@/lib/fixtures/claim_narrative_cases.json";

afterEach(cleanup);
const clone = (kind: keyof typeof fixtures = "facts") => structuredClone(fixtures[kind]) as unknown as Finding;

it.each(["facts", "retry", "configured_facts"] as const)("shows source-corrected %s wording and retains original provenance", kind => {
  const finding = clone(kind), before = JSON.stringify(finding);
  const projection = narrativeProjection(finding);
  expect(projection).not.toBeNull();
  const { container } = render(<FindingsList findings={[finding]} />);
  const card = screen.getByText(finding.title, { selector: "p.font-medium" }).closest("li")!;
  expect(within(card).getByText(finding.explanation!, { exact: false }).closest("details")).toBeNull();
  expect(within(card).getByText(finding.fix_hint!).closest("details")).toBeNull();
  for (const key of ["title", "explanation", "fix_hint", "observation"] as const) {
    const matches = within(card).getAllByText(projection!.original[key]!);
    expect(matches.every(element => element.closest("details") !== null)).toBe(true);
  }
  expect(card.textContent).toContain("fixture-model");
  expect(card.textContent).toContain("Severity and score eligibility are unchanged");
  expect(within(card).getByText("Assessment needs review", { selector: "span" })).toBeTruthy();
  expect(within(card).queryByText("Potential medium impact")).toBeNull();
  expect(within(card).queryByText("Source checks contradict part of this finding")).toBeNull();
  expect(container.querySelector("script")).toBeNull();
  expect(JSON.stringify(finding)).toBe(before);
});

it.each([
  (f: Finding) => { f.title = "All facts are injected without a cap"; },
  (f: Finding) => { f.source = "static"; },
  (f: Finding) => { f.claim_evidence!.narrative_projection!.source_hashes = {}; },
  (f: Finding) => { f.claim_evidence!.source_assessments![0].file = "elsewhere.ts"; },
  (f: Finding) => { f.claim_evidence!.narrative_projection!.original.producer.response = 99; },
  (f: Finding) => { f.claim_evidence!.narrative_projection!.active.title = "Arbitrary correction"; },
  (f: Finding) => { f.title = f.claim_evidence!.narrative_projection!.active.title = "Arbitrary correction"; },
])("rejects invalid or mismatched marker %# without replacing the active claim", mutate => {
  const finding = clone();
  mutate(finding);
  expect(narrativeProjection(finding)).toBeNull();
  expect(Object.fromEntries(claimEvidenceRows(finding))["Recorded wording correction"]).toBeUndefined();
  render(<FindingsList findings={[finding]} />);
  expect(screen.queryByText("Superseded model wording — source premise corrected")).toBeNull();
  expect(screen.getByText("Source checks contradict part of this finding")).toBeTruthy();
});

it("does not invent a correction for legacy findings and escapes retained original markup", () => {
  const old = clone();
  delete old.claim_evidence!.narrative_projection;
  expect(narrativeProjection(old)).toBeNull();
  const projected = clone();
  projected.claim_evidence!.narrative_projection!.original.title = "<script>alert(1)</script>";
  const { container } = render(<FindingsList findings={[projected]} />);
  expect(screen.getByText("<script>alert(1)</script>").closest("details")).not.toBeNull();
  expect(container.querySelector("script")).toBeNull();
});

it("explains only the source-bound query grouping while retaining each original hypothesis", () => {
  const finding = clone("query_group");
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped hypothesis scope"]).toContain("claimed costs remain separate and unverified");
  expect(rows["Grouped original 1 — not independent confirmation"]).toContain("GET /api/messages");
  expect(rows["Grouped original 2 — not independent confirmation"]).toContain("Messages GET endpoint");
  finding.claim_evidence!.source_issue_identity!.file = "another.ts";
  expect(Object.fromEntries(claimEvidenceRows(finding))["Grouped hypothesis scope"]).toBeUndefined();
});

it.each(["facts", "retry"] as const)("refuses %s when the saved check no longer matches its source scope", kind => {
  for (const update of [{ line_start: 999 }, { source_sha256: "0".repeat(64) }, { span: [0, 1] }]) {
    const finding = clone(kind);
    Object.assign(finding.claim_evidence!.source_assessments![0], update);
    expect(narrativeProjection(finding)).toBeNull();
  }
});

it("requires the recorded import configuration hash when validating a helper resolution", () => {
  const finding = clone("configured_facts");
  delete finding.claim_evidence!.narrative_projection!.source_hashes["tsconfig.json"];
  expect(narrativeProjection(finding)).toBeNull();
});
