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

it.each([1, 2])("explains the v%s source-bound query grouping while retaining each original hypothesis", version => {
  const finding = clone("query_group");
  const identity = finding.claim_evidence!.source_issue_identity!;
  identity.version = version;
  if (version === 1) delete identity.binding;
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped hypothesis scope"]).toContain("claimed costs remain separate and unverified");
  expect(rows["Grouped original 1 — not independent confirmation"]).toContain("GET /api/messages");
  expect(rows["Grouped original 2 — not independent confirmation"]).toContain("Messages GET endpoint");
  finding.claim_evidence!.source_issue_identity!.file = "another.ts";
  expect(Object.fromEntries(claimEvidenceRows(finding))["Grouped hypothesis scope"]).toBeUndefined();
});

it.each([
  ["missing binding", (identity: Record<string, unknown>) => { delete identity.binding; }],
  ["unknown version", (identity: Record<string, unknown>) => { identity.version = 3; }],
  ["additional identity field", (identity: Record<string, unknown>) => { identity.extra = true; }],
  ["null binding", (identity: Record<string, unknown>) => { identity.binding = null; }],
  ["missing hash", (identity: Record<string, unknown>) => { identity.binding = { span: [61, 66] }; }],
  ["invalid hash", (identity: Record<string, unknown>) => { identity.binding = { name_sha256: "z".repeat(64), span: [61, 66] }; }],
  ["hash trailing newline", (identity: Record<string, unknown>) => { identity.binding = { name_sha256: "a".repeat(64) + "\n", span: [61, 66] }; }],
  ["additional binding field", (identity: Record<string, unknown>) => { Object.assign(identity.binding!, { extra: true }); }],
  ["fractional span", (identity: Record<string, unknown>) => { (identity.binding as Record<string, unknown>).span = [61.5, 66]; }],
  ["empty span", (identity: Record<string, unknown>) => { (identity.binding as Record<string, unknown>).span = [61, 61]; }],
  ["outside function", (identity: Record<string, unknown>) => { identity.function_span = [62, 256]; }],
  ["overlapping operation", (identity: Record<string, unknown>) => { (identity.binding as Record<string, unknown>).span = [61, 69]; }],
  ["oversized binding", (identity: Record<string, unknown>) => {
    (identity.binding as Record<string, unknown>).span = [1, 130];
    identity.operation_span = [131, 175];
  }],
] as const)("does not claim grouped scope for v2 with %s", (_label, mutate) => {
  const finding = clone("query_group");
  mutate(finding.claim_evidence!.source_issue_identity!);
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped hypothesis scope"]).toBeUndefined();
  expect(rows["Grouped original 1 — not independent confirmation"]).toContain("GET /api/messages");
  expect(rows["Grouped original 2 — not independent confirmation"]).toContain("Messages GET endpoint");
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

it("explains a corrected fact-count group and preserves both complete historical claims", () => {
  const finding = clone("fact_group"), before = JSON.stringify(finding);
  const originals = finding.claim_evidence!.grouped_originals!;
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped interpretation scope"]).toContain("same source path and corrected fact-count interpretation only");
  expect(rows["Grouped interpretation scope"]).toContain("Original conditions and cost claims remain separate and unverified");
  for (const [index, original] of originals.entries()) {
    expect(JSON.parse(rows[`Grouped original ${index + 1} — not independent confirmation`])).toEqual(original);
  }
  const { container } = render(<FindingsList findings={[finding]} />);
  expect(screen.getByText("Grouped interpretation scope", { selector: "dt" })).toBeTruthy();
  expect(container.textContent).toContain("sanitizeFacts does not cap the total number of facts sent to Claude");
  expect(container.textContent).toContain("No external cap on agent_context rows per user exists");
  expect(JSON.stringify(finding)).toBe(before);
});

it.each([
  ["missing identity", (f: Finding) => { delete f.claim_evidence!.source_issue_identity; }],
  ["changed source", (f: Finding) => { f.source = "static"; }],
  ["changed verification status", (f: Finding) => { Object.assign(f, { verification_status: "verified" }); }],
  ["changed condition status", (f: Finding) => { Object.assign(f.claim_evidence!, { conditions_status: "observed" }); }],
  ["changed consequence status", (f: Finding) => { Object.assign(f.claim_evidence!, { consequence_status: "observed" }); }],
  ["invalid confidence", (f: Finding) => { f.confidence = Number.NaN; }],
  ["out-of-range confidence", (f: Finding) => { f.confidence = 1.01; }],
  ["malformed conditions", (f: Finding) => { Object.assign(f.claim_evidence!, { required_conditions: [null] }); }],
  ["changed source binding", (f: Finding) => { f.claim_evidence!.source_assessments![0].source_binding.upper = 41; }],
  ["changed source hash", (f: Finding) => { f.claim_evidence!.source_assessments![0].source_sha256 = "a".repeat(64); }],
  ["changed model", (f: Finding) => {
    f.claim_evidence!.producer!.model = f.claim_evidence!.narrative_projection!.original.producer.model = "another-model";
  }],
  ["changed active claim", (f: Finding) => { f.title = "Every cost claim is confirmed"; }],
  ["nested grouping", (f: Finding) => { f.claim_evidence!.grouped_originals = []; }],
  ["extra field", (f: Finding) => { Object.assign(f, { additional_cost_claim: true }); }],
] as const)("rejects fact grouping with %s in an original even when the representative is valid", (_label, mutate) => {
  const finding = clone("fact_group");
  mutate(finding.claim_evidence!.grouped_originals![1] as unknown as Finding);
  expect(narrativeProjection(finding)).not.toBeNull();
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped interpretation scope"]).toBeUndefined();
  expect(rows["Grouped original 1 — not independent confirmation"]).toBeTruthy();
  expect(rows["Grouped original 2 — not independent confirmation"]).toBeTruthy();
});

it.each([
  ["scope text", (f: Finding) => { f.claim_evidence!.grouped_claim_scope!.scope = "All costs verified"; }],
  ["consequence text", (f: Finding) => { f.claim_evidence!.grouped_claim_scope!.consequences = "Confirmed"; }],
  ["extra scope field", (f: Finding) => { Object.assign(f.claim_evidence!.grouped_claim_scope!, { verified: true }); }],
  ["missing scope marker", (f: Finding) => { delete f.claim_evidence!.grouped_claim_scope; }],
  ["missing original representative", (f: Finding) => { f.confidence = 0.99; }],
  ["only one original", (f: Finding) => { f.claim_evidence!.grouped_originals!.pop(); }],
] as const)("rejects fact grouping with %s while preserving available originals", (_label, mutate) => {
  const finding = clone("fact_group");
  mutate(finding);
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Grouped interpretation scope"]).toBeUndefined();
  expect(rows["Grouped original 1 — not independent confirmation"]).toBeTruthy();
});

it("compares fact-group object keys independently of JSON property order", () => {
  const finding = clone("fact_group");
  finding.claim_evidence!.grouped_originals = finding.claim_evidence!.grouped_originals!
    .map(original => Object.fromEntries(Object.entries(original).reverse()));
  expect(Object.fromEntries(claimEvidenceRows(finding))["Grouped interpretation scope"]).toBeTruthy();
});
