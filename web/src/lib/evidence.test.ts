import { expect, it } from "vitest";
import { claimEvidenceRows, coverageRows, findingCounts, manifestRows } from "./evidence";
import { plainFields } from "./plain";
import type { Finding, ScanManifest } from "./types";

const source: Finding = { rule_id: "aws-access-key-id", title: "AWS match",
  category: "Security", severity: "high", confidence: 1, file: "app/config.py" };

it("explains catch and HTTP evidence without dismissing a compound claim or changing old records", () => {
  const finding: Finding = { ...source, rule_id: "llm-web", source: "llm", claim_evidence: {
    version: 1, source_check: { kind: "not_recorded" }, required_conditions: null,
    conditions_status: "not_checked", consequence_status: "not_checked",
    observation: "Navigation never recovers", context_checks: [{ kind: "react_async_context",
      scope: "Page.submit", checks: [{ kind: "react_async_state_reset",
        summary: "Catch at line 20 contains a saving=false setter at line 22 after earlier statements that may throw.",
        detail: "UI recovery is not proven." }, { kind: "react_async_http_response",
        summary: "Awaited fetch at line 15. Response.ok branches: http_error at line 16.",
        detail: "An HTTP error response does not itself reject." }] }] } };
  const before = JSON.stringify(finding);
  const rows = claimEvidenceRows(finding);
  expect(rows.filter(([label]) => label.startsWith("React error-path evidence"))).toHaveLength(2);
  expect(rows.flat().join(" ")).toContain("after earlier statements that may throw");
  expect(rows.flat().join(" ")).toContain("HTTP error response does not itself reject");
  expect(rows.flat()).toContain("Navigation never recovers");
  expect(findingCounts([finding])).toEqual({ source: 1, examples: 0 });
  expect(JSON.stringify(finding)).toBe(before);
  expect(claimEvidenceRows({ ...finding, claim_evidence: { version: 1,
    source_check: { kind: "not_recorded" }, observation: null, required_conditions: null,
    conditions_status: "not_checked", consequence_status: "not_checked",
    context_checks: [{ kind: "react_async_context", checks: [{ kind: "react_async_state_reset" }] }] } })
    .some(([label]) => label.startsWith("React error-path evidence"))).toBe(false);
});

it("separates examples from the source headline and category count", () => {
  const findings = [source, { ...source, file: "tests/config.py", context: "test_file" }];
  expect(findingCounts(findings)).toEqual({ source: 1, examples: 1 });
  const rows = coverageRows({ total: 0, categories: {}, basis: "static_only" }, findings);
  expect(rows.find(([name]) => name === "Security")?.[1])
    .toBe("Partly checked · 1 unverified finding · 1 test/example observations");
});

it("replaces categorical legacy credential prose without dropping occurrence evidence", () => {
  const text = plainFields({ ...source, context: "test_file", occurrence_count: 2,
    occurrence_files: ["tests/a.py", "tests/b.py"],
    explanation: "An attacker controls the account", fix_hint: "Rotate everything" });
  expect(text.risk).toContain("alone cannot authenticate");
  expect(text.risk).toContain("test, example or comment");
  expect(text.risk).toContain("tests/a.py, tests/b.py");
  expect(text.fix).not.toContain("Rotate everything");
});

it("does not invent execution records for old audits", () => {
  expect(manifestRows({ total: 0, categories: {} }))
    .toEqual([["Scan record", "Not recorded for this older audit"]]);
});

it("counts underlying observations in display-only schema groups", () => {
  expect(findingCounts([{ ...source, occurrence_titles: ["Table A", "Table B"] },
    { ...source, file: "tests/schema.sql" }])).toEqual({ source: 2, examples: 1 });
});

it("shows operation evidence and limits without assigning finding severity", () => {
  const manifest: ScanManifest = {
    archive_sha256: "test-digest", commit_sha: null, engine_version: "test", archive_files: 1,
    static_checks: [], static_limits: {}, inventory: {}, model: null, model_calls: 0,
    rubrics_completed: [], llm_candidate_files: null, llm_submitted_files: null,
    llm_files_not_submitted: null, limitations: [], runtime_verified: false,
    source_facts: { scope: "Syntax only", parsed_files: 0, excluded_files: 0, limitations: [], facts: [],
      operations: { scope: "Names are not resolved", parsed_files: 1, excluded_files: 0,
        limitations: ["record_limit_reached"], records: [{ kind: "javascript_fetch_context",
          file: "api.ts", line: 4, scope: "request", call: "fetch", detail: "Input trust not checked" }] } },
  };
  const rows = Object.fromEntries(manifestRows({ total: 0, categories: {}, scan_manifest: manifest }));
  expect(rows["Operation context 1"]).toBe("api.ts:4 — request: fetch\nInput trust not checked");
  expect(rows["Operation context limits"]).toBe("record_limit_reached");
});

it("shows React async evidence without model calls and preserves syntax limits", () => {
  const manifest: ScanManifest = {
    archive_sha256: "digest", commit_sha: null, engine_version: "test", archive_files: 1,
    static_checks: [], static_limits: {}, inventory: {}, model: null, model_calls: 0,
    rubrics_completed: [], llm_candidate_files: null, llm_submitted_files: null,
    llm_files_not_submitted: null, limitations: [], runtime_verified: false,
    source_facts: { scope: "Syntax only", parsed_files: 0, excluded_files: 0, limitations: [], facts: [],
      react_async: { scope: "No runtime or concurrency proof", parsed_files: 1, excluded_files: 0,
        limitations: ["ambiguous_state_binding"], records: [{ file: "page.tsx", line: 10, line_end: 20,
          scope: "Page.send", await_lines: [13], checks: [{ kind: "react_async_state_reset",
            result: "observed", direct_reset_line: 14, finally_reset_line: null }],
          controls: [{ line: 30, line_end: 30, event: "onClick", disabled: "state_truthy", state: "busy" }] }] } },
  };
  const rows = Object.fromEntries(manifestRows({ total: 0, categories: {}, basis: "static_only", scan_manifest: manifest }));
  expect(rows["React async context 1"]).toContain("page.tsx:10–20 — Page.send\nAwait lines: 13");
  expect(rows["React async context 1"]).toContain('"finally_reset_line":null');
  expect(rows["React async context 1"]).toContain('Button syntax: {"line":30');
  expect(rows["React async limits"]).toBe("ambiguous_state_binding");
  expect(rows["React async scope"]).toBe("No runtime or concurrency proof");
});


it("distinguishes model processing states and missing older accounting", () => {
  const manifest: ScanManifest = {
    archive_sha256: "digest", commit_sha: null, engine_version: "test", archive_files: 1,
    static_checks: [], static_limits: {}, inventory: {}, model: "paid", model_calls: 2,
    rubrics_completed: [], llm_candidate_files: 1, llm_submitted_files: 1,
    llm_files_not_submitted: 0, limitations: ["invalid_responses"], runtime_verified: false,
    model_findings: [{ model: "paid", responses: 2, invalid_responses: 1, empty_responses: 0,
      received: 4, rejected: 2, accepted: 2, merged: 1, saved: 1,
      rejection_reasons: { missing_fields: 2 } }],
  };
  const rows = Object.fromEntries(manifestRows({ total: 0, categories: {}, scan_manifest: manifest }));
  expect(rows["Finding processing: paid"]).toContain("unreadable: 1; valid empty: 0");
  expect(rows["Finding processing: paid"]).toContain("merged: 1; saved representatives: 1");
  expect(rows["Rejection reasons"]).toContain("missing_fields");
  delete manifest.model_findings;
  expect(Object.fromEntries(manifestRows({ total: 0, categories: {}, scan_manifest: manifest }))[
    "Model finding processing"]).toBe("Not recorded for this audit");
});

it("retains grouped original interpretations without treating repeats as confirmation", () => {
  const rows = Object.fromEntries(claimEvidenceRows({ ...source, claim_evidence: {
    version: 1, source_check: { kind: "not_recorded" }, observation: null, required_conditions: null,
    conditions_status: "not_checked", consequence_status: "not_checked",
    grouped_originals: [{ title: "First hypothesis", explanation: "Original reasoning" },
      { title: "Other wording", explanation: "Other reasoning" }],
  } }));
  expect(rows["Grouped original 1 — not independent confirmation"]).toContain("Original reasoning");
  expect(rows["Grouped original 2 — not independent confirmation"]).toContain("Other reasoning");
  expect(rows["Consequence check"]).toBe("No independent verification recorded.");
});

it("shows source counterevidence and policy prerequisites without turning them into verified outcomes", () => {
  const rows = Object.fromEntries(claimEvidenceRows({ ...source, claim_evidence: {
    version: 1, source_check: { kind: "not_recorded" }, observation: "Model interpretation",
    required_conditions: null, conditions_status: "not_checked", consequence_status: "not_checked",
    context_checks: [
      { kind: "guard_context", file: "auth.ts", line: 24,
        summary: "A state comparison precedes the exchange; runtime validity was not checked." },
      { kind: "cost_context", file: "chat.ts", line: 5, checks: [
        { summary: "The imported helper contains numeric slice limits; total request cost is unknown." } ] },
      { kind: "rls_recommendation_context", file: "route.ts", line: 12,
        summary: "SELECT policies alone do not authorize writes. Check policy prerequisites before changing clients." },
    ],
  } }));
  expect(rows["Existing guard evidence — compare with the model claim"]).toContain("auth.ts:24");
  expect(rows["Cost and ordering evidence — compare with the model claim"]).toContain("total request cost is unknown");
  expect(rows["Policy prerequisites — review before changing clients"]).toContain("SELECT policies alone");
  expect(rows["Consequence check"]).toBe("No independent verification recorded.");
});


it("preserves a compound finding while exposing a contradicted atom and superseded recommendation", () => {
  const finding: Finding = { ...source, rule_id: "llm-web", source: "llm", claim_evidence: {
    version: 1, source_check: { kind: "not_recorded" }, required_conditions: null,
    conditions_status: "not_checked", consequence_status: "not_checked", observation: null,
    premise_checks: [{ kind: "json_rejection_uncaught", target: "res", result: "contradicted",
      claim: "JSON parsing lacks a rejection fallback.", detail: "A local fallback exists; fetch rejection is separate." }],
    recommendation_check: { result: "prerequisites_required", detail: "Verify write policies before changing clients.",
      original_fix_hint: "Switch clients; policies already exist." },
  } };
  const rows = Object.fromEntries(claimEvidenceRows(finding));
  expect(rows["Atomic premise contradicted — other claims remain unverified"]).toContain("fetch rejection is separate");
  expect(rows["Superseded original recommendation — do not apply without review"]).toContain("policies already exist");
  expect(rows["Recommendation prerequisites"]).toContain("Verify write policies");
  expect(findingCounts([finding])).toEqual({ source: 1, examples: 0 });
  const contradicted = { ...finding, claim_evidence: { ...finding.claim_evidence!,
    syntax_check: { kind: "http_status_guard_absent" as const, result: "contradicted" as const,
      claim: "No HTTP status guard", detail: "The same response has a return guard." } } };
  expect(findingCounts([contradicted])).toEqual({ source: 0, examples: 0 });
});
