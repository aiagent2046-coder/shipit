import { expect, it } from "vitest";
import { coverageRows, findingCounts, manifestRows } from "./evidence";
import { plainFields } from "./plain";
import type { Finding, ScanManifest } from "./types";

const source: Finding = { rule_id: "aws-access-key-id", title: "AWS match",
  category: "Security", severity: "high", confidence: 1, file: "app/config.py" };

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
