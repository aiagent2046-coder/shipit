import { expect, it } from "vitest";
import { coverageRows, findingCounts, manifestRows } from "./evidence";
import { plainFields } from "./plain";
import type { Finding } from "./types";

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
