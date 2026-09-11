import { expect, it } from "vitest";
import cases from "./fixtures/rule_coverage_cases.json";
import { manifestRows, nonModelStatusNotices } from "./evidence";
import type { ScanManifest, Score } from "./types";

const manifest: ScanManifest = {
  archive_sha256: "digest", commit_sha: null, engine_version: "test", archive_files: 1,
  static_checks: [], static_limits: {}, inventory: {}, model: null, model_calls: 0,
  rubrics_completed: [], llm_candidate_files: null, llm_submitted_files: null,
  llm_files_not_submitted: null, limitations: [], runtime_verified: false,
};

function scoreFor(item: typeof cases[number]): Score {
  return { total: 0, basis: "static_only", categories: {}, scan_manifest: {
    ...manifest, static_checks: [item.rule],
    ...(item.record ? { rule_coverage: { [item.rule]: structuredClone(item.record) } } : {}),
  } } as Score;
}

// Python's renderer uses these same expected values for current and stored audits.
it.each(cases)("reports file coverage without inferring safety: $name", item => {
  const score = scoreFor(item);
  const before = JSON.stringify(score);
  const rows = Object.fromEntries(manifestRows(score));
  expect(rows[`File coverage: ${item.label}`]).toBe(item.summary);
  expect(rows[`Files excluded: ${item.label}`] ?? null).toBe(item.exclusions);
  expect(rows[`Files not fully analyzed: ${item.label}`] ?? null).toBe(item.skips);
  const notices = nonModelStatusNotices(score);
  expect(notices.length).toBe(Number(!!item.notice));
  if (item.notice) {
    expect(notices[0][0]).toBe("Static checks incomplete");
    expect(notices[0][1]).toContain(item.notice);
    expect(notices[0][1]).toContain("named rules only");
    expect(notices[0][1]).toContain("does not establish safety");
  }
  expect(JSON.stringify(score)).toBe(before);
});

it("drops unknown metadata, source paths and reason text from stored coverage", () => {
  const score = scoreFor(cases[0]);
  const coverage = score.scan_manifest!.rule_coverage! as Record<string, Record<string, unknown>>;
  const item = coverage[cases[0].rule];
  const privateValue = "private/source/key.py <script>source-value</script>";
  Object.assign(item, { source: privateValue });
  Object.assign(item.exclusion_reasons!, { [privateValue]: privateValue });
  Object.assign(item.skip_reasons!, { [privateValue]: privateValue });
  coverage[privateValue] = structuredClone(item);
  const before = JSON.stringify(score);
  expect(JSON.stringify(manifestRows(score))).not.toContain("private/source");
  expect(JSON.stringify(nonModelStatusNotices(score))).not.toContain("private/source");
  expect(JSON.stringify(score)).toBe(before);
});

it.each([
  ["version", true], ["version", 2], ["eligible_files", true],
  ["attempted_files", -1], ["analyzed_files", "398"], ["skip_reasons", { file_limit: "440" }],
])("keeps invalid %s counters unknown", (field, value) => {
  const score = scoreFor(cases[0]);
  Object.assign(score.scan_manifest!.rule_coverage!.unsafe_deserialization!, { [String(field)]: value });
  const rows = Object.fromEntries(manifestRows(score));
  expect(rows["File coverage: Unsafe deserialization"]).toBe("Not recorded for this audit");
  expect(rows["Files not fully analyzed: Unsafe deserialization"]).toBeUndefined();
  expect(nonModelStatusNotices(score)).toEqual([]);
});

it("does not infer old rule coverage from archive or secrets counters", () => {
  const score: Score = { total: 0, categories: {}, scan_manifest: { ...manifest, archive_files: 840,
    static_checks: ["outbound_url", "tls_verification", "unsafe_deserialization", "path_traversal"],
    static_limits: { tls_verification: "Bounded TLS checks" },
  } };
  const coverage = manifestRows(score).filter(([label]) => label.startsWith("File coverage:"));
  expect(coverage).toHaveLength(4);
  expect(coverage.every(([, value]) => value === "Not recorded for this audit")).toBe(true);
});
