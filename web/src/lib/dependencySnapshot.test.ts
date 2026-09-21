import { expect, it } from "vitest";
import cases from "./fixtures/dependency_snapshot_cases.json";
import { snapshotCoverage, snapshotMetadata, snapshotNotices, snapshotRows } from "./dependencySnapshot";
import { claimEvidenceRows, evidenceLabel, manifestRows, nonModelStatusNotices } from "./evidence";
import type { Finding, Score } from "./types";

for (const c of cases) it(`snapshot report parity: ${c.name}`, () => {
  const before = JSON.stringify(c);
  expect(snapshotCoverage(c.coverage)?.status ?? null).toBe(c.status);
  const rows = snapshotRows(c.coverage, c.metadata), notices = snapshotNotices(c.coverage, c.metadata);
  expect(notices.map(([title]) => title)).toEqual(c.notice_titles);
  for (const fragment of c.fragments) expect(JSON.stringify(rows)).toContain(fragment);
  if (c.name !== "absent") {
    const score = { basis: "static+preview", scan_manifest: {
      dependency_cve: c.coverage, dependency_snapshot: c.metadata, sca_skipped_reason: "no_client",
      static_checks: [], rubrics_completed: [], static_limits: {}, inventory: {}, model_calls: 1,
      limitations: ["dependency_snapshot_scope", "dependency_runtime_reachability_not_checked"],
    } } as unknown as Score;
    for (const row of rows) expect(manifestRows(score)).toContainEqual(row);
    expect(nonModelStatusNotices(score)).toEqual(notices);
    expect(JSON.stringify(manifestRows(score))).not.toContain("private-cache-value");
  }
  expect(JSON.stringify(c)).toBe(before);
});

it.each([
  ["version", true], ["mode", "network"], ["catalog_sha256", "bad"],
  ["checked_at", "2026-02-30T00:00:00Z"], ["retained_findings", true],
])("rejects invalid metadata %s", (field, value) => {
  expect(snapshotMetadata({ ...cases[0].metadata, [field as string]: value })).toBeNull();
});

it("keeps a retained finding's original source provenance", () => {
  const finding = { rule_id: "dependency-cve-match", source: "dependency", verification_method: "package_version_match",
    claim_evidence: { version: 1, snapshot_sources: [{ name: "cvelist", repository: "https://github.com/CVEProject/cvelistV5",
      commit: "d".repeat(40), generated_at: "2026-09-15T00:00:00Z" }] } } as unknown as Finding;
  expect(evidenceLabel(finding)).toBe("Dependency version match — reachability unverified");
  expect(JSON.stringify(claimEvidenceRows(finding))).toContain("d".repeat(40));
  expect(JSON.stringify(claimEvidenceRows(finding))).toContain("Application reachability was not checked.");
});
