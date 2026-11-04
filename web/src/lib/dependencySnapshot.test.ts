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

const kevSnapshot = { repository: "https://github.com/cisagov/kev-data", commit: "d".repeat(40),
  generated_at: "2026-11-03T21:32:24Z", catalog_version: "2026.11.03", sha256: "e".repeat(64) };
const kevListed = { status: "listed", source: "cisa-kev", cve_id: "CVE-2025-12345", date_added: "2026-10-01",
  due_date: "2026-10-22", ransomware: "Known", snapshot: kevSnapshot };

function dependencyFinding(exploitation?: unknown): Finding {
  return { rule_id: "dependency-cve-match", source: "dependency", verification_method: "package_version_match",
    claim_evidence: { version: 1, snapshot_sources: [{ name: "cvelist", repository: "https://github.com/CVEProject/cvelistV5",
      commit: "a".repeat(40), generated_at: "2026-11-02T00:00:00Z" }],
      ...(exploitation === undefined ? {} : { exploitation }) } } as unknown as Finding;
}

it.each([
  [kevListed, "Listed in the CISA Known Exploited Vulnerabilities catalog as CVE-2025-12345; added 2026-10-01; "
    + "federal due date 2026-10-22; known ransomware campaign use: Known. KEV catalog version 2026.11.03."],
  [{ status: "not_listed", source: "cisa-kev", snapshot: kevSnapshot }, "Not listed in CISA KEV catalog version 2026.11.03. Absence does not establish"],
  [{ status: "not_assessed" }, "Not assessed; this finding's snapshot carried no exploitation source."],
  [undefined, "Not assessed; this finding's snapshot carried no exploitation source."],
  [{ ...kevListed, ransomware: "Maybe" }, "Recorded but unreadable; treat as not assessed."],
  [{ ...kevListed, snapshot: { ...kevSnapshot, sha256: "short" } }, "Recorded but unreadable; treat as not assessed."],
  [{ ...kevListed, snapshot: { ...kevSnapshot, commit: "short" } }, "Recorded but unreadable; treat as not assessed."],
  [{ status: "listed", source: "cisa-kev", snapshot: kevSnapshot }, "Recorded but unreadable; treat as not assessed."],
  [{ status: "not_listed", source: "other", snapshot: kevSnapshot }, "Recorded but unreadable; treat as not assessed."],
])("known exploitation row mirrors the Python report %#", (exploitation, fragment) => {
  const rows = Object.fromEntries(claimEvidenceRows(dependencyFinding(exploitation)));
  expect(rows["Known exploitation"]).toContain(fragment);
  expect(evidenceLabel(dependencyFinding(exploitation))).toBe("Dependency version match — reachability unverified");
});
