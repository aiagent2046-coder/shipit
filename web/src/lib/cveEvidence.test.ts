import { expect, it } from "vitest";
import cases from "../../../tests/fixtures/cve-report.json";
import { cveRows, cveNotices } from "./cveEvidence";
import { manifestRows, nonModelStatusNotices } from "./evidence";
import type { Score } from "./types";

for (const c of cases) it(`CVE report parity: ${c.name}`, () => {
  expect(cveRows(c.value)).toEqual(c.rows);
  expect(cveNotices(c.value)).toEqual(c.notices);
  const score = { scan_manifest: { sca_cve: c.value, static_checks: [], rubrics_completed: [],
    static_limits: {}, inventory: {}, limitations: [] } } as unknown as Score;
  const rows = manifestRows(score);
  const notices = nonModelStatusNotices(score);
  for (const row of c.rows) expect(rows).toContainEqual(row);
  for (const notice of c.notices) expect(notices).toContainEqual(notice);
});
