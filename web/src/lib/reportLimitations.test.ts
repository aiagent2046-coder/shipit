import { expect, it } from "vitest";
import cases from "./fixtures/report_limitation_cases.json";
import { manifestRows, modelStatusNotice, nonModelStatusNotices } from "./evidence";
import type { ScanManifest, Score } from "./types";

const manifest: ScanManifest = {
  archive_sha256: "digest", commit_sha: null, engine_version: "test", archive_files: 1,
  static_checks: [], static_limits: {}, inventory: {}, model: "preview", model_calls: 1,
  rubrics_completed: [], llm_candidate_files: 1, llm_submitted_files: 1,
  llm_files_not_submitted: 0, limitations: [], runtime_verified: false,
};

// The HTML report tests read the same expected stage attribution and legacy cases.
it.each(cases)("keeps model, dependency and unknown limits separate: $name", item => {
  const score: Score = { total: 0, categories: {}, basis: item.basis as Score["basis"],
    ...(!item.no_manifest ? { scan_manifest: {
      ...manifest, model_calls: item.calls!, limitations: item.limitations!,
    } } : {}),
  };
  const before = JSON.stringify(score);
  const notice = modelStatusNotice(score);
  expect(notice?.[0] ?? null).toBe(item.model_title);
  for (const detail of item.model_details) expect(notice?.[1]).toContain(detail);
  if (notice) for (const reason of item.other_reasons) expect(notice[1]).not.toContain(reason);
  const otherNotices = nonModelStatusNotices(score);
  const notices = Object.fromEntries(otherNotices);
  expect(otherNotices.length).toBe(Number(!!item.dependency_reasons.length) + Number(!!item.other_reasons.length));
  if (item.dependency_reasons.length) expect(notices[item.dependency_title!]).toContain(item.dependency_detail);
  if (item.other_reasons.length) {
    expect(notices["Additional audit limitations recorded"]).toContain(item.other_reasons.join(", "));
  }
  if (!item.no_manifest) {
    const rows = Object.fromEntries(manifestRows(score));
    for (const [kind, reasons] of [["Model", item.model_reasons], ["Dependency", item.dependency_reasons],
      ["Other audit", item.other_reasons]] as const) {
      expect(rows[`${kind} limits / skip reasons`]).toBe(reasons.length
        ? reasons.join(", ") : kind === "Model" ? "None recorded" : undefined);
    }
  }
  expect(JSON.stringify(score)).toBe(before);
});
