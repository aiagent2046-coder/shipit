import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { AuditCoverage } from "./AuditCoverage";
import { ConformalRisk } from "./ConformalRisk";
import type { Score } from "@/lib/types";

afterEach(cleanup);

const baseManifest = {
  archive_sha256: "abc123",
  commit_sha: null,
  engine_version: "2026-11-28-2",
  archive_files: 3,
  static_checks: ["cfg_guard_bypass", "ts_cfg_guard_bypass"],
  static_limits: {},
  model: null,
  model_calls: 0,
  rubrics_completed: [],
  llm_candidate_files: null,
  llm_submitted_files: null,
  llm_files_not_submitted: null,
  inventory: {},
  limitations: [],
  runtime_verified: false as const,
};

test("renders nothing when conformal_risk is absent or malformed", () => {
  const { container, rerender } = render(<ConformalRisk value={undefined} />);
  expect(container.innerHTML).toBe("");

  rerender(<ConformalRisk value={{ version: "crc-v1", alpha_fix: "bad" }} />);
  expect(container.innerHTML).toBe("");
});

test("renders three-zone summary and Scan record rows in AuditCoverage when recorded", () => {
  const score: Score = {
    total: 8.5,
    categories: {},
    basis: "static_only",
    scan_manifest: {
      ...baseManifest,
      conformal_risk: {
        version: "crc-2026-11-v1",
        alpha_fix: 0.05,
        alpha_review: 0.2,
        zones: {
          auto_fix_eligible: 2,
          human_review: 1,
          damped_advisory: 0,
        },
        by_stratum: {
          deterministic_ast_cfg: {
            auto_fix_eligible: 2,
            human_review: 0,
            damped_advisory: 0,
          },
          llm_rubric: {
            auto_fix_eligible: 0,
            human_review: 1,
            damped_advisory: 0,
          },
        },
      },
    },
  };

  render(<AuditCoverage score={score} findings={[]} />);
  const region = screen.getByLabelText("Conformal risk control");
  expect(region.textContent).toContain(
    "Conformal risk stratification · auto-fix eligible: 2 · human review: 1 · damped advisory: 0",
  );
  expect(region.textContent).toContain("Conformal stratum: deterministic_ast_cfg");
  expect(region.textContent).toContain("Conformal stratum: llm_rubric");
});
