import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { AuditCoverage } from "./AuditCoverage";
import type { Score, ScanManifest } from "@/lib/types";

afterEach(cleanup);

function score(reason = "check_error: RuntimeError", check = "session_cookie"): Score {
  return { total: 10, categories: { Security: 10 }, basis: "static+llm",
    static_incomplete: true, incomplete_static_categories: ["Security"],
    scan_manifest: {
      archive_sha256: "a".repeat(64), commit_sha: null, engine_version: "test",
      archive_files: 1, static_checks: ["secrets"], static_limits: {}, inventory: {},
      static_checks_not_run: [{ check, reason }],
      model: "test", model_calls: 1, rubrics_completed: [], llm_candidate_files: 1,
      llm_submitted_files: 1, llm_files_not_submitted: 0, limitations: ["static_checks_failed"], runtime_verified: false,
    } satisfies ScanManifest };
}

it.each(["session_cookie", "unsafe_xml_parse"])("names failed %s despite a completed model review and an empty finding list", check => {
  render(<AuditCoverage score={score("check_error: RuntimeError", check)} findings={[]} />);
  const notice = screen.getByRole("complementary", { name: "Static checks failed" });
  expect(notice.textContent).toContain(`${check}: check_error: RuntimeError`);
  expect(notice.textContent).toContain("cannot be used for comparison");
  expect(screen.getByText(`Static check failed: ${check}`)).toBeTruthy();
  expect(screen.getByText("Incomplete — static check failed")).toBeTruthy();
  expect(screen.queryByRole("complementary", { name: "Additional audit limitations recorded" })).toBeNull();
});

it("keeps a malformed saved failure visible without reflecting its exception message", () => {
  const { container } = render(<AuditCoverage findings={[]}
    score={score("check_error: RuntimeError: private-source-secret")} />);
  expect(screen.getByRole("complementary", { name: "Static checks failed" }).textContent)
    .toContain("reason_not_recorded");
  expect(container.textContent).not.toContain("private-source-secret");
});
