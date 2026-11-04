import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ProjectChecks } from "./ProjectChecks";
import { projectChecksRows } from "@/lib/projectChecks";
import { threatContextRows } from "@/lib/threatContext";
import cases from "@/lib/fixtures/threat_context_cases.json";
import projects from "@/lib/fixtures/project_checks_cases.json";

afterEach(cleanup);
for (const fixture of cases) it(`renders threat context: ${fixture.name}`, () => {
  const original = JSON.stringify(fixture.value);
  expect(threatContextRows(fixture.value)).toEqual(fixture.rows);
  expect(JSON.stringify(fixture.value)).toBe(original);
});
it("keeps priority visible and escapes package and remediation labels", () => {
  const value = { ...projects[0].value, threat_context: cases[0].value };
  const { container } = render(<ProjectChecks value={value} />);
  const summary = screen.getByText(/CVEs for expedited review: 1/);
  expect(summary.closest("details")).toBeNull();
  expect(summary.textContent).toContain("Project compromise is not established.");
  expect(screen.getByText(/<svg onload=alert\(1\)>/)).toBeTruthy();
  expect(container.querySelector("svg")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(container.textContent).not.toContain("2026-11-23");
});
it("preserves independent project checks when threat metadata is invalid", () => {
  const value = { ...projects[0].value, threat_context: { runtime_verified: true } };
  const rows = projectChecksRows(value);
  expect(rows[0][0]).toBe("Source");
  expect(rows[2][0]).toBe("Ghidra / binary static");
  expect(rows[3]).toEqual(["CISA KEV threat context", "Unavailable: invalid recorded threat context; no prioritization established."]);
});
it("does not invent threat coverage for an older report", () => {
  expect(projectChecksRows(projects[0].value).some(([label]) => label.startsWith("CISA"))).toBe(false);
});
