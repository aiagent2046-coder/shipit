import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ProjectChecks } from "./ProjectChecks";
import { projectChecksRows } from "@/lib/projectChecks";
import cases from "@/lib/fixtures/project_checks_cases.json";

afterEach(cleanup);
for (const fixture of cases) it(`projects saved evidence: ${fixture.name}`, () => {
  const before = JSON.stringify(fixture.value);
  expect(projectChecksRows(fixture.value)).toEqual(fixture.rows);
  expect(JSON.stringify(fixture.value)).toBe(before);
});
it("renders escaped artifact paths without inferring CVEs or authenticated execution", () => {
  const { container } = render(<ProjectChecks value={cases[0].value} />);
  expect(screen.getByRole("region", { name: "Project checks" })).toBeTruthy();
  expect(screen.getByText(/<img src=x onerror=alert\(1\)>.elf/)).toBeTruthy();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText(/hash consistency does not authenticate tool execution/)).toBeTruthy();
  expect(screen.queryByText(/CVE-2099-1234/)).toBeNull();
  expect(screen.getByText(/not run: 1/)).toBeTruthy();
});
it("does not invent a check panel for legacy reports", () => {
  const { container } = render(<ProjectChecks value={undefined} />);
  expect(container.textContent).toBe("");
});
