import { expect, it } from "vitest";
import cases from "../../../tests/fixtures/owner-report.json";
import reports from "../../../tests/fixtures/deserialization-file-agent.json";
import { projectOwnerReport, type OwnerReportContext } from "./ownerReport";

type Change = { op: string; path: (string | number)[]; value?: unknown };

it.each(cases)("projects the same saved $name owner view as Python without changing evidence", fixture => {
  const report = structuredClone(reports.find(item => item.name === fixture.fixture)!.report);
  const context: OwnerReportContext = {};
  for (const key of ["security_agent", "archive_sha256", "engine_version", "dependency_cve", "runtime_verified"] as const) {
    if (key in report) context[key] = (report as Record<string, unknown>)[key];
  }
  const input = { findings: report.findings, context };
  for (const change of fixture.changes as Change[]) {
    let target = input as Record<string | number, unknown>;
    for (const key of change.path.slice(0, -1)) target = target[key] as Record<string | number, unknown>;
    const key = change.path.at(-1)!;
    if (change.op === "delete") delete target[key]; else target[key] = structuredClone(change.value);
  }
  const before = JSON.stringify(input);
  expect(projectOwnerReport(input.findings, input.context)).toEqual(fixture.expected);
  expect(JSON.stringify(input)).toBe(before);
});

it("counts a repeated location once without deleting either original record", () => {
  const report = reports[0].report;
  const duplicate = structuredClone(report.findings[0]);
  const result = projectOwnerReport([report.findings[0], duplicate], report);
  expect(result.cards.map(card => card.finding_index)).toEqual([0, 1]);
  expect(result.summary?.text).toContain("1 file-loading location needs");
});

it("does not invent a positive project verdict when no supported owner card exists", () => {
  expect(projectOwnerReport([], { runtime_verified: false })).toEqual({ version: 1, cards: [], summary: null });
  expect(projectOwnerReport(null)).toEqual({ version: 1, cards: [], summary: null });
});

it.each(["mode", "status"])("does not coerce a malformed saved %s into a supported agent record", key => {
  const report = structuredClone(reports[0].report);
  const agent = report.security_agent as Record<string, unknown>;
  agent[key] = [agent[key]];
  const result = projectOwnerReport(report.findings, report);
  expect(result.cards).toHaveLength(2);
  expect(result.cards.every(card => card.source_refs.length === 0)).toBe(true);
});
