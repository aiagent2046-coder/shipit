import { expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import cases from "../../../tests/fixtures/owner-report.json";
import reports from "../../../tests/fixtures/deserialization-file-agent.json";
import type { projectOwnerReport } from "./ownerReport";

const source = readFileSync("../browser/src/app.js", "utf8");
const validators = source.slice(source.indexOf("function normalizeAcquisition("),
  source.indexOf("function renderSecurityAgent(agent)"));
const projection = source.slice(source.indexOf("// BEGIN OWNER REPORT PROJECTION"),
  source.indexOf("// END OWNER REPORT PROJECTION"));
const browserProjection: typeof projectOwnerReport = runInNewContext(
  `${validators}; ${projection}; projectOwnerReport`, { structuredClone, sha256 });

it.each(cases)("standalone browser preserves the $name evidence boundary", fixture => {
  const report = structuredClone(reports.find(item => item.name === fixture.fixture)!.report);
  const input: { findings: unknown; context: Record<string, unknown> } = { findings: report.findings, context: {} };
  for (const key of ["security_agent", "archive_sha256", "engine_version", "dependency_cve", "runtime_verified",
    "limitations", "sca_skipped_reason", "sca_dependencies", "sca_coverage_incomplete", "sca_incomplete_lockfiles"]) {
    if (key in report) input.context[key] = (report as Record<string, unknown>)[key];
  }
  for (const change of fixture.changes as { op: string; path: (string | number)[]; value?: unknown }[]) {
    let target = input as Record<string | number, unknown>;
    for (const key of change.path.slice(0, -1)) target = target[key] as Record<string | number, unknown>;
    const key = change.path.at(-1)!;
    if (change.op === "delete") delete target[key]; else target[key] = structuredClone(change.value);
  }
  const before = JSON.stringify(input);
  expect(browserProjection(input.findings, input.context)).toEqual(fixture.expected);
  expect(JSON.stringify(input)).toBe(before);
});

it.each([
  { name: "legacy incomplete scope", context: { limitations: ["dependency_coverage_incomplete"],
    sca_skipped_reason: "no_resolvable_lockfile" }, expected: "Dependency checking is incomplete; see the recorded coverage gaps." },
  { name: "unavailable scope", context: { dependency_cve: { status: "unavailable" } },
    expected: "Dependency checking is unavailable; see the recorded coverage gaps." },
  { name: "checked snapshot with disabled live lookup", context: { dependency_cve: { status: "checked" },
    limitations: ["dependency_check_not_run"], sca_skipped_reason: "no_client", sca_dependencies: 12 }, expected: null },
  { name: "malformed legacy facts", context: { limitations: "dependency_coverage_incomplete",
    sca_coverage_incomplete: "true", sca_skipped_reason: ["no_client"], sca_dependencies: true }, expected: null },
])("browser summary preserves $name", ({ context, expected }) => {
  const report = structuredClone(reports[0].report);
  const input = { ...report, dependency_cve: undefined, ...context };
  const before = JSON.stringify(input);
  const notes = browserProjection(input.findings, input).summary!.coverage_notes;
  expect(notes.filter(note => note.startsWith("Dependency checking"))).toEqual(expected ? [expected] : []);
  expect(JSON.stringify(input)).toBe(before);
});
