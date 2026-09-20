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
  for (const key of ["security_agent", "archive_sha256", "engine_version", "dependency_cve", "runtime_verified"]) {
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
