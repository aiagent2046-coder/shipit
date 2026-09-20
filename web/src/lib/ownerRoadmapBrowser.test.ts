import { expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import cases from "../../../tests/fixtures/owner-roadmap.json";
import type { projectOwnerRoadmap } from "./ownerRoadmap";

const source = readFileSync("../browser/src/app.js", "utf8");
const validators = source.slice(source.indexOf("function normalizeAcquisition("),
  source.indexOf("function renderSecurityAgent(agent)"));
const block = (name: string) => {
  const begin = `// BEGIN ${name} PROJECTION`, end = `// END ${name} PROJECTION`;
  if (!source.includes(begin) || !source.includes(end)) throw new Error(`Missing ${name}`);
  return source.slice(source.indexOf(begin), source.indexOf(end));
};
const browserRoadmap: typeof projectOwnerRoadmap = runInNewContext(
  `${validators}; ${block("OWNER REPORT")}; ${block("OWNER ROADMAP")}; projectOwnerRoadmap`,
  { structuredClone, sha256 },
);

it.each(cases)("browser roadmap preserves the $name plan and original data", fixture => {
  const input = structuredClone(fixture.input);
  const before = JSON.stringify(input);
  expect(browserRoadmap(input.findings, input.context)).toEqual(fixture.expected);
  expect(JSON.stringify(input)).toBe(before);
});
