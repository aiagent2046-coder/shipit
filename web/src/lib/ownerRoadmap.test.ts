import { expect, it } from "vitest";
import cases from "../../../tests/fixtures/owner-roadmap.json";
import { projectOwnerRoadmap, type OwnerRoadmapTask } from "./ownerRoadmap";
import type { OwnerReportContext } from "./ownerReport";

it.each(cases)("projects the same $name roadmap as Python without changing the saved report", fixture => {
  const input = structuredClone(fixture.input);
  const before = JSON.stringify(input);
  const roadmap = projectOwnerRoadmap(input.findings, input.context as OwnerReportContext);
  expect(roadmap).toEqual(fixture.expected);
  expect(JSON.stringify(input)).toBe(before);
  const seen = new Set<string>();
  for (const task of roadmap.tasks) {
    expect(seen.has(task.id)).toBe(false);
    // A dependency must point to an earlier task, never form a cycle or dangle.
    for (const prerequisite of task.depends_on) expect(seen.has(prerequisite)).toBe(true);
    seen.add(task.id);
    const allowedKeys: (keyof OwnerRoadmapTask)[] = ["id", "stage", "kind", "title", "why", "action", "owner",
      "needs", "depends_on", "done_when", "finding_indices", "coverage_refs"];
    expect(Object.keys(task).sort()).toEqual(allowedKeys.sort());
  }
});

it("does not coerce truthy status values or missing runtime evidence into tasks", () => {
  expect(projectOwnerRoadmap(null, { dependency_cve: { status: ["partial"] }, runtime_verified: "false" }))
    .toEqual({ version: 1, tasks: [] });
  expect(projectOwnerRoadmap([], { runtime_verified: 0 })).toEqual({ version: 1, tasks: [] });
});
