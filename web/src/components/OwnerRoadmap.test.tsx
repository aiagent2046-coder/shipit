import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import reports from "../../../tests/fixtures/deserialization-file-agent.json";
import { FindingsList, PreviewHistory } from "./FindingsList";
import { OwnerRoadmap } from "./OwnerRoadmap";
import { projectOwnerRoadmap } from "@/lib/ownerRoadmap";
import { projectOwnerReport } from "@/lib/ownerReport";
import type { Finding, Score } from "@/lib/types";

afterEach(cleanup);

it("groups shared follow-up work and opens the exact original finding or prerequisite from a native link", () => {
  const report = structuredClone(reports[0].report);
  const findings = report.findings as Finding[];
  // Keep the original record index while confidence sorting changes display order.
  findings[0].confidence = .4;
  findings[1].confidence = .9;
  const before = JSON.stringify(report);
  const projection = projectOwnerRoadmap(findings, report);
  const { container } = render(<><OwnerRoadmap projection={projection} findings={findings} />
    <FindingsList findings={findings} projection={projectOwnerReport(findings, report)} /></>);
  const roadmap = screen.getByRole("region", { name: "Project roadmap" });
  expect(within(roadmap).getAllByRole("heading", { level: 3 }).map(heading => heading.textContent))
    .toEqual(["First", "After clarification", "If needed"]);
  expect(within(roadmap).getByText("Suggested next steps from this report. These tasks have not been carried out or verified."))
    .toBeTruthy();
  const task = document.getElementById("roadmap-task-file-loading-origin")!;
  const criteria = within(task).getByText("Completion criteria and references").parentElement as HTMLDetailsElement;
  expect(criteria.open).toBe(false);
  criteria.open = true;
  const source = within(criteria).getByRole("link", { name: `Observation 1 · ${findings[0].file}:${findings[0].line}` });
  const group = screen.getByText("Pickle file loading · 2 locations").parentElement as HTMLDetailsElement;
  group.open = false;
  source.focus();
  expect(document.activeElement).toBe(source);
  // Native keyboard activation produces a click with detail 0; no custom key handling is needed.
  fireEvent.click(source, { detail: 0 });
  expect(group.open).toBe(true);
  expect(document.activeElement?.id).toBe("roadmap-finding-0");
  expect(document.getElementById("roadmap-finding-0")!.textContent).toContain(`${findings[0].file}:${findings[0].line}`);
  const later = document.getElementById("roadmap-task-file-loading-decision")!;
  const laterDetails = within(later).getByText("Completion criteria and references").parentElement as HTMLDetailsElement;
  laterDetails.open = true;
  fireEvent.click(within(laterDetails).getByRole("link", { name: projection.tasks[0].title }), { detail: 0 });
  expect(document.activeElement).toBe(task);
  const ids = [...container.querySelectorAll("[id]")].map(element => element.id);
  expect(new Set(ids).size).toBe(ids.length);
  expect(document.getElementById("owner-finding-0")).not.toBeNull();
  expect(JSON.stringify(report)).toBe(before);
});

it("keeps contextual observations and history intact while source links target only the current report", () => {
  const example: Finding = { rule_id: "test-observation", title: "Example observation", source: "static",
    category: "Security", severity: "low", confidence: .5, file: "tests/example.py", line: 4,
    explanation: "Check whether this example is used.", fix_hint: "Retain the original suggestion." };
  const contradicted: Finding = { ...example, source: "llm", rule_id: "llm-web", file: "src/main.ts", line: 7,
    title: "Original contradicted claim", claim_evidence: { version: 1, source_check: { kind: "not_recorded" },
      observation: null, required_conditions: null, conditions_status: "not_checked", consequence_status: "not_checked",
      syntax_check: { kind: "react_hook_order", result: "contradicted", claim: "The hook is conditional.", detail: "The hook is unconditional." } } };
  const findings = [example, contradicted];
  const score: Score = { total: 0, categories: {}, preview_history: { version: 1, preview_audit_id: "prior",
    content_hash: "same", engine_version: "older", model: null, total: 0, matched_count: 0,
    retained_findings: findings, status: "not_reassessed" } };
  const { container } = render(<><OwnerRoadmap projection={projectOwnerRoadmap(findings)} findings={findings} />
    <details><summary>Current observations</summary><FindingsList findings={findings} /></details>
    <PreviewHistory score={score} /></>);
  const roadmap = screen.getByRole("region", { name: "Project roadmap" });
  const task = document.getElementById("roadmap-task-remaining-observations")!;
  const criteria = within(task).getByText("Completion criteria and references").parentElement as HTMLDetailsElement;
  criteria.open = true;
  const current = screen.getByText("Current observations").parentElement as HTMLDetailsElement;
  fireEvent.click(within(roadmap).getByRole("link", { name: "Observation 2 · src/main.ts:7" }));
  expect(current.open).toBe(true);
  expect(document.activeElement?.id).toBe("roadmap-finding-1");
  expect(within(document.getElementById("roadmap-finding-1")!).getByText("Syntax premise contradicted", { selector: "span" })).toBeTruthy();
  expect(within(document.getElementById("roadmap-finding-0")!).getByText("Retain the original suggestion.")).toBeTruthy();
  const history = screen.getByRole("region", { name: "Free audit history" });
  expect(history.textContent).toContain("Not repeated does not mean fixed");
  expect(history.querySelector("[id^='roadmap-finding-']")).toBeNull();
  expect(container.querySelectorAll("#roadmap-finding-0")).toHaveLength(1);
  expect(container.querySelectorAll("#roadmap-finding-1")).toHaveLength(1);
});

it("links recorded coverage gaps and escapes filenames without turning them into a required fix", () => {
  const context = { runtime_verified: false, dependency_cve: { status: "partial",
    incomplete_manifests: { "<script>alert(1)</script>/requirements.txt": "unresolved" } } };
  const { container } = render(<><OwnerRoadmap projection={projectOwnerRoadmap([], context)} findings={[]} />
    <div id="roadmap-coverage" tabIndex={-1}>Original recorded coverage</div></>);
  expect(container.querySelector("script")).toBeNull();
  const details = screen.getAllByText("Completion criteria and references")[0].parentElement as HTMLDetailsElement;
  details.open = true;
  expect(within(details).getByText("Unresolved manifest: <script>alert(1)</script>/requirements.txt")).toBeTruthy();
  fireEvent.click(within(details).getByRole("link", { name: "Dependency coverage" }));
  expect(document.activeElement?.id).toBe("roadmap-coverage");
  expect(screen.getByText(/Docker is only one possible hosting option/)).toBeTruthy();
  expect(screen.queryByRole("checkbox")).toBeNull();
});

it("keeps absent roadmap evidence explicit without a readiness claim", () => {
  render(<OwnerRoadmap projection={projectOwnerRoadmap([])} findings={[]} />);
  expect(screen.getByText("No next steps can be generated from the recorded findings and coverage. This does not establish that the project is ready or safe."))
    .toBeTruthy();
  expect(screen.queryByRole("heading", { name: "First" })).toBeNull();
});

it("assigns one current anchor per input occurrence even when records share identity or classifications", () => {
  const finding: Finding = { rule_id: "no-dockerfile", title: "Inventory observation", source: "static",
    category: "Deploy", severity: "low", confidence: 1, context: "deployment_inventory",
    claim_evidence: { version: 1, source_check: { kind: "not_recorded" }, observation: null, required_conditions: null,
      conditions_status: "not_checked", consequence_status: "not_checked",
      syntax_check: { kind: "react_hook_order", result: "contradicted", claim: "Recorded claim.", detail: "Recorded counterevidence." } } };
  const { container } = render(<FindingsList findings={[finding, finding]} />);
  expect(container.querySelectorAll("#roadmap-finding-0")).toHaveLength(1);
  expect(container.querySelectorAll("#roadmap-finding-1")).toHaveLength(1);
  expect(container.querySelectorAll("[id^='roadmap-finding-']")).toHaveLength(2);
});
