import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import reports from "../../../tests/fixtures/deserialization-file-agent.json";
import { FindingsList, OwnerReportSummary } from "./FindingsList";
import { projectOwnerReport } from "@/lib/ownerReport";
import type { Finding } from "@/lib/types";

afterEach(cleanup);

it("shows the saved next action and its limits before technical detail while keeping all original findings", () => {
  const report = structuredClone(reports[0].report), findings = report.findings as Finding[];
  const before = JSON.stringify(report), projection = projectOwnerReport(findings, report);
  render(<><OwnerReportSummary projection={projection} /><FindingsList findings={findings} projection={projection} /></>);
  const summary = screen.getByRole("region", { name: "Report in brief" });
  expect(within(summary).getByRole("link", { name: "See the file-loading question" }).getAttribute("href"))
    .toBe("#owner-finding-0");
  for (const card of projection.cards) {
    const element = document.getElementById(`owner-finding-${card.finding_index}`)!;
    expect(element.tabIndex).toBe(-1);
    for (const value of [...card.known, ...card.unknown, card.next_action, card.done_when]) {
      const text = within(element).getByText(value);
      expect(text.closest("details:not([open])")).toBeNull();
    }
    const developer = within(element).getByText("Details for a developer").parentElement as HTMLDetailsElement;
    expect(developer.open).toBe(false);
    const original = findings[card.finding_index];
    expect(developer.textContent).toContain(original.explanation);
    expect(developer.textContent).toContain(original.fix_hint);
    expect(developer.textContent).toContain(`pickle.load() at line ${original.line}`);
  }
  expect(screen.getByText("Pickle file loading · 2 locations")).toBeTruthy();
  const group = screen.getByText("Pickle file loading · 2 locations").parentElement as HTMLDetailsElement;
  group.open = false;
  fireEvent.click(within(summary).getByRole("link", { name: "See the file-loading question" }));
  expect(group.open).toBe(true);
  expect(document.activeElement?.id).toBe("owner-finding-0");
  expect(JSON.stringify(report)).toBe(before);
});

it("keeps missing evidence visible and never treats an unrelated observation as covered by the owner view", () => {
  const report = structuredClone(reports[0].report);
  const findings = [...report.findings, { ...report.findings[0], rule_id: "another-rule", title: "Separate observation",
    explanation: "A separate issue still needs review.", claim_evidence: null }] as Finding[];
  render(<FindingsList findings={findings} context={{ runtime_verified: false }} />);
  expect(screen.getAllByText("The file path and handle flow have not been established for this call.")).toHaveLength(2);
  expect(screen.queryByText("The code opens the file at the supplied path and passes its contents to this loader.")).toBeNull();
  expect(screen.getByText("A separate issue still needs review.")).toBeTruthy();
});
