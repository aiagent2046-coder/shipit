import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { Finding, Score } from "@/lib/types";
import reports from "../../../tests/fixtures/security-agent-reports.json";
import { AuditCoverage } from "./AuditCoverage";
import { PatternReview } from "./PatternReview";

afterEach(cleanup);

const completed = reports.find(report => report.name === "completed")!;
const unavailable = reports.find(report => report.name === "unavailable")!;

it.each(reports)("renders the real $name pattern review before the scan record", report => {
  const record = report.score.scan_manifest.security_agent;
  const { container } = render(<AuditCoverage score={report.score as unknown as Score}
    findings={[report.finding as unknown as Finding]} />);
  const summary = screen.getByText(
    `Pattern review · ${record.status} · observations: ${record.observations.length}`,
  );
  const details = summary.closest("details")!;
  expect(details.open).toBe(false);
  expect(details.getAttribute("aria-label")).toBe("Pattern review");
  const summaries = Array.from(container.querySelectorAll("details > summary"));
  expect(summaries.indexOf(summary)).toBeLessThan(summaries.indexOf(screen.getByText("Scan record")));

  fireEvent.click(summary);
  expect(details.open).toBe(true);
  expect(details.textContent).toContain(record.stop_reason);
  if (record.catalog) {
    expect(details.textContent).toContain(record.catalog.version);
    expect(details.textContent).toContain(record.catalog.sha256);
  }
  for (const observation of record.observations) {
    expect(within(details).getByRole("heading", { name: observation.title })).toBeTruthy();
    expect(within(details).getByText(`${observation.file}:${observation.line}`)).toBeTruthy();
    for (const weakness of observation.weaknesses) expect(details.textContent).toContain(weakness);
    for (const missing of observation.missing_evidence) {
      expect(details.textContent).toContain(missing.replaceAll("_", " "));
    }
    expect(details.textContent).toContain(observation.recipe.id);
    expect(details.textContent).toContain(observation.evidence.sql_observation.source_sha256);
  }
});

it("keeps the completed source review separate from runtime, driver and patch verification", () => {
  const record = completed.score.scan_manifest.security_agent;
  const { container } = render(<PatternReview value={record} />);
  fireEvent.click(screen.getByText("Pattern review · completed · observations: 1"));
  expect(screen.getByText("Missing evidence").nextElementSibling?.textContent)
    .toContain("psycopg3 cursor provenance");
  expect(screen.getByText("Missing evidence").nextElementSibling?.textContent)
    .toContain("runtime behavior contract");
  expect(screen.getByText("Next step").nextElementSibling?.textContent)
    .toBe("Manual review: gather the missing evidence before choosing a repair.");
  expect(screen.getByText("SQL source trace").nextElementSibling?.textContent)
    .toBe("concatenation at line 2 → execute() at line 3. Possible local flow; "
      + "input control and runtime behavior were not checked.");
  expect(screen.getByText("Verification and changes").nextElementSibling?.textContent)
    .toBe("Runtime tests not run. No automatic patch applied.");
  expect(container.textContent).toContain("Completion describes bounded review, not project safety.");
  expect(container.textContent).not.toMatch(/driver verified|runtime verified|confirmed vulnerability/i);
});

it.each([undefined, null, {}, { version: 99 }])("hides legacy or unrecognized pattern records: %j", value => {
  const { container } = render(<PatternReview value={value} />);
  expect(container.textContent).toBe("");
  expect(container.querySelector("details")).toBeNull();
});

it("keeps legacy audit coverage readable without inventing a pattern review", () => {
  render(<AuditCoverage score={{ ...completed.score, scan_manifest: {
    ...completed.score.scan_manifest, security_agent: undefined,
  } } as unknown as Score} findings={[]} />);
  expect(screen.getByText("Scan record")).toBeTruthy();
  expect(screen.queryByText(/^Pattern review ·/)).toBeNull();
});

it("renders hostile filenames and titles as text without mutating the record", () => {
  const filename = "src/<img src=x onerror=alert(1)>.py";
  const title = "<script>Pattern title</script>";
  const original = completed.score.scan_manifest.security_agent;
  const record = { ...original, observations: original.observations.map(observation => ({
    ...observation, file: filename, title, evidence: { sql_observation: {
      ...observation.evidence.sql_observation, file: filename,
    } },
  })) };
  const before = JSON.stringify(record);
  const { container } = render(<PatternReview value={record} />);
  fireEvent.click(screen.getByText("Pattern review · completed · observations: 1"));
  expect(screen.getByText(`${filename}:3`)).toBeTruthy();
  expect(screen.getByRole("heading", { name: title })).toBeTruthy();
  expect(container.querySelector("script, img")).toBeNull();
  expect(JSON.stringify(record)).toBe(before);
});

it("clears previous observations and catalog data when the record changes", () => {
  const record = completed.score.scan_manifest.security_agent;
  const { container, rerender } = render(<PatternReview value={record} />);
  fireEvent.click(screen.getByText("Pattern review · completed · observations: 1"));
  expect(screen.getByRole("heading", { name: record.observations[0].title })).toBeTruthy();

  rerender(<PatternReview value={unavailable.score.scan_manifest.security_agent} />);
  expect(screen.getByText("Pattern review · unavailable · observations: 0")).toBeTruthy();
  expect(container.textContent).not.toContain("CWE-89");
  expect(container.textContent).not.toContain("src/query.py");
  expect(container.textContent).not.toContain(record.catalog!.sha256);

  rerender(<PatternReview value={undefined} />);
  expect(container.textContent).toBe("");
  expect(container.querySelector("details")).toBeNull();
});
