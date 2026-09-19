import { expect, it } from "vitest";
import reports from "../../../tests/fixtures/security-agent-reports.json";
import { claimEvidenceRows, manifestRows, nonModelStatusNotices } from "./evidence";
import { patternReview, sqlEvidenceRows } from "./securityAgent";
import type { Finding, Score } from "./types";

const completed = reports.find(report => report.name === "completed")!;
const record = completed.score.scan_manifest.security_agent;
const finding = completed.finding as unknown as Finding;

it.each(reports)("preserves the saved $name scan and explains the bounded review", report => {
  const before = JSON.stringify(report);
  const score = report.score as unknown as Score;
  const saved = report.score.scan_manifest.security_agent;
  const review = patternReview(saved)!;
  expect(review.status).toBe(saved.status);
  expect(review.observations).toHaveLength(saved.observations.length);
  expect(score.scan_manifest!.model_calls).toBe(0);
  const rows = Object.fromEntries(manifestRows(score));
  expect(rows["Pattern review"]).toContain(saved.stop_reason);
  expect(rows["Pattern review"]).toContain("Completion describes bounded review, not project safety.");
  if (saved.catalog) expect(rows["Pattern catalog"]).toContain(saved.catalog.sha256);
  expect(nonModelStatusNotices(score).filter(([label]) => label === "Pattern review incomplete"))
    .toHaveLength(saved.status === "completed" ? 0 : 1);
  expect(JSON.stringify(nonModelStatusNotices(score))).not.toMatch(/security_agent_(incomplete|unavailable)/);
  const evidence = Object.fromEntries(claimEvidenceRows(report.finding as unknown as Finding));
  expect(evidence["Static observation — unverified"]).toBe(report.finding.claim_evidence.observation);
  expect(evidence["Model interpretation — unverified"]).toBeUndefined();
  expect(evidence["SQL source trace"]).toBe("concatenation at line 2 → execute() at line 3. Possible local flow; "
    + "driver identity, input control and runtime behavior were not checked.");
  expect(evidence["SQL source SHA-256"]).toBe(report.finding.claim_evidence.sql_observation.source_sha256);
  for (const observation of review.observations) {
    const detail = Object.fromEntries(observation.rows);
    expect(detail["Candidate weakness classes"]).toContain("CWE-89");
    expect(detail["Missing evidence"]).toContain("psycopg3 cursor provenance");
    expect(detail["SQL source trace"]).toBe(evidence["SQL source trace"]);
    expect(detail["Repair guidance"]).toContain(saved.observations[0].recipe.id);
  }
  expect(JSON.stringify(report)).toBe(before);
});

it.each([
  ["version", 2], ["runtime_verified", true], ["automatic_patch", true],
  ["mode", "model"], ["status", "verified"], ["budget", []], ["observations", {}], ["plan", null],
])("does not present unsupported or stronger review metadata: %s", (field, value) => {
  expect(patternReview({ ...record, [field as string]: value })).toBeNull();
});

it.each([
  { state: "verified" }, { next_action: "automatic_patch" }, { line: true }, { file: [] },
  { recipe: null }, { recipe: { ...record.observations[0].recipe, automatic_apply: true } },
  { recipe: { ...record.observations[0].recipe, status: "verified" } },
])("retains the review summary and marks an unsupported observation as undisplayed: %j", invalid => {
  const review = patternReview({ ...record, observations: [{ ...record.observations[0], ...invalid }] })!;
  expect(review.status).toBe("completed");
  expect(review.observations).toEqual([]);
  expect(Object.fromEntries(review.rows)["Observation display incomplete"])
    .toBe("1 records could not be displayed within the supported schema and limit.");
});

it("does not echo a stored exception message or retrieve newer repair instructions", () => {
  const old = { ...record, stop_reason: "agent_error: ValueError: private credentials", observations: [{
    ...record.observations[0], recipe: { status: "manual_guidance", automatic_apply: false, id: "historical-recipe" },
  }] };
  const review = patternReview(old)!;
  expect(JSON.stringify(review)).not.toContain("private credentials");
  expect(Object.fromEntries(review.rows)["Pattern review"]).toContain("Stop reason not recorded");
  expect(Object.fromEntries(review.observations[0].rows)["Repair guidance"]).toContain("historical-recipe");
  expect(JSON.stringify(review)).not.toContain(record.observations[0].recipe.id);
});

it.each([
  { version: 2 }, { file: "another.py" }, { sink_line: 4 }, { assembly_line: true },
  { method: "model_flow" }, { source_sha256: "missing" }, { driver_status: "verified" },
  { input_control_status: "verified" }, { flow_status: "confirmed" },
])("does not display unsupported or mismatched SQL evidence: %j", invalid => {
  const trace = { ...completed.finding.claim_evidence.sql_observation, ...invalid };
  const changed = { ...finding, claim_evidence: { ...finding.claim_evidence!, sql_observation: trace } };
  expect(sqlEvidenceRows(changed)).toEqual([]);
  expect(Object.fromEntries(claimEvidenceRows(changed))["Static observation — unverified"])
    .toBe(finding.claim_evidence!.observation);
  const review = patternReview({ ...record, observations: [{ ...record.observations[0], evidence: {
    sql_observation: trace,
  } }] })!;
  expect(Object.fromEntries(review.observations[0].rows)["SQL source trace"]).toBeUndefined();
});

it.each([
  ["llm", "llm-security", "Model interpretation — unverified"],
  [undefined, "llm-security", "Model interpretation — unverified"],
  ["dependency", "dependency-cve-match", "Source observation — unverified"],
  [undefined, "old-rule", "Legacy observation — provenance not recorded"],
])("labels the recorded producer without importing a static SQL trace: %s", (source, rule, label) => {
  const changed = { ...finding, source, rule_id: rule } as Finding;
  const rows = Object.fromEntries(claimEvidenceRows(changed));
  expect(rows[label!]).toBe(finding.claim_evidence!.observation);
  expect(rows["SQL source trace"]).toBeUndefined();
  expect(rows["Consequence check"]).toBe("No independent verification recorded.");
});

it("leaves legacy findings readable without inventing a trace or review", () => {
  const changed = structuredClone(finding);
  delete changed.claim_evidence!.sql_observation;
  expect(sqlEvidenceRows(changed)).toEqual([]);
  expect(patternReview(undefined)).toBeNull();
  expect(Object.fromEntries(claimEvidenceRows(changed))["Static observation — unverified"])
    .toBe(finding.claim_evidence!.observation);
});
