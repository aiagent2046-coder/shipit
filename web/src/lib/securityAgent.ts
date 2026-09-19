import type { Finding } from "./types";

type Rows = [string, string][];
export interface PatternReviewView {
  status: "completed" | "partial" | "unavailable";
  rows: Rows;
  observations: { id: string; title: string; file: string; line: number; rows: Rows }[];
}

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown, fallback = "Not recorded"): string =>
  typeof value === "string" && value.length > 0 ? value : fallback;
const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const number = (value: unknown) => count(value) ? String(value) : "Not recorded";
const label = (value: unknown) => text(value).replaceAll("_", " ");
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

function sqlTraceRows(value: unknown, file: unknown, line: unknown): Rows {
  // Mirror app.scan.security_agent.sql_observation. A renderer does not infer
  // source/driver/runtime proof from a stored claim or a familiar method name.
  if (!object(value) || (value.version !== 1 && value.version !== 2)
    || value.method !== "python_ast_local_flow"
    || value.file !== file || !digest(value.source_sha256)
    || !["concatenation", "percent_format", "f_string", "format_call", "join_call"].includes(text(value.assembly_kind, ""))
    || !["execute", "executemany", "executescript", "raw", "execute_sql"].includes(text(value.sink_method, ""))
    || value.flow_status !== "possible_local_flow"
    || value.input_control_status !== "not_checked"
    || !count(value.assembly_line) || value.assembly_line < 1 || value.assembly_line > 2 ** 31 - 1
    || !count(value.sink_line) || value.sink_line < 1 || value.sink_line > 2 ** 31 - 1
    || value.sink_line !== line) return [];
  const proof = value.driver_provenance;
  let driver = value.version === 1 ? "Not checked in this historical report."
    : "Unknown; cursor provenance was not established.";
  if (value.version === 1 ? value.driver_status !== "not_checked"
    : !["unknown", "source_resolved"].includes(text(value.driver_status, ""))) return [];
  if (value.version === 2 && value.driver_status === "source_resolved") {
    if (!object(proof) || proof.version !== 1 || proof.driver !== "psycopg3"
      || proof.method !== "python_ast_straight_line" || !["execute", "executemany"].includes(text(value.sink_method))
      || !count(proof.import_line) || !count(proof.connection_line) || !count(proof.cursor_line)
      || proof.import_line < 1 || proof.import_line > proof.connection_line
      || proof.connection_line > proof.cursor_line || proof.cursor_line > value.sink_line) return [];
    driver = `Psycopg 3: import line ${proof.import_line} → connect() line ${proof.connection_line} → `
      + `cursor() line ${proof.cursor_line}. Static source provenance only; `
      + "installed driver and runtime behavior are unverified.";
  } else if ("driver_provenance" in value) return [];
  return [
    ["SQL source trace", `${value.assembly_kind} at line ${value.assembly_line} → `
      + `${value.sink_method}() at line ${value.sink_line}. Possible local flow; `
      + "input control and runtime behavior were not checked."],
    ["SQL source SHA-256", value.source_sha256],
    ["SQL driver source", driver],
  ];
}

export function sqlEvidenceRows(finding: Finding): Rows {
  if (finding.source !== "static" || finding.rule_id !== "sql-injection-string-built-query"
    || finding.claim_evidence?.version !== 1) return [];
  return sqlTraceRows(finding.claim_evidence.sql_observation, finding.file, finding.line);
}

export function patternReview(value: unknown): PatternReviewView | null {
  // Older/future records must not acquire a review or a stronger verdict.
  if (!object(value) || value.version !== 1 || value.mode !== "deterministic_static"
    || !(value.status === "completed" || value.status === "partial" || value.status === "unavailable")
    || value.automatic_patch !== false || value.runtime_verified !== false
    || !Array.isArray(value.plan) || !Array.isArray(value.observations) || !object(value.budget)) return null;
  const catalog = object(value.catalog) ? value.catalog : {};
  const source = object(value.source) ? value.source : {};
  const budget = value.budget;
  const knownStops = ["agent_unavailable", "checks_unavailable", "candidate_budget_exhausted",
    "coverage_incomplete", "bounded_review_completed"];
  const stop = typeof value.stop_reason === "string" && (knownStops.includes(value.stop_reason)
    || /^agent_error: [A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value.stop_reason)) ? value.stop_reason : "Stop reason not recorded";
  const rows: Rows = [
    ["Pattern review", `${value.status}; ${value.observations.length} observations; ${stop}. `
      + "Completion describes bounded review, not project safety."],
    ["Pattern catalog", `${text(catalog.version, "Unavailable")}; SHA-256: `
      + (digest(catalog.sha256) ? catalog.sha256 : "Unavailable")],
    ["Patterns in catalog", number(catalog.cards)],
    ["Review source SHA-256", digest(source.archive_sha256) ? source.archive_sha256 : "Not recorded"],
    ["Review engine", text(source.engine_version)],
    ["Candidate review", `${number(budget.processed)} processed / ${number(budget.candidates_found)} found; `
      + `${number(budget.candidates_omitted)} omitted; limit ${number(budget.max_candidates)}.`],
    ["Verification and changes", "Runtime tests not run. No automatic patch applied."],
  ];
  for (const step of value.plan) {
    if (!object(step)) continue;
    const coverage = object(step.coverage) ? step.coverage : {};
    const state = ["analyzed", "not_applicable", "partial", "unavailable"].includes(text(step.status, ""))
      ? label(step.status) : "Not recorded";
    rows.push([`Pattern check: ${text(step.title, text(step.pattern_id))}`, `${state}; `
      + `${number(coverage.analyzed_files)} of ${number(coverage.eligible_files)} eligible files analyzed.`]);
  }
  const observations: PatternReviewView["observations"] = [];
  if (!value.observations.length) rows.push(["Pattern observations",
    "No reviewed candidates recorded. An empty result does not establish safety."]);
  for (const item of value.observations.slice(0, 128)) {
    if (!object(item) || typeof item.file !== "string" || !count(item.line) || item.line < 1
      || item.state !== "needs_evidence" || item.next_action !== "manual_review") continue;
    const missing = strings(item.missing_evidence);
    const recipe = item.recipe;
    if (!object(recipe) || recipe.automatic_apply !== false
      || !["manual_guidance", "not_available"].includes(text(recipe.status, ""))) continue;
    const evidence = object(item.evidence) ? item.evidence : {};
    const details: Rows = [
      ["Pattern", `${text(item.pattern_id)}; revision ${number(item.pattern_revision)}`],
      ["Candidate weakness classes", (strings(item.weaknesses).filter(v => /^CWE-[1-9][0-9]*$/.test(v)).join(", ") || "Not recorded")
        + " — candidate classes, not verified vulnerabilities."],
      ["Review state", "Needs evidence; the candidate and repair preconditions remain unverified."],
      ...(item.rule_id === "sql-injection-string-built-query" ? sqlTraceRows(evidence.sql_observation, item.file, item.line) : []),
      ["Missing evidence", missing.length ? missing.map(label).join("; ") : "Not recorded; prerequisites are not established."],
      ["Next step", "Manual review: gather the missing evidence before choosing a repair."],
      ["Repair guidance", recipe.status === "manual_guidance" && recipe.automatic_apply === false
        ? `${text(recipe.id)} · manual guidance; check all prerequisites. No automatic patch applied.`
        : "No repair guidance available. No automatic patch applied."],
    ];
    observations.push({ id: text(item.id, String(observations.length)), title: text(item.title, "Static observation"),
      file: item.file, line: item.line, rows: details });
  }
  if (observations.length < value.observations.length) rows.push(["Observation display incomplete",
    `${value.observations.length - observations.length} records could not be displayed within the supported schema and limit.`]);
  return { status: value.status, rows, observations };
}

export function patternReviewNotices(value: unknown): Rows {
  const review = patternReview(value);
  if (!review || review.status === "completed") return [];
  return [["Pattern review incomplete", "The coordinator could not complete its bounded plan. "
    + "Existing findings are retained; missing review does not establish safety."]];
}
