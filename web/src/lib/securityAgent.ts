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

type AcquisitionSpan = [number, number, number, number];
type AcquisitionFact = {
  id: string; method: string;
  sources?: { parameter: string; channel: string; span: AcquisitionSpan }[];
  locations?: AcquisitionSpan[];
  slots?: { index: number; role: string }[];
  constraints?: { slot: number; kind: string; type: string; span: AcquisitionSpan }[];
};
export interface SourceAcquisition {
  version: 1; status: "completed" | "partial" | "unsupported"; stop_reason: string;
  source: { file: string; source_sha256: string; sink_span?: AcquisitionSpan };
  facts: AcquisitionFact[];
  attempts: { action: string; result: string; reason: string; produced: string[]; detail?: string }[];
  budget: { max_steps: number; steps: number; work_units: number };
}

// Keep this bounded contract in sync with app/scan/evidence_record.py and the
// standalone browser renderer. Saved facts cannot establish runtime safety.
export function normalizeAcquisition(value: unknown, trace: unknown): SourceAcquisition | null {
  const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
  const integer = (v: unknown, min = 0, max = 2 ** 31 - 1): v is number =>
    Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
  const keys = (v: unknown, required: string[], optional: string[] = []): v is Record<string, unknown> =>
    obj(v) && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
  const span = (v: unknown): v is AcquisitionSpan => Array.isArray(v) && v.length === 4
    && v.every(n => integer(n)) && v[0] > 0 && (v[2] > v[0] || v[2] === v[0] && v[3] > v[1]);
  const identifier = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(v);
  // Python uses Unicode identifier rules and counts code points, not UTF-16
  // units. Join controls are not Python identifiers; require absolute end too.
  const parameter = (v: unknown): v is string => typeof v === "string" && v.length <= 256
    && [...v].length <= 128 && /^[_\p{XID_Start}]\p{XID_Continue}*(?![\s\S])/u.test(v)
    && !/[\u200c\u200d]/u.test(v);
  const choice = (v: unknown, options: string[]): v is string => typeof v === "string" && options.includes(v);
  const sha = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
  const actions = ["locate_source", "trace_request_input", "inspect_sql_slots", "collect_value_constraints"];
  const methods: Record<string, string> = { request_input_source: "fastapi_ast_binding",
    local_input_flow: "python_ast_straight_line", sql_value_position: "postgresql_ast_slot_context",
    value_constraints: "python_ast_constraints" };
  const fields: Record<string, string> = { request_input_source: "sources", local_input_flow: "locations",
    sql_value_position: "slots", value_constraints: "constraints" };
  const produces: Record<string, string[]> = { locate_source: [], trace_request_input: ["request_input_source", "local_input_flow"],
    inspect_sql_slots: ["sql_value_position"], collect_value_constraints: ["value_constraints"] };
  const stops = ["source_goal_reached", "no_further_action", "source_unavailable", "source_changed", "source_parse_error",
    "source_limit", "ambiguous_sink", "sink_not_found", "budget_exhausted", "collector_error"];
  const reasons = ["source_snapshot_matched", "source_unavailable", "source_changed", "source_limit", "source_parse_error",
    "sink_not_found", "ambiguous_sink", "request_flow_established", "request_flow_not_established",
    "sql_value_positions_established", "sql_slots_not_established", "value_constraints_recorded",
    "value_constraints_unknown", "collector_failed", "work_budget_exhausted", "step_budget_exhausted"];
  if (!obj(trace) || trace.version !== 2 || trace.method !== "python_ast_local_flow"
    || trace.input_control_status !== "not_checked" || trace.flow_status !== "possible_local_flow"
    || !integer(trace.sink_line, 1)
    || !keys(value, ["version", "status", "stop_reason", "source", "facts", "attempts", "budget"])
    || value.version !== 1 || !choice(value.status, ["completed", "partial", "unsupported"])
    || !choice(value.stop_reason, stops)) return null;
  const driver = trace.driver_provenance;
  const validDriver = trace.driver_status === "source_resolved" && choice(trace.sink_method, ["execute", "executemany"])
    && obj(driver) && driver.version === 1 && driver.driver === "psycopg3" && driver.method === "python_ast_straight_line"
    && integer(driver.import_line, 1, trace.sink_line) && integer(driver.connection_line, 1, trace.sink_line)
    && integer(driver.cursor_line, 1, trace.sink_line)
    && driver.import_line <= driver.connection_line && driver.connection_line <= driver.cursor_line;
  if (trace.driver_status === "source_resolved" && !validDriver
    || trace.driver_status === "unknown" && "driver_provenance" in trace
    || !choice(trace.driver_status, ["unknown", "source_resolved"])
    || !integer(trace.assembly_line, 1)
    || !choice(trace.assembly_kind, ["concatenation", "percent_format", "f_string", "format_call", "join_call"])
    || !choice(trace.sink_method, ["execute", "executemany", "executescript", "raw", "execute_sql"])) return null;
  const source = value.source;
  if (!keys(source, ["file", "source_sha256"], ["sink_span"]) || typeof source.file !== "string"
    || !source.file.length || source.file.length > 4096 || /[\x00-\x1f]/.test(source.file)
    || source.file !== trace.file || !sha(source.source_sha256) || source.source_sha256 !== trace.source_sha256
    || "sink_span" in source && (!span(source.sink_span) || source.sink_span[0] !== trace.sink_line)) return null;
  const { facts, attempts, budget } = value;
  if (!Array.isArray(facts) || facts.length > 4 || !Array.isArray(attempts) || attempts.length > 4
    || !keys(budget, ["max_steps", "steps", "work_units"]) || !integer(budget.max_steps, 0, 4)
    || !integer(budget.steps, 0, budget.max_steps) || budget.steps !== attempts.length || !integer(budget.work_units)) return null;
  const found = new Map<string, AcquisitionFact>();
  for (const fact of facts) {
    if (!obj(fact) || typeof fact.id !== "string" || !Object.hasOwn(methods, fact.id) || found.has(fact.id)
      || fact.method !== methods[fact.id]) return null;
    const field = fields[fact.id], entries = fact[field];
    if (!keys(fact, ["id", "method", field]) || !Array.isArray(entries) || !entries.length
      || entries.length > (["locations", "constraints"].includes(field) ? 128 : 64)) return null;
    if (field === "sources") {
      if (entries.some(item => !keys(item, ["parameter", "channel", "span"]) || !parameter(item.parameter)
        || !choice(item.channel, ["query", "path"]) || !span(item.span))) return null;
    } else if (field === "locations") {
      if (!entries.every(span)) return null;
    } else if (field === "slots") {
      if (!validDriver || entries.some((item, index) => !keys(item, ["index", "role"])
        || item.index !== index || item.role !== "value")) return null;
    } else if (entries.some(item => !keys(item, ["slot", "kind", "type", "span"])
      || !integer(item.slot, 0, 63) || !choice(item.kind, ["declared_type", "int_conversion", "request_string"])
      || !choice(item.type, ["str", "int", "float", "bool"]) || !span(item.span)
      || item.kind === "int_conversion" && item.type !== "int" || item.kind === "request_string" && item.type !== "str")) return null;
    found.set(fact.id, fact as unknown as AcquisitionFact);
  }
  if (found.has("request_input_source") !== found.has("local_input_flow")) return null;
  if (found.has("value_constraints")) {
    if (!found.has("local_input_flow")) return null;
    const covered = new Set(found.get("value_constraints")!.constraints!.map(item => item.slot));
    const slots = found.get("sql_value_position")?.slots?.map(item => item.index)
      ?? Array.from({ length: covered.size }, (_, i) => i);
    if (covered.size !== slots.length || slots.some(index => !covered.has(index))) return null;
  }
  const emitted = new Set<string>();
  let previous = -1;
  for (const attempt of attempts) {
    if (!keys(attempt, ["action", "result", "reason", "produced"], ["detail"])
      || typeof attempt.action !== "string" || !actions.includes(attempt.action)
      || "detail" in attempt && !identifier(attempt.detail)
      || !choice(attempt.result, ["established", "unknown", "unsupported", "error", "budget_exhausted"])
      || !choice(attempt.reason, reasons) || !Array.isArray(attempt.produced)
      || attempt.produced.some(id => typeof id !== "string")) return null;
    const establishedReasons: Record<string, string> = { locate_source: "source_snapshot_matched", trace_request_input: "request_flow_established",
      inspect_sql_slots: "sql_value_positions_established", collect_value_constraints: "value_constraints_recorded" };
    if (attempt.result === "established" && attempt.reason !== establishedReasons[attempt.action]
      || attempt.action === "locate_source" && attempt.result === "established" && !("sink_span" in source)) return null;
    const order = actions.indexOf(attempt.action), produced = new Set<string>(attempt.produced);
    const expected = attempt.result === "established" ? produces[attempt.action] : [];
    if (order <= previous || produced.size !== attempt.produced.length || produced.size !== expected.length
      || expected.some(id => !produced.has(id)) || [...produced].some(id => !found.has(id))
      || order > 0 && (!obj(attempts[0]) || attempts[0].action !== "locate_source" || attempts[0].result !== "established")) return null;
    produced.forEach(id => emitted.add(id)); previous = order;
  }
  if (emitted.size !== found.size || facts.length > 0 && !("sink_span" in source)) return null;
  const complete = found.size === 4;
  if ((value.status === "completed") !== complete || (value.stop_reason === "source_goal_reached") !== complete
    || (value.status === "partial") !== choice(value.stop_reason, ["budget_exhausted", "collector_error", "source_limit"])) return null;
  return structuredClone(value) as unknown as SourceAcquisition;
}

export function acquisitionRows(value: unknown, trace: unknown): [string, string][] {
  const record = normalizeAcquisition(value, trace);
  if (!record) return [];
  const human = (v: string) => v.replaceAll("_", " ");
  const rows: [string, string][] = [["Source investigation", `${record.status}; ${human(record.stop_reason)}. `
    + "Source evidence only; runtime exploitability and repair behavior remain unverified."]];
  const labels: Record<string, string> = { locate_source: "Locate the source", trace_request_input: "Trace request input",
    inspect_sql_slots: "Check SQL value positions", collect_value_constraints: "Check value constraints" };
  for (const step of record.attempts) rows.push([`Investigation: ${labels[step.action]}`, `${human(step.result)}; ${human(step.reason)}`]);
  for (const fact of record.facts) {
    const detail = fact.sources ? fact.sources.map(item => `${item.channel} parameter ${item.parameter} at line ${item.span[0]}`).join("; ")
      : fact.locations ? `Local flow at lines ${fact.locations.map(item => item[0]).join(", ")}`
      : fact.slots ? `${fact.slots.length} substitution(s) in SQL value positions.`
      : fact.constraints!.map(item => `slot ${item.slot + 1}: ${human(item.kind)} ${item.type} at line ${item.span[0]}`).join("; ");
    rows.push([`Source fact: ${human(fact.id)}`, detail]);
  }
  rows.push(["Investigation budget", `${record.budget.steps} of ${record.budget.max_steps} actions; ${record.budget.work_units} work units.`]);
  return rows;
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
    "coverage_incomplete", "bounded_review_completed", "evidence_collection_incomplete"];
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
      || !((item.state === "needs_evidence" && item.next_action === "manual_review")
        || (item.state === "source_evidence_collected" && item.next_action === "review_runtime_contract"))) continue;
    const missing = strings(item.missing_evidence);
    const recipe = item.recipe;
    if (!object(recipe) || recipe.automatic_apply !== false
      || !["manual_guidance", "not_available"].includes(text(recipe.status, ""))) continue;
    const evidence = object(item.evidence) ? item.evidence : {};
    const traceRows = item.rule_id === "sql-injection-string-built-query" ? sqlTraceRows(evidence.sql_observation, item.file, item.line) : [];
    const acquisition = traceRows.length ? normalizeAcquisition(item.acquisition, evidence.sql_observation) : null;
    const collected = item.state === "source_evidence_collected";
    if (collected && acquisition?.status !== "completed") continue;
    const details: Rows = [
      ["Pattern", `${text(item.pattern_id)}; revision ${number(item.pattern_revision)}`],
      ["Candidate weakness classes", (strings(item.weaknesses).filter(v => /^CWE-[1-9][0-9]*$/.test(v)).join(", ") || "Not recorded")
        + " — candidate classes, not verified vulnerabilities."],
      ["Review state", collected ? "Supported source evidence collected; runtime behavior and repair preconditions remain unverified."
        : "Needs evidence; the candidate and repair preconditions remain unverified."],
      ...traceRows,
      ...acquisitionRows(acquisition, evidence.sql_observation),
      ...("acquisition" in item && !acquisition ? [["Source investigation unavailable", "The saved evidence could not be validated. Do not treat missing source facts as established."]] as Rows : []),
      ["Missing evidence", missing.length ? missing.map(label).join("; ") : "Not recorded; prerequisites are not established."],
      ["Next step", collected ? "Review the runtime contract: confirm reachability, input control and expected query behavior before choosing a repair."
        : "Manual review: gather the missing evidence before choosing a repair."],
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
