type Rows = [string, string][];
export interface JsSqlReviewView {
  rows: Rows;
  observations: { id: string; title: string; file: string; line: number; rows: Rows }[];
}

export function jsSqlReview(value: unknown, source: unknown): JsSqlReviewView | null {
  const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
  const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 2 ** 31;
  const digest = (v: unknown) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
  const keys = (v: Record<string, unknown>, expected: string[]) => Object.keys(v).length === expected.length && expected.every(key => Object.hasOwn(v, key));
  const states = ["fixed_sql_fragments", "dynamic_sql_unresolved", "unavailable"];
  if (!object(value) || !object(source) || !object(value.source) || value.version !== 1
    || !digest(source.archive_sha256) || typeof source.engine_version !== "string"
    || value.source.archive_sha256 !== source.archive_sha256 || value.source.engine_version !== source.engine_version
    || value.runtime_verified !== false || value.automatic_patch !== false || value.model_calls !== 0
    || typeof value.coverage_partial !== "boolean" || !object(value.budget) || !Array.isArray(value.observations)) return null;
  if (!keys(value, ["version", "source", "status", "budget", "observations", "coverage_partial", "runtime_verified", "automatic_patch", "model_calls"])
    || !keys(source, ["archive_sha256", "engine_version"]) || !keys(value.source, ["archive_sha256", "engine_version"])
    || source.engine_version.length < 1 || source.engine_version.length > 128
    || !keys(value.budget, ["max_candidates", "candidates_found", "processed", "omitted"])) return null;
  const budget = value.budget;
  if (budget.max_candidates !== 32 || !count(budget.candidates_found) || !count(budget.processed)
    || !count(budget.omitted) || budget.processed > 32 || budget.processed !== value.observations.length
    || budget.candidates_found !== budget.processed + budget.omitted || budget.processed !== Math.min(32, budget.candidates_found)) return null;
  const observations: JsSqlReviewView["observations"] = [];
  const ids = new Set<string>();
  for (const item of value.observations) {
    if (!object(item) || typeof item.id !== "string" || !item.id || ids.has(item.id)
      || typeof item.file !== "string" || !item.file || item.file.length > 4096
      || !count(item.line) || item.line < 1 || !states.includes(String(item.state)) || !object(item.analysis)) return null;
    if (!keys(item, ["id", "file", "line", "state", "analysis", "tasks"])) return null;
    ids.add(item.id);
    const a = item.analysis;
    if (a.version !== 1 || a.runtime_verified !== false || a.file !== item.file || a.sink_line !== item.line
      || a.verdict !== item.state || !digest(a.source_sha256)
      || !(a.sink_column === null || (count(a.sink_column) && a.sink_column > 0))
      || !(a.sink_method === null || (typeof a.sink_method === "string" && a.sink_method.length > 0 && a.sink_method.length <= 80))
      || !["present", "absent", "unknown"].includes(String(a.parameter_argument))
      || !Array.isArray(a.fragments) || a.fragments.length > 32 || !Array.isArray(item.tasks) || item.tasks.length !== 3) return null;
    if (!keys(a, ["version", "file", "source_sha256", "sink_line", "sink_column", "sink_method", "verdict", "parameter_argument", "fragments", "reason", "runtime_verified"])) return null;
    const reasons: Record<string, string> = { fixed_literal: "literal", fixed_helper: "single_return_literal_args",
      fixed_const: "stable_const", unknown: "unresolved_expression" };
    for (const f of a.fragments) {
      if (!object(f) || !keys(f, ["line", "kind", "reason"]) || !count(f.line) || f.line < 1 || typeof f.kind !== "string"
        || !Object.hasOwn(reasons, f.kind) || f.reason !== reasons[f.kind]) return null;
    }
    for (let index = 0; index < 3; index++) {
      const task = item.tasks[index];
      const previous = index ? item.tasks[index - 1] : null;
      if (!object(task) || !keys(task, ["agent", "status", "input_sha256", "output_sha256", "depends_on"]) || task.agent !== ["detector", "researcher", "verifier"][index]
        || task.status !== (index && item.state === "unavailable" ? "blocked" : "completed")
        || !digest(task.input_sha256) || !digest(task.output_sha256) || !Array.isArray(task.depends_on)
        || task.depends_on.length !== (index ? 1 : 0)
        || (index && (task.input_sha256 !== previous.output_sha256 || task.depends_on[0] !== previous.output_sha256))) return null;
    }
    if (item.state !== "unavailable" && (a.sink_column === null || a.sink_method === null || a.parameter_argument === "unknown")) return null;
    const fixed = item.state === "fixed_sql_fragments";
    if (fixed && (a.reason !== "proven_fixed" || !a.fragments.length || a.fragments.some(f => f.kind === "unknown"))) return null;
    if (item.state === "dynamic_sql_unresolved" && a.reason !== "unresolved_expression") return null;
    const unavailable = ["invalid_utf8", "unsupported_file", "file_limit", "parse_error", "node_limit", "depth_limit",
      "sink_not_found", "ambiguous_sink", "source_unavailable", "source_limit", "source_changed", "researcher_unavailable"];
    if (item.state === "unavailable" && !unavailable.includes(String(a.reason))) return null;
    const summary = fixed ? "Query text uses fixed fragments within bounded source analysis."
      : item.state === "dynamic_sql_unresolved" ? "Dynamic SQL text remains unresolved; external input control was not established."
      : "Source review unavailable; no conclusion about the query was established.";
    observations.push({ id: item.id, title: "JavaScript SQL source review", file: item.file, line: item.line,
      rows: [["Source result", summary], ["Reason", String(a.reason).replaceAll("_", " ")],
        ["Parameter argument", `${a.parameter_argument}; presence alone does not establish parameter binding or driver behavior.`],
        ["Source fragments", a.fragments.length ? a.fragments.map(f => `Line ${f.line}: ${String(f.kind).replaceAll("_", " ")} (${String(f.reason).replaceAll("_", " ")})`).join("; ") : "No source fragments established."],
        ["Task handoff", "Detector → researcher → verifier; bounded deterministic source review. Saved digests are consistency links, not independent attestation."],
        ["Source SHA-256", String(a.source_sha256)],
        ["Scope", "Static source analysis only. Runtime exploitability and database driver behavior remain unverified. The original finding is retained."]] });
  }
  const partial = value.coverage_partial || budget.omitted > 0 || value.observations.some(item => item.state === "unavailable");
  if (value.status !== (partial ? "partial" : "completed")) return null;
  return { rows: [["JavaScript SQL source review", `${value.status}; ${observations.length} observations; ${budget.omitted} omitted; limit 32.`],
    ["JavaScript SQL review limits", "No LLM calls, runtime execution or automatic patch. Fixed SQL fragments do not establish project safety."]], observations };
}
