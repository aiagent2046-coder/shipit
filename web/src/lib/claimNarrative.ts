/** Validate a saved correction, never generate one from a model marker.
 * Mirrors app/scan/claim_narrative.py. The archive was checked at creation;
 * rendering checks consistency of its saved bindings and exact active wording.
 */
import type { Finding, NarrativeProjection, SourceAssessment } from "./types";

type RecordValue = Record<string, unknown>;
type Location = RecordValue & { line_start: number; line_end: number; span: [number, number] };
type BoundLocation = Location & { file: string; source_sha256: string };
const record = (v: unknown): v is RecordValue => typeof v === "object" && v !== null && !Array.isArray(v);
const integer = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);
const digest = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const path = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 512
  && !v.includes("\\") && v.split("/").every(p => !["", ".", ".."].includes(p));
const span = (v: unknown): v is [number, number] => Array.isArray(v) && v.length === 2
  && integer(v[0]) && integer(v[1]) && v[0] >= 0 && v[0] < v[1];
const location = (v: unknown): v is Location => record(v) && integer(v.line_start) && integer(v.line_end)
  && v.line_start >= 1 && v.line_start <= v.line_end && span(v.span);
const inside = (v: unknown, outer: unknown): v is Location => location(v) && location(outer)
  && outer.span[0] <= v.span[0] && v.span[1] <= outer.span[1]
  && outer.line_start <= v.line_start && v.line_end <= outer.line_end;
const bound = (v: unknown, hashes: RecordValue): v is BoundLocation => location(v)
  && path(v.file) && digest(v.source_sha256) && hashes[v.file] === v.source_sha256;
const sameKeys = (v: RecordValue, keys: string[]) => Object.keys(v).length === keys.length
  && keys.every(k => Object.hasOwn(v, k));
const producer = (v: unknown): v is NarrativeProjection["original"]["producer"] => record(v)
  && typeof v.model === "string" && v.model.trim().length > 0
  && typeof v.rubric === "string" && v.rubric.trim().length > 0 && integer(v.response) && v.response > 0;
const equalProducer = (a: NarrativeProjection["original"]["producer"], b: NarrativeProjection["original"]["producer"]) =>
  a.model === b.model && a.response === b.response && a.rubric === b.rubric;

function wording(check: SourceAssessment, finding: Finding, hashes: RecordValue): NarrativeProjection["active"] | null {
  const b = check.source_binding;
  if (!bound(b, hashes) || b.file !== finding.file || check.file !== finding.file
    || check.source_sha256 !== b.source_sha256 || check.line_start !== b.line_start || check.line_end !== b.line_end
    || (check.span !== undefined && (!span(check.span) || check.span.some((n, i) => n !== b.span[i])))) return null;
  let used: BoundLocation[];
  let active: NarrativeProjection["active"];
  if (check.kind === "fact_input_count_unbounded") {
    const query = b.query_result, call = b.call, result = b.caller_result, input = b.input_argument;
    const consumerCall = b.consumer_call, callee = b.callee, consumer = b.consumer;
    if (b.line_start !== check.line_start || b.line_end !== check.line_end
      || !inside(query, b) || !inside(call, b) || !inside(result, b) || !inside(input, b)
      || !inside(consumerCall, b) || !inside(call, result) || !inside(input, call)
      || query.span[1] >= result.span[0] || result.span[1] >= consumerCall.span[0]
      || !integer(finding.line) || ![query, call].some(v => v.line_start <= finding.line! && finding.line! <= v.line_end)
      || !integer(b.upper) || b.upper < 0 || b.database_read_bound !== "not_checked" || b.total_prompt_bound !== "not_checked"
      || !bound(callee, hashes) || !bound(consumer, hashes) || !inside(b.return, callee) || !inside(b.slice, b.return)
      || !inside(consumer.return, consumer) || !inside(consumer.mapped_input, consumer.return)) return null;
    used = [b, callee, consumer];
    for (const key of ["resolution", "consumer_resolution"]) {
      const resolution = b[key];
      if (!record(resolution) || !["relative_source_candidate", "literal_config_source_candidate"].includes(String(resolution.kind))) return null;
      if (resolution.configuration !== null && resolution.configuration !== undefined) {
        if (!bound(resolution.configuration, hashes)) return null;
        used.push(resolution.configuration);
      } else if (resolution.kind === "literal_config_source_candidate") return null;
    }
    const observation = `The cited query result passes through a collection cap of ${b.upper} items `
      + "before the recorded fact-block renderer. The preceding database read "
      + "and the complete prompt have not been shown to be bounded by this check.";
    active = {
      title: "Fact count is capped before rendering; database read needs separate review",
      explanation: observation + " An uncapped fact count on this source path is contradicted. "
        + "Database read volume, other prompt inputs, item lengths and actual charges "
        + "remain separate questions; a downstream cap does not settle them.",
      fix_hint: "Inspect the database query and its expected volume separately. If its read volume "
        + "needs a limit or pagination, preserve the intended ordering and fact selection. "
        + "Retain the existing collection cap; assess other prompt inputs and item lengths "
        + "before claiming a total prompt or cost bound.", observation,
    };
  } else {
    const call = b.retry_call, callback = b.callback, wrapper = b.wrapper, identity = check.operation_identity;
    const checks = b.response_status_checks, parses = b.response_json_calls;
    if (!bound(wrapper, hashes) || wrapper.file !== finding.file || !inside(call, b) || !inside(callback, call)
      || !integer(finding.line) || ![call, wrapper].some(v => v.line_start <= finding.line! && finding.line! <= v.line_end)
      || !record(identity) || !sameKeys(identity, ["version", "mechanism", "file", "source_sha256", "operation_span"])
      || identity.version !== 1 || !["retry_poll_execution", "insert_count_schedule", "duplicate_key_dispatch"].includes(String(identity.mechanism))
      || identity.file !== finding.file || identity.source_sha256 !== b.source_sha256 || !span(identity.operation_span)
      || identity.operation_span[1] > 256000 || identity.operation_span.some((n, i) => n !== call.span[i])
      || !integer(b.maximum_attempts) || b.maximum_attempts < 1 || !integer(b.maximum_additional_attempts)
      || b.maximum_additional_attempts !== b.maximum_attempts - 1
      || !["literal_loop_bound", "parameter_default", "literal_call_override"].includes(String(b.attempt_bound_mode))
      || !Array.isArray(checks) || !checks.length || !Array.isArray(parses) || !parses.length
      || [...checks, ...parses].some(v => !location(v) || v.span[0] <= call.span[1])) return null;
    used = [b, wrapper];
    const observation = "The retry callback returns the recorded request. Checks of that response's HTTP "
      + "status and JSON parsing occur after the awaited retry call, outside its callback.";
    active = {
      title: "Request rejection can retry; later response checks are outside the callback",
      explanation: observation + ` The wrapper configures at most ${b.maximum_attempts} total attempts `
        + `(${b.maximum_additional_attempts} additional attempt${b.maximum_additional_attempts === 1 ? "" : "s"}). Failures in those later response checks `
        + "do not re-enter this retry invocation. Request rejection can still retry; "
        + "runtime outcomes and repeated charges are not established by this source check.",
      fix_hint: "Review the request rejection and timeout policy separately from HTTP status handling. "
        + "Before repeating an operation after an uncertain response, check its remote outcome "
        + "and applicable idempotency support. Verify actual attempts and charges separately; "
        + "do not attribute retries to response checks outside this callback.", observation,
    };
  }
  const usedHashes = Object.fromEntries(used.map(v => [v.file, v.source_sha256]));
  return sameKeys(hashes, Object.keys(usedHashes)) && Object.entries(usedHashes).every(([k, v]) => hashes[k] === v)
    ? active : null;
}

export function narrativeProjection(finding: Finding, assessments: SourceAssessment[]): NarrativeProjection | null {
  const evidence = finding.claim_evidence, p: unknown = evidence?.narrative_projection;
  if (finding.source !== "llm" || finding.verification_method !== "model_review" || evidence?.version !== 1
    || !record(p) || p.version !== 1 || p.method !== "source_bound_projection"
    || !["fact_input_count_unbounded", "retry_callback_scope"].includes(String(p.kind)) || p.whole_finding !== false
    || !Array.isArray(p.applied_checks) || p.applied_checks.length !== 1 || p.applied_checks[0] !== p.kind
    || !record(p.source_hashes) || !record(p.original) || !record(p.active) || typeof p.previous_fix_hint !== "string"
    || !["title", "explanation", "fix_hint"].every(k => typeof (p.original as RecordValue)[k] === "string")
    || (p.original.observation !== null && typeof p.original.observation !== "string")
    || !producer(p.original.producer) || !producer(evidence.producer) || !equalProducer(p.original.producer, evidence.producer)
    || evidence.source_check?.kind !== "quote_match" || !integer(evidence.source_check.line_start)
    || !integer(evidence.source_check.line_end) || !integer(finding.line) || evidence.source_check.line_start < 1
    || evidence.source_check.line_start > finding.line || finding.line > evidence.source_check.line_end) return null;
  const candidates = assessments.filter(c => ["fact_input_count_unbounded", "retry_callback_scope"].includes(c.kind)
    && c.result === "contradicted" && c.whole_finding === false);
  if (candidates.length !== 1 || candidates[0].kind !== p.kind) return null;
  const expected = wording(candidates[0], finding, p.source_hashes);
  if (!expected || !sameKeys(p.active, Object.keys(expected))) return null;
  for (const key of ["title", "explanation", "fix_hint", "observation"] as const) {
    if (p.active[key] !== expected[key] || p.active[key] !== (key === "observation" ? evidence.observation : finding[key])) return null;
  }
  return p as unknown as NarrativeProjection;
}
