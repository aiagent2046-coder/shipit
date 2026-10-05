/** Mirrors app/scan/fact_projection_grouping.py. A grouping marker is not proof:
 * every saved original must retain the same validated source correction.
 */
import type { Finding, NarrativeProjection } from "./types";

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const groupScope = {
  mechanism: "fact_count_projection",
  scope: "Same source path and corrected fact-count interpretation only.",
  consequences: "Original conditions and cost claims remain separate and unverified; "
    + "repetition is not independent confirmation.",
};
type ProjectionCheck = (finding: Finding) => NarrativeProjection | null;

// Stable JSON equality retains unknown fields and array order. Reject values
// that JSON would silently omit or coerce rather than treating them as equal.
function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (record(value)) return `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  throw new TypeError("Expected a JSON value");
}

function projectionKey(value: unknown, project: ProjectionCheck): string | null {
  if (!record(value) || !record(value.claim_evidence)) return null;
  const evidence = value.claim_evidence;
  if (evidence.version !== 1 || !Object.hasOwn(evidence, "source_issue_identity")
    || evidence.source_issue_identity !== null || Object.hasOwn(evidence, "grouped_originals")
    || Object.hasOwn(evidence, "grouped_claim_scope") || value.source !== "llm"
    || value.verification_method !== "model_review" || value.verification_status !== "unverified"
    || typeof value.rule_id !== "string" || !value.rule_id.startsWith("llm-")
    || typeof value.confidence !== "number" || !Number.isFinite(value.confidence)
    || value.confidence < 0 || value.confidence > 1
    || evidence.conditions_status !== "not_checked" || evidence.consequence_status !== "not_checked"
    || !Array.isArray(evidence.required_conditions)
    || !evidence.required_conditions.every(condition => typeof condition === "string")) return null;
  const projection = project(value as unknown as Finding);
  if (projection?.kind !== "fact_input_count_unbounded" || !record(evidence.producer)) return null;
  const payload = { ...value }, retainedEvidence = { ...evidence };
  const producer = { ...evidence.producer }, retainedProjection = { ...projection } as Record<string, unknown>;
  delete payload.confidence;
  delete retainedEvidence.required_conditions;
  delete producer.response;
  delete retainedProjection.original;
  delete retainedProjection.previous_fix_hint;
  retainedEvidence.producer = producer;
  retainedEvidence.narrative_projection = retainedProjection;
  payload.claim_evidence = retainedEvidence;
  return canonical(payload);
}

export function validatedFactGroup(finding: Finding, project: ProjectionCheck): boolean {
  try {
    const evidence = finding.claim_evidence;
    if (!record(evidence) || canonical(evidence.grouped_claim_scope) !== canonical(groupScope)
      || !Array.isArray(evidence.grouped_originals) || evidence.grouped_originals.length < 2) return false;
    const retainedEvidence = { ...evidence };
    delete retainedEvidence.grouped_claim_scope;
    delete retainedEvidence.grouped_originals;
    const representative = { ...finding, claim_evidence: retainedEvidence };
    const key = projectionKey(representative, project);
    return key !== null
      && evidence.grouped_originals.some(original => canonical(original) === canonical(representative))
      && evidence.grouped_originals.every(original => projectionKey(original, project) === key);
  } catch {
    return false;
  }
}
