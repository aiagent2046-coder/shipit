import type { Finding } from "./types";
import { normalizeDeserializationObservation } from "./securityAgent";

/** View-only grouping: no representative, rewritten finding or changed count. */
export function relatedFindingGroups(findings: Finding[]): Finding[][] {
  const groups = new Map<string, Finding[]>(), result: Finding[][] = [];
  for (const finding of findings) {
    const trace = finding.source === "static" && finding.rule_id === "unsafe-deserialization"
      && finding.claim_evidence?.version === 1
      ? normalizeDeserializationObservation(finding.claim_evidence.deserialization_observation) : null;
    if (!trace || trace.loader !== "pickle.load" || trace.file !== finding.file || trace.sink_line !== finding.line) {
      result.push([finding]);
      continue;
    }
    const key = JSON.stringify([finding.rule_id, trace.file, trace.source_sha256, trace.loader,
      finding.context || "", finding.claim_evidence?.source_context?.kind || "", finding.severity || "",
      finding.verification_status || "", finding.verification_method || ""]);
    if (!groups.has(key)) {
      const group: Finding[] = [];
      groups.set(key, group);
      result.push(group);
    } else if (groups.get(key)!.some(member => JSON.stringify(
      (member.claim_evidence!.deserialization_observation as Record<string, unknown>).sink_span,
    ) === JSON.stringify(trace.sink_span))) {
      result.push([finding]);
      continue;
    }
    groups.get(key)!.push(finding);
  }
  return result;
}
