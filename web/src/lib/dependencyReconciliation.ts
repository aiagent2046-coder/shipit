import type { Finding, Score } from "./types";

const dependencyRules = new Set(["dependency-cve-match", "dependency-known-vulnerability"]);
const text = (value: unknown): string => typeof value === "string" ? value.trim() : "";

function recordedMatch(finding: Finding) {
  const evidence = finding.claim_evidence as Record<string, unknown> | null | undefined;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return null;
  const ecosystem = text(evidence.ecosystem).toLowerCase();
  let name = text(evidence.package).toLowerCase();
  if (ecosystem === "pypi") name = name.replace(/[-_.]+/g, "-");
  const version = text(evidence.installed_version);
  const ids = new Set([evidence.advisory_id,
    ...(Array.isArray(evidence.advisory_ids) ? evidence.advisory_ids : [])].map(text).filter(Boolean));
  if (!ecosystem || !name || !version || !ids.size) return null;
  return { identity: JSON.stringify([ecosystem, name, version]), ids };
}

// Only recorded package/version identities and overlapping advisory IDs establish
// repetition. Absence in the current findings is not an assessment of safety.
export function unrepeatedDependencyMatches(score: Score, findings?: Finding[]): Finding[] {
  if (findings === undefined || score.free_baseline?.version !== 1) return [];
  const current = findings.filter(f => dependencyRules.has(f.rule_id)).map(recordedMatch);
  return score.free_baseline.findings.filter(f => {
    if (f.rule_id !== "dependency-cve-match") return false;
    const prior = recordedMatch(f);
    return !prior || !current.some(match => match && match.identity === prior.identity
      && [...prior.ids].some(id => match.ids.has(id)));
  });
}
