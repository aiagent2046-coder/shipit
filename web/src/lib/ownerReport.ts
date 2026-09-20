import { normalizeAcquisition, normalizeDeserializationAgent, normalizeDeserializationObservation } from "./securityAgent";

export interface OwnerReportContext {
  security_agent?: unknown;
  archive_sha256?: unknown;
  engine_version?: unknown;
  dependency_cve?: unknown;
  limitations?: unknown;
  sca_skipped_reason?: unknown;
  sca_dependencies?: unknown;
  sca_coverage_incomplete?: unknown;
  sca_incomplete_lockfiles?: unknown;
  runtime_verified?: unknown;
}

export interface OwnerReportCard {
  finding_index: number;
  title: string;
  impact: string;
  known: string[];
  unknown: string[];
  next_action: string;
  done_when: string;
  source_refs: { file: string; line: number; sha256: string; sink_span: number[]; acquisition_version: 3 }[];
}

export interface OwnerReportProjection {
  version: 1;
  cards: OwnerReportCard[];
  summary: { title: string; text: string; coverage_notes: string[]; next_action: string } | null;
}

const ownerObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const ownerDigest = (value: unknown): value is string => typeof value === "string"
  && /^[a-f0-9]{64}(?![\s\S])/.test(value);

export interface DependencyCoverageGap {
  status: "partial" | "unavailable";
  unresolved_manifests: string[];
}

// Match Python's explicit whitespace and codepoint ordering for saved paths.
function ownerCodepointOrder(left: string, right: string): number {
  const a = Array.from(left, char => char.codePointAt(0)!);
  const b = Array.from(right, char => char.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function ownerUnresolvedManifests(value: unknown): string[] {
  return ownerObject(value) ? Object.entries(value)
    .filter(([path, reason]) => /[^\t\n\v\f\r ]/.test(path) && reason === "unresolved")
    .map(([path]) => path).sort(ownerCodepointOrder) : [];
}

// A recognized bundled snapshot owns its recorded scope. Disabled live OSV
// must not negate it; missing facts never become a completeness or safety claim.
export function dependencyCoverageGap(context: unknown): DependencyCoverageGap | null {
  if (!ownerObject(context)) return null;
  const snapshot = context.dependency_cve;
  if (ownerObject(snapshot)) {
    if (snapshot.status === "checked" || snapshot.status === "not_applicable") return null;
    if (snapshot.status === "partial" || snapshot.status === "unavailable") {
      return { status: snapshot.status, unresolved_manifests: ownerUnresolvedManifests(snapshot.incomplete_manifests) };
    }
  }
  const limitations = new Set(Array.isArray(context.limitations)
    ? context.limitations.filter((item): item is string => typeof item === "string") : []);
  const skipped = typeof context.sca_skipped_reason === "string" ? context.sca_skipped_reason : "";
  const dependencies = context.sca_dependencies;
  const noClient = skipped === "no_client" && typeof dependencies === "number"
    && Number.isSafeInteger(dependencies) && dependencies > 0;
  const unavailable = ["dependency_check_not_run", "dependency_database_unavailable", "dependency_snapshot_unavailable"]
    .some(reason => limitations.has(reason)) || skipped.startsWith("osv_unavailable") || noClient;
  const partial = ["dependency_lockfile_unreadable", "dependency_coverage_incomplete"]
    .some(reason => limitations.has(reason)) || context.sca_coverage_incomplete === true
    || skipped === "no_resolvable_lockfile" || skipped.startsWith("lockfile_unreadable");
  return unavailable || partial ? {
    status: unavailable ? "unavailable" : "partial",
    unresolved_manifests: ownerUnresolvedManifests(context.sca_incomplete_lockfiles),
  } : null;
}

// Presentation only: never fetch, infer trust from a function name, or alter the
// finding. Saved acquisitions become source facts only after receipt validation.
function ownerAgent(value: unknown, context: OwnerReportContext): Record<string, unknown> | null {
  if (!ownerObject(value) || value.version !== 1
    || typeof value.mode !== "string" || !["deterministic_static", "deterministic_evidence"].includes(value.mode)
    || typeof value.status !== "string" || !["completed", "partial", "unavailable"].includes(value.status)
    || value.automatic_patch !== false || value.runtime_verified !== false
    || !Array.isArray(value.plan) || !Array.isArray(value.observations) || !ownerObject(value.budget)
    || !ownerObject(value.source) || !ownerDigest(value.source.archive_sha256)
    || typeof value.source.engine_version !== "string" || !value.source.engine_version
    || context.archive_sha256 != null && context.archive_sha256 !== value.source.archive_sha256
    || context.engine_version != null && context.engine_version !== value.source.engine_version) return null;
  try {
    const normalized = normalizeDeserializationAgent(value);
    return ownerObject(normalized) ? normalized : null;
  } catch {
    return null;
  }
}

function ownerTrace(value: unknown): Record<string, unknown> | null {
  if (!ownerObject(value) || value.source !== "static" || value.rule_id !== "unsafe-deserialization"
    || !ownerObject(value.claim_evidence) || value.claim_evidence.version !== 1
    || !Number.isSafeInteger(value.line)) return null;
  const evidence = value.claim_evidence;
  // Special source assessments retain their existing narrative and verdict.
  // This narrow owner view must not supersede or hide their counterevidence.
  if (ownerObject(evidence.syntax_check) && evidence.syntax_check.result === "contradicted"
    || [evidence.source_assessments, evidence.premise_checks].some(items => Array.isArray(items) && items.length > 0)) return null;
  const trace = normalizeDeserializationObservation(evidence.deserialization_observation);
  return trace?.sink_method === "load" && trace.file === value.file && trace.sink_line === value.line ? trace : null;
}

function ownerSameTrace(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  return Object.keys(left).every(key => JSON.stringify(left[key]) === JSON.stringify(right[key]));
}

export function projectOwnerReport(findings: unknown, contextValue: OwnerReportContext | null = {}): OwnerReportProjection {
  const context = ownerObject(contextValue) ? contextValue : {};
  const cards: OwnerReportCard[] = [];
  if (!Array.isArray(findings)) return { version: 1, cards, summary: null };
  const agent = ownerAgent(context.security_agent, context);
  const observations = agent && Array.isArray(agent.observations) ? agent.observations : [];
  const locations = new Set<string>();
  const nextAction = "Identify where this file comes from and who can replace or modify it.";
  for (const [findingIndex, finding] of findings.entries()) {
    const trace = ownerTrace(finding);
    if (!trace) continue;
    locations.add(JSON.stringify([trace.file, trace.source_sha256, trace.sink_span]));
    const matches = observations.filter(observation => {
      if (!ownerObject(observation) || observation.pattern_id !== "python-unsafe-deserialization"
        || observation.rule_id !== "unsafe-deserialization" || observation.file !== trace.file
        || observation.line !== trace.sink_line || !ownerObject(observation.evidence)) return false;
      const savedTrace = normalizeDeserializationObservation(observation.evidence.deserialization_observation);
      return savedTrace !== null && ownerSameTrace(trace, savedTrace);
    });
    const match = matches.length === 1 && ownerObject(matches[0]) ? matches[0] : null;
    const acquisition = match ? normalizeAcquisition(match.acquisition, trace) : null;
    const enriched = acquisition?.version === 3 && acquisition.status === "completed";
    const known = ["The code uses a file-loading method that can execute instructions stored in the file."];
    const unknown = [
      "Where the file comes from and who can change it.",
      "Whether the application checks the file’s trust before loading it.",
      "Whether the possible command execution can occur in the running application.",
    ];
    if (enriched) known.push("The code opens the file at the supplied path and passes its contents to this loader.");
    else unknown.unshift("The file path and handle flow have not been established for this call.");
    cards.push({
      finding_index: findingIndex,
      title: "File loading needs a trust check",
      impact: "If an untrusted file reaches this loader, it may run commands with the application’s permissions.",
      known, unknown, next_action: nextAction,
      done_when: "Record the file’s producer, everyone who can change it, and the trust check used before loading; then have a developer review whether that check is sufficient.",
      source_refs: enriched ? [{ file: String(trace.file), line: Number(trace.sink_line),
        sha256: String(trace.source_sha256), sink_span: [...trace.sink_span as number[]], acquisition_version: 3 }] : [],
    });
  }
  if (!cards.length) return { version: 1, cards, summary: null };
  const coverageNotes = ["Source review does not establish exploitation or a verified fix."];
  const dependencyGap = dependencyCoverageGap(context);
  if (dependencyGap) coverageNotes.push(dependencyGap.status === "partial"
    ? "Dependency checking is incomplete; see the recorded coverage gaps."
    : "Dependency checking is unavailable; see the recorded coverage gaps.");
  if (context.runtime_verified === false) coverageNotes.push("Application behavior has not been verified by this report.");
  const locationText = locations.size === 1 ? "1 file-loading location needs" : `${locations.size} file-loading locations need`;
  return { version: 1, cards, summary: {
    title: "File loading: the next question",
    text: `${locationText} a trust check. This summary covers those locations; other observations remain below.`,
    coverage_notes: coverageNotes,
    next_action: nextAction,
  } };
}
