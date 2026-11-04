/** Bounded presentation only: these rows never affect findings or scores. */
import { threatContextRows } from "./threatContext";
type RecordValue = Record<string, unknown>;
export type ProjectCheckRows = [string, string][];
const object = (v: unknown): v is RecordValue => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max = 1024): v is string => typeof v === "string" && v.length <= max && !/[\x00-\x1f]/.test(v);
const hash = (v: unknown, length = 64): v is string => typeof v === "string" && new RegExp(`^[0-9a-f]{${length}}$`).test(v);
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const repositories: Record<string, string> = { cvelist: "https://github.com/CVEProject/cvelistV5", "github-reviewed": "https://github.com/github/advisory-database" };
// KEV is pinned to the same cisagov/kev-data commit as kev-catalog.json; its identity adds the
// upstream catalog version and the digest of the compiled blob to the usual repository pin.
const annotations: Record<string, string> = { "cisa-kev": "https://github.com/cisagov/kev-data" };
const annotationKeys = ["repository", "commit", "generated_at", "catalog_version", "sha256"];
const states = new Set(["completed", "partial", "unavailable", "not_run", "not_applicable"]);
const stage = (v: unknown): v is RecordValue => object(v) && typeof v.status === "string" && states.has(v.status);
const label = (v: unknown) => String(v).replaceAll("_", " ");
const unavailable: ProjectCheckRows = [["Project checks", "Unavailable: invalid or incompatible recorded evidence; no complete result established."]];
export const PROJECT_CHECKS_SCOPE = "Missing or incomplete checks are not clean results. Ghidra evidence is operator-supplied; hash consistency does not authenticate tool execution. Symbols do not establish a CVE match. Runtime behaviour is not verified and binary evidence does not authorize automatic patches.";

export function projectChecksRows(value: unknown): ProjectCheckRows {
  if (value == null) return [];
  if (!object(value) || value.schema !== 1 || !hash(value.archive_sha256) || value.runtime_verified !== false) return unavailable;
  const { source, dependencies: deps, binary_static: binary } = value;
  if (!stage(source) || !stage(deps) || !stage(binary)
    || ![source.checks_run, source.checks_not_run, source.findings].every(count) || !text(source.agent_status, 80)
    || !count(deps.findings) || !["offline_catalog", "live_osv", "not_run"].includes(String(deps.mode))
    || (deps.catalog_sha256 != null && !hash(deps.catalog_sha256))
    || (deps.reason != null && !text(deps.reason))
    || binary.schema !== 1 || binary.archive_sha256 !== value.archive_sha256 || binary.provenance !== "operator_supplied"
    || binary.runtime_verified !== false || binary.automatic_patch !== false || !count(binary.artifacts_omitted)
    || !Array.isArray(binary.artifacts) || binary.artifacts.length > 32
    || !Array.isArray(binary.limitations) || binary.limitations.length > 32 || !binary.limitations.every(v => text(v))
    || !object(deps.sources) || Object.keys(deps.sources).length > 8) return unavailable;
  if (source.status === "completed" && (source.checks_not_run !== 0 || source.checks_run === 0)) return unavailable;
  const rows: ProjectCheckRows = [
    ["Source", `${label(source.status)}; checks run: ${source.checks_run}; not run: ${source.checks_not_run}; findings: ${source.findings}; pattern review: ${label(source.agent_status)}.`],
    ["Vulnerability databases", `${label(deps.status)}; mode: ${label(deps.mode)}; findings: ${deps.findings}.`],
    ["Ghidra / binary static", `${label(binary.status)}; artifacts: ${binary.artifacts.length}; omitted: ${binary.artifacts_omitted}. Operator-supplied evidence; execution not authenticated.`],
    ["Project archive SHA-256", value.archive_sha256],
  ];
  if (deps.reason) rows.push(["Dependency check scope", String(deps.reason)]);
  rows.push(["Catalog SHA-256", String(deps.catalog_sha256 || "Not recorded")]);
  for (const [name, provenance] of Object.entries(deps.sources)) {
    if (Object.hasOwn(annotations, name)) {
      if (!object(provenance) || provenance.repository !== annotations[name] || !hash(provenance.commit, 40)
        || !text(provenance.generated_at, 64) || !text(provenance.catalog_version, 80) || !hash(provenance.sha256)) return unavailable;
      rows.push([`Exploitation source: ${name}`, annotationKeys.map(key => `${key}: ${provenance[key]}`).join("; ")]);
      continue;
    }
    if (!Object.hasOwn(repositories, name) || !object(provenance) || provenance.repository !== repositories[name]
      || !hash(provenance.commit, 40) || !text(provenance.generated_at, 64)) return unavailable;
    const parts: string[] = [];
    for (const key of ["repository", "commit", "generated_at"]) {
      if (!(key in provenance)) continue;
      if (!text(provenance[key]) || (key === "commit" && !hash(provenance[key], 40))) return unavailable;
      parts.push(`${key}: ${provenance[key]}`);
    }
    rows.push([`Advisory source: ${name}`, parts.join("; ") || "Provenance not recorded"]);
  }
  for (const [index, artifact] of binary.artifacts.entries()) {
    if (!stage(artifact) || !("sha256" in artifact) || !("bytes" in artifact) || !text(artifact.path, 4096)
      || (artifact.sha256 != null && !hash(artifact.sha256)) || (artifact.bytes != null && !count(artifact.bytes))
      || (["completed", "partial"].includes(String(artifact.status)) && (artifact.sha256 == null || artifact.bytes == null))
      || (artifact.reason != null && !text(artifact.reason))) return unavailable;
    if (artifact.runtime_verified === true || artifact.automatic_patch === true
      || (artifact.provenance != null && artifact.provenance !== "operator_supplied")
      || (["completed", "partial"].includes(String(artifact.status)) && (!object(artifact.provider)
        || artifact.provider.name !== "ghidra" || !text(artifact.provider.version, 160)
        || !object(artifact.facts) || !["functions", "imports"].every(key => {
          const facts = (artifact.facts as RecordValue)[key]; return Array.isArray(facts) && facts.length <= 1000;
        })))) return unavailable;
    let detail = `${artifact.path}; ${label(artifact.status)}; SHA-256: ${artifact.sha256 || "Not recorded"}; bytes: ${artifact.bytes ?? "Not recorded"}.`;
    if (artifact.reason) detail += ` ${artifact.reason}`;
    if (object(artifact.facts)) for (const key of ["functions", "imports"]) {
      const facts = artifact.facts[key];
      if (Array.isArray(facts) && facts.length <= 1000) detail += ` ${key}: ${facts.length}.`;
    }
    if (object(artifact.provider)) {
      const provider = artifact.provider;
      const parts = ["name", "version"].filter(key => text(provider[key], 160)).map(key => `${key}: ${provider[key]}`);
      for (const key of ["distribution_sha256", "exporter_sha256"]) if (hash(provider[key])) parts.push(`${key}: ${provider[key]}`);
      detail += ` Provider: ${parts.join("; ")}.`;
    } else if (text(artifact.provider, 160) && artifact.provider) detail += ` Provider: ${artifact.provider}.`;
    rows.push([`Binary artifact ${index + 1}`, detail]);
  }
  if ((binary.status === "completed" && (!binary.artifacts.length || binary.artifacts_omitted !== 0
      || binary.artifacts.some(item => !object(item) || item.status !== "completed")))
    || (binary.status === "not_applicable" && (binary.artifacts.length > 0 || binary.artifacts_omitted !== 0))
    || (binary.status === "not_run" && binary.artifacts.some(item => !object(item) || item.status !== "not_run"))) return unavailable;
  binary.limitations.forEach((item, index) => rows.push([`Binary limitation ${index + 1}`, String(item)]));
  if (Object.hasOwn(value, "threat_context")) {
    const threatRows = threatContextRows(value.threat_context);
    rows.splice(3, 0, threatRows[0]);
    rows.push(...threatRows.slice(1));
  }
  return rows;
}
