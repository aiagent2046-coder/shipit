// Mirrors app/report/dependency_snapshot.py; rendering never contacts an advisory service.
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const repositories: Record<string, string> = {
  cvelist: "https://github.com/CVEProject/cvelistV5",
  "github-reviewed": "https://github.com/github/advisory-database",
};
const labels: Record<string, string> = { cvelist: "CVE Program", "github-reviewed": "GitHub-reviewed GHSA" };
export const snapshotScopeReasons = new Set(["dependency_snapshot_scope", "dependency_runtime_reachability_not_checked"]);
const scope = "Exact npm/PyPI lockfile versions are compared with a bundled advisory snapshot. "
  + "A match does not establish reachable or exploitable application code. "
  + "Unknown assessments and packages absent from the snapshot are not safe results.";

function date(value: unknown): number | null {
  if (typeof value !== "string" || value.length > 64
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const [year, month, day, hour, minute, second] = value.slice(0, 19).split(/[-T:]/).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const result = Date.parse(value);
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
    && hour < 24 && minute < 60 && second < 60 && Number.isFinite(result) ? result : null;
}

type Metadata = { version: 1; mode: "bundled"; catalog_sha256: string | null;
  checked_at: string | null; retained_findings?: number };
type Source = { repository: string; commit: string; generated_at: string };
type Coverage = { status: string; sources: Record<string, Source>; status_counts: Record<string, number>;
  dependencies_found: number; dependencies_checked: number; unknown_reason_counts: Record<string, number>;
  manifest_gap_reason_counts: Record<string, number>; incomplete_manifest_count: number;
  inventory_truncated: number; findings_truncated: number; evaluations_truncated: number };

export function snapshotMetadata(value: unknown): Metadata | null {
  if (!object(value) || value.version !== 1 || value.mode !== "bundled") return null;
  const digest = value.catalog_sha256 ?? null, checked = value.checked_at ?? null;
  if (digest !== null && (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest))) return null;
  if (checked !== null && date(checked) === null) return null;
  if ("retained_findings" in value && !count(value.retained_findings)) return null;
  return { version: 1, mode: "bundled", catalog_sha256: digest as string | null, checked_at: checked as string | null,
    ...("retained_findings" in value ? { retained_findings: value.retained_findings as number } : {}) };
}

function reasons(value: unknown): Record<string, number> | null {
  if (!object(value) || Object.keys(value).length > 200 || Object.entries(value).some(
    ([k, v]) => !/^[a-z][a-z0-9_]{0,79}$/.test(k) || !count(v))) return null;
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) as Record<string, number>;
}

export function snapshotCoverage(value: unknown): Coverage | null {
  if (!object(value) || typeof value.status !== "string"
    || !["checked", "partial", "not_applicable", "unavailable"].includes(value.status)) return null;
  if (value.status === "unavailable") return { status: "unavailable" } as Coverage;
  const counts = value.status_counts, sources = value.sources;
  if (!object(counts) || !["affected", "unaffected", "unknown", "not_in_catalog"].every(k => count(counts[k]))
    || !["dependencies_found", "dependencies_checked"].every(k => count(value[k]))
    || !object(sources) || !Object.keys(sources).length
    || Object.keys(sources).some(k => !Object.hasOwn(repositories, k))) return null;
  const cleanSources: Record<string, Source> = {};
  for (const [name, repository] of Object.entries(repositories)) {
    if (!Object.hasOwn(sources, name)) continue;
    const source = sources[name];
    if (!object(source) || source.repository !== repository || typeof source.commit !== "string"
      || !/^[0-9a-f]{40}$/.test(source.commit) || date(source.generated_at) === null) return null;
    cleanSources[name] = { repository, commit: source.commit, generated_at: source.generated_at as string };
  }
  const unknown = reasons(value.unknown_reason_counts ?? {}), gaps = reasons(value.manifest_gap_reason_counts ?? {});
  const manifests = value.incomplete_manifests ?? {};
  if (!unknown || !gaps || !object(manifests)
    || !["inventory_truncated", "findings_truncated", "evaluations_truncated"].every(k => count(value[k] ?? 0))) return null;
  const result: Coverage = {
    status: String(value.status), sources: cleanSources, status_counts: Object.fromEntries(
      ["affected", "unaffected", "unknown", "not_in_catalog"].map(k => [k, counts[k] as number])),
    dependencies_found: value.dependencies_found as number, dependencies_checked: value.dependencies_checked as number,
    unknown_reason_counts: unknown, manifest_gap_reason_counts: gaps, incomplete_manifest_count: Object.keys(manifests).length,
    inventory_truncated: (value.inventory_truncated ?? 0) as number,
    findings_truncated: (value.findings_truncated ?? 0) as number,
    evaluations_truncated: (value.evaluations_truncated ?? 0) as number,
  };
  const hasGaps = counts.unknown || counts.not_in_catalog || result.incomplete_manifest_count
    || result.inventory_truncated || result.findings_truncated || result.evaluations_truncated
    || Object.keys(unknown).length || Object.keys(gaps).length;
  return ["checked", "not_applicable"].includes(result.status) && hasGaps ? null : result;
}

function freshness(coverage: Coverage, metadata: Metadata | null): string {
  const checked = date(metadata?.checked_at);
  if (checked === null) return "Unknown; check time is not recorded.";
  const ages = Object.entries(coverage.sources).map(([name, source]) =>
    [name, Math.floor((checked - date(source.generated_at)!) / 86_400_000)] as const);
  if (ages.some(([, age]) => age < 0)) return "Unknown; a source timestamp is later than the recorded check.";
  const state = ages.some(([, age]) => age >= 7) ? "Stale" : "Within the 7-day freshness window";
  return `${state} at the recorded check; source age in days: ${ages.map(([name, age]) => `${name}: ${age}`).join(", ")}.`;
}

export function snapshotRows(value: unknown, metadataValue?: unknown): [string, string][] {
  if (value == null && metadataValue == null) return [];
  const coverage = snapshotCoverage(value), metadata = snapshotMetadata(metadataValue);
  if (!coverage) return [["Dependency snapshot", "Coverage not recorded or unreadable; no complete result established."]];
  const rows: [string, string][] = [["Dependency snapshot", coverage.status],
    ["Snapshot SHA-256", metadata?.catalog_sha256 || "Not recorded"],
    ["Snapshot checked at", metadata?.checked_at || "Not recorded"], ["Snapshot scope", scope]];
  if (coverage.status === "unavailable") return rows;
  rows.push(["Snapshot freshness", freshness(coverage, metadata)]);
  for (const [name, source] of Object.entries(coverage.sources)) rows.push([`Snapshot source: ${labels[name]}`,
    `${source.repository}; commit: ${source.commit}; generated: ${source.generated_at}.`]);
  const counts = coverage.status_counts;
  rows.push(["Snapshot dependency coverage",
    `${coverage.dependencies_checked} of ${coverage.dependencies_found} dependency versions checked. `
    + `Advisory assessments: ${counts.affected} affected; ${counts.unaffected} unaffected; ${counts.unknown} unknown. `
    + `${counts.not_in_catalog} unique package/version entries absent from the snapshot. `
    + "Assessment counts are not unique dependency counts."]);
  for (const [key, label] of [["unknown_reason_counts", "Snapshot unknown reasons"],
    ["manifest_gap_reason_counts", "Snapshot manifest gaps"]] as const) rows.push([label,
    Object.entries(coverage[key]).map(([reason, n]) => `${reason.replaceAll("_", " ")}: ${n}`).join(", ") || "None recorded"]);
  rows.push(["Snapshot processing gaps", `Incomplete manifests: ${coverage.incomplete_manifest_count}; `
    + `inventory omitted: ${coverage.inventory_truncated}; findings omitted: ${coverage.findings_truncated}; `
    + `evaluations omitted: ${coverage.evaluations_truncated}.`]);
  return rows;
}

export function snapshotNotices(value: unknown, metadataValue?: unknown): [string, string][] {
  if (value == null && metadataValue == null) return [];
  const coverage = snapshotCoverage(value), metadata = snapshotMetadata(metadataValue);
  const notices: [string, string][] = [];
  if (!coverage) notices.push(["Dependency snapshot unreadable", "Snapshot coverage could not be validated. " + scope]);
  else if (coverage.status === "unavailable") notices.push([
    "Dependency snapshot unavailable", "The bundled catalog could not be checked. " + scope]);
  else if (coverage.status === "partial") notices.push(["Dependency snapshot incomplete",
    `${coverage.status_counts.unknown} unknown advisory assessments; ${coverage.status_counts.not_in_catalog} package/version `
    + `entries absent from the snapshot; ${coverage.incomplete_manifest_count} incomplete manifests. `
    + "Review the recorded reasons and processing limits. " + scope]);
  if (coverage && coverage.status !== "unavailable") {
    const fresh = freshness(coverage, metadata);
    if (fresh.startsWith("Stale")) notices.push(["Dependency snapshot stale", fresh + " Newer advisories may be absent."]);
    else if (fresh.startsWith("Unknown")) notices.push(["Dependency snapshot freshness unknown", fresh]);
  }
  if (metadata?.retained_findings) notices.push(["Earlier dependency findings retained",
    `${metadata.retained_findings} earlier snapshot findings retained because the current snapshot check was incomplete. `
    + "Their original source provenance still applies; the current check did not reconfirm them."]);
  return notices;
}

export function snapshotFindingRows(value: unknown): [string, string][] {
  if (!object(value)) return [];
  const rows: [string, string][] = [];
  for (const source of Array.isArray(value.snapshot_sources) ? value.snapshot_sources.slice(0, 2) : []) {
    if (!object(source) || typeof source.name !== "string" || !Object.hasOwn(repositories, source.name)
      || source.repository !== repositories[source.name] || typeof source.commit !== "string"
      || !/^[0-9a-f]{40}$/.test(source.commit) || date(source.generated_at) === null) continue;
    rows.push([`Finding snapshot source: ${labels[source.name]}`,
      `${source.repository}; commit: ${source.commit}; generated: ${source.generated_at}.`]);
  }
  return rows.length ? rows : [["Finding snapshot source", "Not recorded or unreadable for this finding."]];
}
