/** Presentation of recorded KEV evidence; never a scoring or matching engine. */
type Row = [string, string];
type Obj = Record<string, unknown>;
const object = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max = 1024): v is string => typeof v === "string" && !/^[\s\u0085]*$/u.test(v) && v.length <= max * 2 && Array.from(v).length <= max && !/[\x00-\x1f\x7f\ud800-\udfff]/u.test(v);
const hash = (v: unknown, length = 64): v is string => typeof v === "string" && new RegExp(`^[0-9a-f]{${length}}$`).test(v);
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const date = (v: unknown): v is string => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)
  && !v.startsWith("0000") && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString().slice(0, 10) === v;
const timestamp = (v: unknown): v is string => typeof v === "string"
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(v)
  && date(v.slice(0, 10)) && Number(v.slice(11, 13)) < 24 && Number(v.slice(14, 16)) < 60 && Number(v.slice(17, 19)) < 60;
const label = "CISA KEV threat context";
const repository = "https://github.com/cisagov/kev-data";
const invalid: Row[] = [[label, "Unavailable: invalid recorded threat context; no prioritization established."]];
export const THREAT_CONTEXT_SCOPE = "Known exploitation concerns this CVE in the wild; compromise of this project is not established. Priority is separate from severity and finding confidence. Absence from KEV is not evidence of safety.";

export function threatContextRows(value: unknown): Row[] {
  if (!object(value) || value.schema !== 1 || !["completed", "partial", "stale", "unavailable"].includes(String(value.status))
    || value.runtime_verified !== false || !date(value.as_of) || !hash(value.fingerprint)
    || ![value.matched_cves, value.eligible_findings, value.unmapped_findings].every(count)) return invalid;
  const { source, matches, limitations } = value;
  if (!Array.isArray(matches) || matches.length > 256 || value.matched_cves !== matches.length
    || !Array.isArray(limitations) || limitations.length > 32 || !limitations.every(item => text(item))
    || (value.status === "unavailable" && matches.length > 0)
    || (source === null && value.status !== "unavailable")) return invalid;
  if (source !== null && (!object(source) || source.repository !== repository || !hash(source.commit, 40)
    || !hash(source.upstream_sha256) || !hash(source.catalog_sha256)
    || !timestamp(source.source_committed_at) || !timestamp(source.date_released) || !text(source.catalog_version, 80))) return invalid;
  const priority = value.status === "unavailable" ? "prioritization unavailable" : `CVEs for expedited review: ${value.matched_cves}`;
  const rows: Row[] = [[label, `${value.status}; as of ${value.as_of}; ${priority}. Eligible findings: ${value.eligible_findings}; unmapped: ${value.unmapped_findings}. Project compromise is not established.`],
    ["Threat context scope", THREAT_CONTEXT_SCOPE]];
  if (object(source)) rows.push(
    ["KEV source", `${source.repository}; commit: ${source.commit}; committed: ${source.source_committed_at}; released: ${source.date_released}; catalog version: ${source.catalog_version}.`],
    ["KEV catalog SHA-256", String(source.catalog_sha256)], ["KEV upstream SHA-256", String(source.upstream_sha256)],
  );
  const seen = new Set<string>();
  for (const item of matches) {
    if (!object(item) || typeof item.cve_id !== "string" || !/^CVE-\d{4}-\d{4,19}$/.test(item.cve_id)
      || seen.has(item.cve_id) || item.priority !== "expedited" || item.reason !== "known_exploitation"
      || !date(item.date_added) || !date(item.cisa_due_date) || !text(item.required_action, 4096)
      || !["Known", "Unknown"].includes(String(item.known_ransomware_campaign_use))
      || !Array.isArray(item.finding_refs) || item.finding_refs.length < 1 || item.finding_refs.length > 64) return invalid;
    const targets: string[] = [];
    for (const reference of item.finding_refs) {
      if (!object(reference) || !["dependency-cve-match", "dependency-known-vulnerability"].includes(String(reference.rule_id))
        || !count(reference.line) || !text(reference.file, 1024) || !text(reference.package, 256)
        || !text(reference.ecosystem, 80) || !text(reference.installed_version, 256)) return invalid;
      targets.push(`${reference.ecosystem}:${reference.package} ${reference.installed_version} (${reference.file}:${reference.line})`);
    }
    seen.add(item.cve_id);
    rows.push([`KEV ${item.cve_id}`, `Expedited review; listed ${item.date_added}. Affected findings: ${targets.join("; ")}. CISA action: ${item.required_action}`]);
  }
  limitations.forEach((item, index) => rows.push([`Threat limitation ${index + 1}`, String(item)]));
  return rows;
}
