// CVE presentation mirrors app/report/cve.py. Only validated source metadata
// enters the report; no browser request is made to CVE or any other service.
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const id = (v: unknown): v is string => typeof v === "string" && /^CVE-[0-9]{4}-[0-9]{4,19}$/.test(v);
function date(v: unknown): v is string | null {
  if (v == null) return true;
  if (typeof v !== "string" || v.length > 64
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/.test(v)) return false;
  const [year, month, day, hour, minute, second] = v.slice(0, 19).split(/[-T:]/).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
    && hour < 24 && minute < 60 && second < 60 && Number.isFinite(Date.parse(v));
}
const statuses = ["complete", "partial", "unavailable", "not_applicable", "disabled", "not_run"];
const reasons = ["invalid_record", "unsupported_schema", "http_error", "not_found", "rate_limited", "timeout",
  "network_error", "response_too_large", "time_budget"];
type CveRecord = { id: string; state: string; provider: string; cwes: string[];
  published_at: string | null; updated_at: string | null; url: string };
type Summary = { status: string; checked_at: string | null; requested: number; attempted: number;
  resolved: number; unavailable: number; not_requested: number; rejected: number; records: CveRecord[] };

function normalized(v: unknown): Summary | null {
  if (!object(v) || v.version !== 1 || v.source !== "CVE Program" || typeof v.status !== "string"
    || !statuses.includes(v.status) || !date(v.checked_at)) return null;
  const keys = ["requested", "attempted", "resolved", "unavailable", "not_requested", "rejected"];
  if (!keys.every(k => count(v[k])) || !Array.isArray(v.records) || !Array.isArray(v.errors)
    || v.records.length + v.errors.length > 1000) return null;
  const seen = new Set<string>();
  const records: CveRecord[] = [];
  for (const r of v.records) {
    if (!object(r) || !id(r.id) || seen.has(r.id) || !["PUBLISHED", "REJECTED"].includes(String(r.state))
      || r.url !== `https://www.cve.org/CVERecord?id=${r.id}`
      || r.record_url !== `https://cveawg.mitre.org/api/cve/${r.id}`
      || typeof r.data_version !== "string" || r.data_version.length > 32 || !/^5\.[012](?:\.(?:0|[1-9][0-9]*))?$/.test(r.data_version)
      || typeof r.title !== "string" || typeof r.description !== "string" || !r.description.slice(0, 4096).trim()
      || typeof r.provider !== "string" || !date(r.published_at) || !date(r.updated_at)
      || !Array.isArray(r.cwes) || r.cwes.length > 20
      || !r.cwes.every(c => typeof c === "string" && /^CWE-[1-9][0-9]{0,4}$/.test(c))
      || new Set(r.cwes).size !== r.cwes.length
      || (r.state === "REJECTED" && (r.cwes.length > 0 || r.title.length > 0))) return null;
    seen.add(r.id);
    records.push({ id: r.id, state: String(r.state), provider: r.provider.slice(0, 32), cwes: r.cwes,
      published_at: r.published_at ?? null, updated_at: r.updated_at ?? null, url: String(r.url) });
  }
  for (const e of v.errors) {
    if (!object(e) || !id(e.id) || seen.has(e.id) || typeof e.reason !== "string" || !reasons.includes(e.reason)) return null;
    seen.add(e.id);
  }
  const s = v as unknown as Summary;
  if (s.resolved !== records.length || s.unavailable !== v.errors.length
    || s.attempted !== s.resolved + s.unavailable || s.requested !== s.attempted + s.not_requested
    || s.rejected !== records.filter(r => r.state === "REJECTED").length || !!s.attempted !== !!s.checked_at) return null;
  const expected = !s.requested ? "not_applicable" : s.resolved === s.requested ? "complete" : s.resolved ? "partial" : "unavailable";
  if (["disabled", "not_run"].includes(s.status) ? !!s.requested : s.status !== expected) return null;
  return { ...s, records };
}

export function cveRows(value: unknown): [string, string][] {
  const c = normalized(value);
  if (!c) return [["CVE Program", "Not recorded or unreadable for this audit"]];
  const descriptions: Record<string, string> = {
    disabled: "Official CVE lookup disabled; no CVE request made.",
    not_run: "Official CVE lookup not run; no CVE request made.",
    not_applicable: "No CVE IDs in the available OSV answer; no CVE request made. This is not a search of the full CVE catalogue.",
  };
  const detail = descriptions[c.status] ?? `${c.status}: ${c.resolved} of ${c.requested} CVE records fetched; `
    + `${c.unavailable} unavailable; ${c.not_requested} not requested; ${c.rejected} rejected. Checked: ${c.checked_at || "No request made"}. `
    + "OSV supplies package-version matches. CVE record state does not establish application exploitability.";
  return [["CVE Program", detail], ...c.records.map((r): [string, string] => [r.id,
    `${r.state}; CNA: ${r.provider || "Not recorded"}; CWE: ${r.cwes.join(", ") || "Not recorded"}; `
    + `published: ${r.published_at || "Not recorded"}; updated: ${r.updated_at || "Not recorded"}. ${r.url}`])];
}

export function cveNotices(value: unknown): [string, string][] {
  const c = normalized(value);
  if (!c) return value == null ? [] : [["CVE record evidence unreadable",
    "CVE lookup coverage could not be validated. This is not a complete CVE result."]];
  const notices: [string, string][] = [];
  if (["partial", "unavailable"].includes(c.status)) notices.push(["CVE record lookup incomplete",
    `${c.resolved} of ${c.requested} CVE records fetched. `
    + "Missing CVE records do not invalidate OSV matches or establish the absence of vulnerabilities."]);
  if (c.rejected) notices.push(["CVE source disagreement",
    `${c.rejected} CVE records referenced by OSV are REJECTED by the CVE Program. `
    + "OSV findings and ratings are retained; review the official records before acting."]);
  return notices;
}
