import type { Finding, Score } from "./types";

const nonProductionContexts = new Set([
  "test_fixture", "test_file", "comment", "doc_example", "ci_service",
]);
const nonProductionDirectories = new Set([
  "__tests__", "__mocks__", "__snapshots__", "test", "tests", "spec", "e2e",
  "cypress", "playwright", "mock", "mocks", "smoke", "blog", "docs", "doc",
  "content", "posts", "articles", "examples", "example", "fixtures",
  "__fixtures__", "samples",
]);

export function isNonProductionFinding(finding: Finding): boolean {
  if (finding.context) return nonProductionContexts.has(finding.context);
  const path = (finding.file ?? "").toLowerCase();
  const parts = path.split("/");
  const directories = parts.slice(0, -1);
  const name = parts.at(-1) ?? "";
  if (directories.some((p) => p === "migration" || p === "migrations")) return false;
  const envTemplate = name.startsWith(".env.") && name.split(".").slice(2)
    .some((p) => ["example", "sample", "template", "dist"].includes(p));
  return directories.some((p) => nonProductionDirectories.has(p))
    || /\.(test|spec|cy|stories)\.[jt]sx?$/.test(path)
    || /\.mdx?$/.test(path)
    || /(^|\/)jest\.setup\.[jt]s$/.test(path)
    || envTemplate;
}

// Mirrors app/report/evidence.py, including the conservative legacy fallback.
export function evidenceLabel(finding: Finding): string {
  if (finding.source === "llm" || finding.rule_id?.startsWith("llm-")) {
    return "Model hypothesis — unverified";
  }
  if (finding.source === "static") return "Static signal — unverified";
  return "Legacy finding — verification not recorded";
}

export function coverageRows(score: Score, findings: Finding[]): [string, string][] {
  const recorded = score.unexamined !== undefined ||
    score.basis === "static_only" || score.basis === "static+preview";
  const skipped = new Set(score.unexamined ?? (recorded ? ["Auth", "Money & Data"] : []));
  const names = new Set([
    "Security", "Auth", "Testing", "Deploy", "Money & Data", "Frontend",
    ...Object.keys(score.categories),
  ]);
  return [...names].map((name) => {
    const { source: count, examples } = findingCounts(findings.filter((f) => f.category === name));
    let label = !recorded ? "Coverage not recorded" : skipped.has(name)
      ? (count ? "Not surveyed — see findings" : "Not checked") : "Partly checked";
    if (name === "Auth" && skipped.has(name) && score.scan_manifest?.static_checks.includes("auth_read_consistency")) {
      label = "Local Python route check ran — broader auth not checked";
    }
    const elsewhere = score.reported_elsewhere?.[name];
    if (elsewhere?.length) label += ` — findings reported under ${elsewhere.join(", ")}`;
    if (count) label += ` · ${count} unverified finding${count === 1 ? "" : "s"}`;
    if (examples) label += ` · ${examples} test/example observations`;
    return [name, label];
  });
}

export function findingCounts(findings: Finding[]): { source: number; examples: number } {
  return findings.reduce((counts, finding) => {
    const key = isNonProductionFinding(finding) ? "examples" : "source";
    counts[key] += finding.occurrence_titles?.length || 1;
    return counts;
  }, { source: 0, examples: 0 });
}

export function manifestRows(score: Score): [string, string][] {
  const m = score.scan_manifest;
  if (!m) return [["Scan record", "Not recorded for this older audit"]];
  const rows: [string, string][] = [
    ["Archive SHA-256", m.archive_sha256 || "Not recorded"],
    ["Git commit", m.commit_sha || "Not recorded for this archive"],
    ["Scan engine", m.engine_version || "Not recorded"],
    ["Files in archive", String(m.archive_files)],
    ["Static checks run", m.static_checks.join(", ") || "Not recorded"],
    ["Last responding model", m.model || "No model response recorded"],
    ["Model responses", String(m.model_calls)],
    ["Review areas applied", m.rubrics_completed.join(", ") || "None"],
    ["Files eligible for model review", String(m.llm_candidate_files ?? "Not recorded")],
    ["Unique files submitted to model", String(m.llm_submitted_files ?? "Not recorded")],
    ["Eligible files not submitted", String(m.llm_files_not_submitted ?? "Not recorded")],
    ["Model limits / skip reasons", m.limitations.join(", ") || "None recorded"],
  ];
  for (const [check, status] of Object.entries(m.static_limits)) rows.push([`Static scope: ${check}`, status]);
  for (const [kind, paths] of Object.entries(m.inventory)) {
    const shown = paths.slice(0, 5).join(", ") + (paths.length > 5 ? ` (+${paths.length - 5} more)` : "");
    rows.push([kind, `${paths.length} found` + (shown ? `: ${shown}` : "")]);
  }
  return rows;
}
