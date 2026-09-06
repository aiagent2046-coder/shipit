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
    const count = findings.filter((f) => f.category === name).length;
    let label = !recorded ? "Coverage not recorded" : skipped.has(name)
      ? (count ? "Not surveyed — see findings" : "Not checked") : "Partly checked";
    const elsewhere = score.reported_elsewhere?.[name];
    if (elsewhere?.length) label += ` — findings reported under ${elsewhere.join(", ")}`;
    if (count) label += ` · ${count} unverified finding${count === 1 ? "" : "s"}`;
    return [name, label];
  });
}
