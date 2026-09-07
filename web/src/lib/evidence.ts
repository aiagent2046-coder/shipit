import type { Finding, Score, Severity } from "./types";

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

export function isInformational(finding: Finding): boolean {
  return finding.rule_id === "no-dockerfile" && finding.context === "deployment_inventory";
}

// Mirrors app/report/evidence.py, including the conservative legacy fallback.
export function syntaxContradicted(finding: Finding): boolean {
  return finding.claim_evidence?.version === 1
    && finding.claim_evidence.syntax_check?.result === "contradicted";
}

export function evidenceLabel(finding: Finding): string {
  if (isInformational(finding)) return "Deployment inventory — informational";
  if (syntaxContradicted(finding)) return "Model syntax premise contradicted — see bounded check";
  if (finding.source === "llm" || finding.rule_id?.startsWith("llm-")) {
    return "Model hypothesis — unverified";
  }
  if (finding.source === "static") return "Static signal — unverified";
  return "Legacy finding — verification not recorded";
}

export function claimEvidenceRows(finding: Finding): [string, string][] {
  const record = finding.claim_evidence?.version === 1 ? finding.claim_evidence : undefined;
  const check = record?.source_check;
  const checked = check?.kind === "quote_match"
    ? `Quoted text matched in source lines ${check.line_start}–${check.line_end}. This does not verify the interpretation.`
    : check?.kind === "static_rule"
      ? "A static rule emitted this observation. Its consequence was not tested."
      : "Not recorded for this finding; do not assume the cited code was verified.";
  const rows: [string, string][] = [["Source check", checked]];
  const context = record?.source_context;
  if (context) {
    const labels: Record<string, string> = { comment: "Comment", docstring: "Python docstring",
      doc_example: "Documentation/example", test_file: "Test file", test_fixture: "Test fixture/placeholder",
      ci_service: "CI configuration with a local host", placeholder_uri: "Example URI",
      configuration_template: "Configuration text containing change_me",
      source_literal: "Source text; runtime use not established" };
    rows.push(["Source context", labels[context.kind] ?? "Not recorded"]);
    rows.push(["URI protocol", `${context.uri_scheme} — ${context.uri_kind}; ` +
      "URI use, credential validity and deployment are not verified."]);
  }
  const syntax = record?.syntax_check;
  if (syntax) {
    const labels = { contradicted: "Syntax premise contradicted", observed: "Syntax pattern observed",
      not_checked: "Syntax premise not checked" };
    const location = syntax.line_start ? ` Checked source lines ${syntax.line_start}–${syntax.line_end}.` : "";
    rows.push([labels[syntax.result] ?? labels.not_checked, `${syntax.claim} ${syntax.detail}${location}`]);
  }
  for (const context of record?.context_checks ?? []) {
    rows.push(["Deterministic context check", JSON.stringify(context)]);
  }
  for (const [i, original] of (record?.grouped_originals ?? []).entries()) {
    rows.push([`Grouped original ${i + 1} — not independent confirmation`, JSON.stringify(original)]);
  }
  if (record?.observation) rows.push(["Model interpretation — unverified", record.observation]);
  rows.push(["Required conditions — not checked", record?.required_conditions?.length
    ? record.required_conditions.join("\n") : "Not recorded; do not assume the conditions for harm are satisfied."]);
  rows.push(["Consequence check", "No independent verification recorded."]);
  return rows;
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
    if (isInformational(finding) || syntaxContradicted(finding)) return counts;
    const key = isNonProductionFinding(finding) ? "examples" : "source";
    counts[key] += finding.occurrence_titles?.length || 1;
    return counts;
  }, { source: 0, examples: 0 });
}

export function sourceSeverityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (isInformational(finding) || syntaxContradicted(finding)) continue;
    if (isNonProductionFinding(finding)) continue;
    const severities = finding.occurrence_severities?.length
      ? finding.occurrence_severities : [finding.severity];
    for (const severity of severities) if (Object.hasOwn(counts, severity)) counts[severity] += 1;
  }
  return counts;
}

// Mirrors model_status_notice: reasons describe the audit service, not the project.
export function modelStatusNotice(score: Score): [string, string] | null {
  const manifest = score.scan_manifest;
  const reasons = manifest?.limitations ?? [];
  const limited = reasons.length > 0 || score.basis === "static+partial";
  if (!limited && score.basis !== "static_only") return null;
  const responded = (manifest?.model_calls ?? 0) > 0;
  let title = responded || score.basis === "static+partial" ? "Model review incomplete" : "Model review unavailable";
  if (responded && reasons.length === 1 && reasons[0] === "input_truncated") title = "Model review may be incomplete";
  let detail = responded
    ? "Model responses are available, but review limits were recorded."
    : "No model response is recorded. Only static observations are available.";
  if (reasons.includes("billing")) detail += " The model provider reported a billing or quota limit.";
  else if (reasons.includes("provider") || reasons.includes("provider_failure") || reasons.some((r) => r.startsWith("rubric_failed:"))) {
    detail += " A model request failed.";
  }
  if (reasons.includes("cost_cap_exceeded") || reasons.includes("daily_spend_cap")) {
    detail += " A review spending limit was reached.";
  }
  if (reasons.includes("input_truncated")) {
    detail += " Token accounting suggests possible input truncation; this is not independently verified.";
  }
  if (!manifest) detail = "The review is recorded as limited. The reason and model execution details were not recorded.";
  return [title, detail + " This is a limit of the audit, not evidence of a defect in your project."];
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
  if (m.model_findings == null) {
    rows.push(["Model finding processing", "Not recorded for this audit"]);
  } else if (!m.model_findings.length) {
    rows.push(["Model finding processing", "No model response processed"]);
  } else for (const row of m.model_findings) {
    rows.push([`Finding processing: ${row.model || "unknown model"}`,
      `Responses: ${row.responses}; unreadable: ${row.invalid_responses}; valid empty: ${row.empty_responses}. ` +
      `Received entries: ${row.received}; rejected: ${row.rejected}; accepted before grouping: ${row.accepted}; ` +
      `merged: ${row.merged}; saved representatives: ${row.saved}. ` +
      "Merged originals are retained. These counts do not verify conclusions."]);
    rows.push(["Rejection reasons", JSON.stringify(row.rejection_reasons)]);
  }
  const exclusionLabels: Record<string, string> = {
    no_rubric_match: "No keyword match in configured review areas",
    rubric_not_reached: "Matching review areas were not reached",
    selection_budget: "Outside file-selection budgets of attempted areas",
    request_window: "Removed to fit the request window",
  };
  if (m.llm_selection_exclusions) {
    for (const [key, label] of Object.entries(exclusionLabels))
      rows.push([`Files not submitted: ${label}`, String(m.llm_selection_exclusions[key] ?? 0)]);
  } else if (m.llm_files_not_submitted) rows.push(["File exclusion reasons", "Not recorded for this audit"]);
  for (const [check, status] of Object.entries(m.static_limits)) rows.push([`Static scope: ${check}`, status]);
  const facts = m.source_facts;
  if (facts) {
    rows.push(["Source fact scope", facts.scope]);
    rows.push(["Python files parsed for source facts", String(facts.parsed_files)]);
    rows.push(["Source fact limits", facts.limitations.join(", ") || "None recorded"]);
    facts.facts.forEach((fact, i) => rows.push([`Source syntax fact ${i + 1}`,
      `${fact.file}:${fact.line} — ${fact.scope}: call ${fact.call}; matching ${fact.import_module} import at line ${fact.import_line}`]));
    const react = facts.react_async;
    if (react) {
      rows.push(["React async scope", react.scope],
        ["Files parsed for React async context", String(react.parsed_files)],
        ["React async limits", react.limitations.join(", ") || "None recorded"]);
      react.records.forEach((fact, i) => rows.push([`React async context ${i + 1}`,
        [`${fact.file}:${fact.line}–${fact.line_end} — ${fact.scope}`,
          `Await lines: ${fact.await_lines.join(", ")}`,
          ...fact.checks.map(c => JSON.stringify(c)),
          ...fact.controls.map(c => `Button syntax: ${JSON.stringify(c)}`)].join("\n")]));
    }
    const functions = facts.functions;
    if (functions) {
      rows.push(["Function evidence scope", functions.scope],
        ["Functions indexed", String(functions.indexed_functions)],
        ["Function evidence limits", functions.limitations.join(", ") || "None recorded"]);
      functions.records.forEach((fact, i) => rows.push([`Function evidence ${i + 1}`,
        [`${fact.file}:${fact.line}–${fact.line_end} — ${fact.scope}`,
          ...fact.checks.map(c => JSON.stringify(c)),
          ...fact.candidates.map(c => `Candidate (binding not resolved): ${JSON.stringify(c)}`)].join("\n")]));
    }
    const operations = facts.operations;
    if (operations) {
      rows.push(["Operation context scope", operations.scope],
        ["Files parsed for operation context", String(operations.parsed_files)],
        ["Operation context limits", operations.limitations.join(", ") || "None recorded"]);
      operations.records.forEach((fact, i) => rows.push([`Operation context ${i + 1}`,
        `${fact.file}:${fact.line} — ${fact.scope}: ${fact.call}\n${fact.detail}`]));
    }
  }
  for (const [kind, paths] of Object.entries(m.inventory)) {
    const shown = paths.slice(0, 5).join(", ") + (paths.length > 5 ? ` (+${paths.length - 5} more)` : "");
    rows.push([kind, `${paths.length} found` + (shown ? `: ${shown}` : "")]);
  }
  return rows;
}


export function observationSummary(findings: Finding[]): string {
  const { source, examples } = findingCounts(findings);
  let informational = 0, contradicted = 0;
  for (const f of findings) {
    const count = f.occurrence_titles?.length || 1;
    if (syntaxContradicted(f)) contradicted += count;
    else if (isInformational(f)) informational += count;
  }
  return `${source + examples + informational + contradicted} observations: ${source} in source, `
    + `${examples} in tests/examples, ${informational} informational, `
    + `${contradicted} with contradicted syntax premises.`;
}

export function reviewContributionRows(score: Score): [string, string, string][] {
  if (score.free_baseline?.version !== 1) return [];
  function values(stage?: Score | null): string[] {
    const m = stage?.scan_manifest;
    const processing = m?.model_findings;
    const saved = processing?.length && processing.every((r) => Number.isInteger(r.saved))
      ? processing.reduce((total, r) => total + r.saved, 0) : null;
    return [m?.llm_submitted_files, m?.model_calls, saved].map((v) => v == null ? "Not recorded" : String(v));
  }
  const free = values(score.free_baseline.score), paid = values(score);
  return ["Files submitted to model", "Model responses", "Retained model hypotheses"]
    .map((label, i) => [label, free[i], paid[i]]);
}
