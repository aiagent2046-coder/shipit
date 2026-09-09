import type { Finding, ModelAcceptance, Score, Severity } from "./types";

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

export function partialContradicted(finding: Finding): boolean {
  return finding.claim_evidence?.version === 1 && !syntaxContradicted(finding)
    && (finding.claim_evidence.premise_checks ?? []).some(check => check.result === "contradicted");
}

export function evidenceLabel(finding: Finding): string {
  if (isInformational(finding)) return "Deployment inventory — informational";
  if (syntaxContradicted(finding)) return "Model syntax premise contradicted — see bounded check";
  if (partialContradicted(finding)) return "Part of the model claim is contradicted — remaining claims need review";
  if (finding.source === "llm" || finding.rule_id?.startsWith("llm-")) {
    return "Model hypothesis — unverified";
  }
  if (finding.source === "static") return "Static signal — unverified";
  return "Legacy finding — verification not recorded";
}

function groupedClaimScopeRows(finding: Finding): [string, string][] {
  const evidence = finding.claim_evidence;
  const grouping: unknown = evidence?.grouped_claim_scope;
  const originals = evidence?.grouped_originals;
  if (evidence?.version !== 1 || !record(grouping)
    || grouping.mechanism !== "react_network_rejection_cleanup"
    || !Array.isArray(originals) || originals.length <= 1) return [];
  const rows: [string, string][] = [["Grouped hypothesis scope",
    "Grouped by the same source operation and network-rejection cleanup hypothesis. "
    + "Original conditions and consequences retain their own verification statuses."]];
  if (!Array.isArray(grouping.title_source_disagreements)) return rows;
  const handler = evidence.source_issue_identity?.handler;
  for (const disagreement of grouping.title_source_disagreements) {
    if (!record(disagreement) || disagreement.result !== "different_handler_label"
      || !count(disagreement.original_index) || disagreement.original_index >= originals.length
      || typeof disagreement.source_handler !== "string"
      || !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(disagreement.source_handler)
      || disagreement.source_handler !== handler) continue;
    rows.push(["Handler label needs review",
      `Original ${disagreement.original_index + 1} uses a different handler label. `
      + `Bound source handler: ${disagreement.source_handler}. `
      + "The original wording is retained; its handler label is not verified."]);
  }
  return rows;
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
  if (partialContradicted(finding)) rows.push(["Assessment needs review",
    "A bounded source check contradicts part of this finding. The original model severity "
    + "remains in the score because the other claims have not been resolved; it is not "
    + "independent confirmation of their impact. Review the source checks before acting."]);
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
  for (const premise of record?.premise_checks ?? []) {
    const location = premise.source_line_start
      ? ` Target ${premise.target}, source lines ${premise.source_line_start}–${premise.source_line_end}.` : "";
    rows.push([premise.result === "contradicted"
      ? "Atomic premise contradicted — other claims remain unverified" : "Atomic premise not checked",
    `${premise.claim} ${premise.detail}${location}`]);
  }
  const contextLabels: Record<string, string> = {
    guard_context: "Existing guard evidence — compare with the model claim",
    cost_context: "Cost and ordering evidence — compare with the model claim",
    rls_recommendation_context: "Policy prerequisites — review before changing clients",
  };
  for (const context of record?.context_checks ?? []) {
    if (context.scope === "bounded_source_context") {
      const label = context.result === "observed"
        ? "Bounded source context — compare with the model claim" : "Source context not checked";
      rows.push([label, `${typeof context.claim === "string" ? context.claim : ""} `
        + `${typeof context.detail === "string" ? context.detail : ""}`]);
      if (context.result === "observed" && context.source_binding && typeof context.source_binding === "object"
        && !Array.isArray(context.source_binding)) {
        rows.push(["Checked source context binding", JSON.stringify(context.source_binding)]);
      }
    }
    const label = typeof context.kind === "string" ? contextLabels[context.kind] : undefined;
    if (label) {
      const summaries = context.summary ? [context.summary] : (Array.isArray(context.checks)
        ? context.checks.map(item => item?.summary) : []);
      for (const summary of summaries) {
        if (typeof summary !== "string" || !summary) continue;
        const location = typeof context.file === "string"
          ? context.file + (context.line ? `:${context.line}` : "") : "";
        rows.push([label, (location ? `${location} — ` : "") + summary]);
      }
    }
    if (context.kind === "react_async_context" && Array.isArray(context.checks)) {
      for (const item of context.checks) {
        if (item && typeof item.summary === "string" && item.summary) {
          rows.push(["React error-path evidence — compare with the model claim",
            `${context.scope ?? ""}: ${item.summary} ${item.detail ?? ""}`]);
        }
      }
    }
    rows.push(["Deterministic context check", JSON.stringify(context)]);
  }
  const recommendation = record?.recommendation_check;
  if (recommendation && typeof recommendation === "object" && !Array.isArray(recommendation)
      && Object.keys(recommendation).length) {
    rows.push(["Recommendation prerequisites", typeof recommendation.detail === "string"
      ? recommendation.detail : "Not recorded."]);
    for (const [i, check] of (Array.isArray(recommendation.checks) ? recommendation.checks : []).entries()) {
      if (!check || typeof check !== "object" || Array.isArray(check) || check.version !== 1
          || check.result !== "prerequisites_required" || typeof check.kind !== "string"
          || typeof check.detail !== "string") continue;
      rows.push([`Recommendation check ${i + 1} — prerequisites not verified`,
        `${check.kind}: ${check.detail} ${typeof check.scope === "string" ? check.scope : ""}`]);
      const conditions = Array.isArray(check.prerequisites)
        ? check.prerequisites.filter((p): p is string => typeof p === "string" && p.length > 0) : [];
      if (conditions.length) {
        rows.push([`Required recommendation conditions ${i + 1}`, conditions.join("\n")]);
      }
      if (typeof check.reference === "string" && check.reference) {
        rows.push([`Recommendation API reference ${i + 1}`, check.reference]);
      }
    }
    if (typeof recommendation.original_fix_hint === "string") {
      rows.push(["Superseded original recommendation — do not apply without review", recommendation.original_fix_hint]);
    }
    if (recommendation.original_provenance && typeof recommendation.original_provenance === "object"
        && !Array.isArray(recommendation.original_provenance) && Object.keys(recommendation.original_provenance).length) {
      rows.push(["Superseded recommendation provenance — not independent verification",
        JSON.stringify(recommendation.original_provenance)]);
    }
    for (const [i, hint] of (Array.isArray(recommendation.superseded_fix_hints)
      ? recommendation.superseded_fix_hints : []).entries()) {
      if (typeof hint === "string") {
        rows.push([`Superseded intermediate recommendation ${i + 1} — do not apply without review`, hint]);
      }
    }
  }
  rows.push(...groupedClaimScopeRows(finding));
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

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function acceptanceState(received: number, accepted: number, rejected: number): ModelAcceptance["state"] {
  return received === 0 ? "no_candidates" : rejected === 0 ? "all_accepted"
    : accepted === 0 ? "none_accepted" : "partially_accepted";
}

// Per-model processing remains the canonical source for both old and new
// reports. Do not trust a duplicated summary over the recorded counts, or turn
// missing/inconsistent accounting into zero candidates.
export function modelAcceptanceSummary(score: Score): ModelAcceptance | null {
  const manifest = score.scan_manifest;
  if (!manifest) return null;
  const processing: unknown = manifest.model_findings;
  if (!Array.isArray(processing) || processing.length === 0) return null;
  let received = 0, accepted = 0, rejected = 0, source_rejected = 0, withdrawn = 0;
  for (const row of processing) {
    if (!record(row) || !count(row.received) || !count(row.accepted) || !count(row.rejected)
      || !record(row.rejection_reasons) || row.received !== row.accepted + row.rejected) return null;
    let reasons = 0;
    for (const [reason, value] of Object.entries(row.rejection_reasons)) {
      if (!count(value)) return null;
      reasons += value;
      if (reason === "source_quote_or_location_mismatch") source_rejected += value;
      else if (reason === "self_cancelled") withdrawn += value;
    }
    if (!Number.isSafeInteger(reasons) || reasons !== row.rejected) return null;
    received += row.received;
    accepted += row.accepted;
    rejected += row.rejected;
    if (![received, accepted, rejected, source_rejected, withdrawn].every(count)) return null;
  }
  return { version: 1, received, accepted, rejected, source_rejected, withdrawn,
    other_rejected: rejected - source_rejected - withdrawn,
    state: acceptanceState(received, accepted, rejected) };
}

export function modelAcceptanceNotice(score: Score): [string, string] | null {
  const summary = modelAcceptanceSummary(score);
  if (!summary || summary.rejected === 0) return null;
  const details: string[] = [];
  if (summary.source_rejected) details.push(`${summary.source_rejected} could not be matched to the cited source`);
  if (summary.withdrawn) details.push(`${summary.withdrawn} ${summary.withdrawn === 1 ? "was" : "were"} withdrawn by the model`);
  if (summary.other_rejected) details.push(`${summary.other_rejected} failed response validation`);
  return [`Model observations accepted: ${summary.accepted} of ${summary.received}`,
    details.join("; ") + ". Excluded observations are not included in the findings. "
    + "Acceptance checks source citation and response format; it does not verify conclusions or establish project safety."];
}

const rejectionReasons = new Set(["not_an_object", "missing_fields", "invalid_severity",
  "invalid_confidence", "invalid_text", "source_quote_or_location_mismatch", "self_cancelled"]);
const rejectionDetails = new Set([...rejectionReasons, "unknown_file", "invalid_line_range",
  "quote_missing_or_short", "quote_mismatch", "quote_outside_cited_window",
  "quote_prompt_line_prefix", "quote_ellipsis_fragments_match", "diagnostic_limit_reached"]);
const rejectionRubrics = new Set(["auth", "security", "money", "web"]);
const maxRejectionItems = 200;

function diagnosticLine(value: unknown): number | null {
  return count(value) && value > 0 && value <= 2 ** 31 - 1 ? value : null;
}

// Never stringify a diagnostic record: only closed codes and bounded metadata
// may be displayed. Rejected source text, path suggestions and arbitrary extra
// fields must not appear in either the notice or the technical scan record.
function rejectionDiagnosticRows(score: Score): [string, string][] {
  const diagnostics: unknown = score.scan_manifest?.rejection_diagnostics;
  if (diagnostics === undefined || diagnostics === null) return [];
  if (!record(diagnostics) || diagnostics.version !== 1
    || !Array.isArray(diagnostics.items) || !count(diagnostics.omitted)) {
    return [["Rejection diagnostics", "Not recorded in a supported format"]];
  }
  const rows: [string, string][] = [];
  let omitted = diagnostics.omitted, shown = 0;
  for (const item of diagnostics.items) {
    if (shown >= maxRejectionItems || !record(item)
      || !count(item.response) || item.response === 0 || !count(item.item) || item.item === 0
      || typeof item.rubric !== "string" || !rejectionRubrics.has(item.rubric)
      || typeof item.reason !== "string" || !rejectionReasons.has(item.reason)
      || typeof item.detail !== "string" || !rejectionDetails.has(item.detail)) {
      omitted = Math.min(Number.MAX_SAFE_INTEGER, omitted + 1);
      continue;
    }
    shown += 1;
    const fileRef = typeof item.file_ref === "string" && /^sha256:[0-9a-f]{64}$/.test(item.file_ref)
      ? item.file_ref : "Not recorded";
    const start = diagnosticLine(item.line_start), end = diagnosticLine(item.line_end);
    rows.push([`Rejected observation ${shown}`,
      `Response: ${item.response}; review area: ${item.rubric}; entry: ${item.item}. `
      + `Reason: ${item.reason}; detail: ${item.detail}. `
      + `File reference: ${fileRef}; cited lines: ${start ?? "Not recorded"}–${end ?? "Not recorded"}.`]);
  }
  rows.unshift(["Rejection diagnostics", `${shown} records shown; ${count(omitted) ? omitted : "unknown count"} omitted. `
    + `At most ${maxRejectionItems} records are retained. Rejected text and source quotes are not retained; `
    + "a file reference identifies a known source path by hash. These records explain processing, not whether a claim is true."]);
  return rows;
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
  rows.push(...rejectionDiagnosticRows(score));
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
    const indexes = [["guards", "Guard evidence"], ["cost_context", "Cost evidence"],
      ["rls_recommendations", "Policy recommendation evidence"]] as const;
    for (const [key, label] of indexes) {
      const index = facts[key];
      if (!index) continue;
      rows.push([`${label} scope`, index.scope],
        [`${label} limits`, index.limitations.join(", ") || "None recorded"],
        [`${label} records`, String(index.records.length)]);
      index.records.forEach((item, i) => rows.push([`${label} ${i + 1}`, JSON.stringify(item)]));
    }
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
