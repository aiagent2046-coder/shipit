import { AuditCoverage } from "@/components/AuditCoverage";
import type { Finding, Score, Severity } from "@/lib/types";
import { SEVERITY_META, sortFindings } from "@/lib/format";
import { isInformational, claimEvidenceRows, evidenceLabel, isNonProductionFinding, narrativeProjection, partialContradicted, sourceSeverityCounts, syntaxContradicted, unsupportedTransport } from "@/lib/evidence";
import { plainFields } from "@/lib/plain";
import { relatedFindingGroups } from "@/lib/findingGroups";
import { projectOwnerReport, type OwnerReportCard, type OwnerReportContext, type OwnerReportProjection } from "@/lib/ownerReport";

function revealOwnerFinding(index: number) {
  const target = document.getElementById(`owner-finding-${index}`);
  for (let parent = target?.parentElement; parent; parent = parent.parentElement) {
    if (parent instanceof HTMLDetailsElement) parent.open = true;
  }
  target?.focus();
}

export function OwnerReportSummary({ projection }: { projection: OwnerReportProjection }) {
  const { summary } = projection;
  if (!summary) return null;
  return <section aria-label="Report in brief" className="my-6 space-y-3 rounded-lg border border-border bg-surface p-4">
    <h2 className="text-lg font-semibold">{summary.title}</h2>
    <p>{summary.text}</p>
    <p className="text-sm"><strong>First step: </strong>{summary.next_action}</p>
    <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
      {summary.coverage_notes.map(note => <li key={note}>{note}</li>)}
    </ul>
    {projection.cards.length > 0 && <a className="inline-block text-sm underline underline-offset-4"
      href={`#owner-finding-${projection.cards[0].finding_index}`}
      onClick={() => revealOwnerFinding(projection.cards[0].finding_index)}>See the file-loading question</a>}
  </section>;
}

function OwnerFindingDetails({ card }: { card: OwnerReportCard }) {
  return <dl className="space-y-3 text-sm">
    <div><dt className="font-semibold">What we know</dt><dd><ul className="list-disc space-y-1 pl-5 text-muted">
      {card.known.map(fact => <li key={fact}>{fact}</li>)}
    </ul></dd></div>
    <div><dt className="font-semibold">What needs checking</dt><dd><ul className="list-disc space-y-1 pl-5 text-muted">
      {card.unknown.map(gap => <li key={gap}>{gap}</li>)}
    </ul></dd></div>
    <div><dt className="font-semibold">What to do next</dt><dd>{card.next_action}</dd></div>
    <div><dt className="font-semibold">This step is complete when</dt><dd className="text-muted">{card.done_when}</dd></div>
  </dl>;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.low;
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-semibold ${meta.badgeClass}`}
    >
      <span aria-hidden="true">{meta.emoji}</span>
      Potential {severity} impact
    </span>
  );
}

// Findings whose suggested fix is delivered by an Enterprise-tier capability
// (e.g. the no-Dockerfile fix references the Deploy Pack). The audit still
// surfaces the finding on every tier; only the automated fix is Enterprise.
const ENTERPRISE_FIX_RULES = new Set<string>(["no-dockerfile"]);

function EnterpriseBadge() {
  return (
    <span className="inline-flex items-center whitespace-nowrap rounded-full border border-border bg-surface px-2 py-0.5 text-xs font-medium text-muted">
      Enterprise
    </span>
  );
}

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  const counts = sourceSeverityCounts(findings);
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const present = order.filter((s) => counts[s] > 0);
  if (present.length === 0) {
    return <span className="text-sm text-muted">No source observations recorded</span>;
  }
  return (
    <div className="flex flex-wrap gap-2">
      {present.map((s) => (
        <span
          key={s}
          className={`rounded-full border px-2 py-0.5 text-xs font-medium ${SEVERITY_META[s].badgeClass}`}
        >
          {counts[s]} {s}
        </span>
      ))}
    </div>
  );
}

function FindingCard({ finding, historical = false, included = false, refreshed = false, ownerCard, findingIndex }: {
  finding: Finding; historical?: boolean; included?: boolean; refreshed?: boolean; ownerCard?: OwnerReportCard; findingIndex?: number;
}) {
  const { what, risk, fix } = plainFields(finding);
  const projection = narrativeProjection(finding);
  const loc = finding.file
    ? `${finding.file}${finding.line ? `:${finding.line}` : ""}`
    : "";
  const model = finding.source === "llm" || finding.rule_id?.startsWith("llm-");
  const contradicted = syntaxContradicted(finding);
  const unsupported = unsupportedTransport(finding) && !contradicted && !historical;
  const partial = partialContradicted(finding) && !historical;
  const snapshotMatch = finding.rule_id === "dependency-cve-match" && finding.source === "dependency"
    && finding.verification_method === "package_version_match";
  const retainedMatch = finding.claim_evidence?.snapshot_check_status === "retained_not_reconfirmed";
  const historicalLabel = refreshed
    ? snapshotMatch
      ? retainedMatch ? "Earlier dependency finding — not reconfirmed" : "Dependency match — checked with refreshed snapshot"
      : "Reused free audit observation — not reassessed"
    : included ? "Free audit observation — included in this audit" : "Previous preview — not reassessed";
  const historicalGuidance = projection ? "Recorded verification guidance — not reassessed"
    : refreshed
      ? snapshotMatch
        ? retainedMatch ? "Earlier advisory guidance — not reconfirmed" : "Snapshot advisory guidance — reachability unverified"
        : "Reused free audit suggestion — not reassessed"
      : included ? "Free audit suggestion — unverified" : "Original preview suggestion — not reassessed";
  const tech = [(partial || unsupported) && !projection ? "" : finding.title, loc, finding.masked].filter(Boolean).join(" · ");
  const evidence = <dl className="my-3 space-y-2 whitespace-pre-line text-sm">
    {claimEvidenceRows(finding, historical).map(([label, value], index) => (
      <div key={`${label}-${index}`}><dt className="font-medium">{label}</dt><dd className="text-muted">{value}</dd></div>
    ))}
  </dl>;
  const original = <>
      <div className="mb-2 flex items-start justify-between gap-3">
        <p className="font-medium">{unsupported ? "Credential transport — exposure not established"
          : partial && !projection ? "Source checks contradict part of this finding" : what}</p>
        {historical ? <span className="text-sm text-muted">{historicalLabel}
          {isNonProductionFinding(finding) && " · Test/example context"}</span>
          : contradicted ? <span className="text-sm text-muted">Syntax premise contradicted</span>
          : unsupported ? <span className="text-sm text-muted">Needs exposure evidence</span>
          : partial ? <span className="text-sm text-muted">Assessment needs review</span>
          : isInformational(finding) ? <span className="text-sm text-muted">Informational</span>
          : <SeverityBadge severity={finding.severity} />}
      </div>
      <p className="mb-2 text-sm text-muted">{evidenceLabel(finding, historical)}</p>
      {partial && <p className="mb-2 text-sm text-muted">
        Other claims remain unverified. Review the counterevidence below; the original model severity is retained in the score pending review.
      </p>}
      {risk && (!partial || projection) && !unsupported && <p className="mb-2 text-sm text-muted">
        {model && <strong>Possible consequence — unverified: </strong>}{risk}
      </p>}
      {model ? evidence : <details className="my-3 text-sm"><summary>Evidence and conditions</summary>{evidence}</details>}
      {partial && !projection && <details className="my-3 text-sm text-muted">
        <summary>Original model claim and suggestion — contains a contradicted premise</summary>
        <p>{what}</p>{risk && <p>{risk}</p>}{fix && <p>{fix}</p>}
      </details>}
      {projection && <details className="my-3 text-sm text-muted">
        <summary>Superseded model wording — source premise corrected</summary>
        {(["title", "explanation", "fix_hint", "observation"] as const).map(key =>
          projection.original[key] ? <p key={key}>{projection.original[key]}</p> : null)}
      </details>}
      {unsupported && <details className="my-3 text-sm text-muted">
        <summary>Original model claim and suggestion — exposure not established</summary>
        <p>{finding.title}</p>{finding.explanation && <p>{finding.explanation}</p>}
        {finding.fix_hint && <p>{finding.fix_hint}</p>}
      </details>}
      {fix && (contradicted || historical) && <details className="my-3 text-sm text-muted">
        <summary>{historical ? historicalGuidance
          : "Original model suggestion — premise contradicted"}</summary>{fix}
      </details>}
      {fix && !contradicted && (!partial || projection) && !unsupported && !historical && (
        <p className="mb-2 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm text-accent">
          <span>
            <span aria-hidden="true">→ </span>
            {model && <strong>Suggested verification / fix: </strong>}
            {fix}
          </span>
          {!isInformational(finding) && ENTERPRISE_FIX_RULES.has(finding.rule_id) && <EnterpriseBadge />}
        </p>
      )}
      {tech && (
        <p className="break-all font-mono text-xs text-muted">{tech}</p>
      )}
  </>;
  return <li className="rounded-lg border border-border bg-surface p-4 scroll-mt-6"
    id={findingIndex !== undefined ? `roadmap-finding-${findingIndex}` : undefined} tabIndex={findingIndex !== undefined ? -1 : undefined}>
    {ownerCard ? <div id={`owner-finding-${ownerCard.finding_index}`} tabIndex={-1} className="scroll-mt-6">
      <div className="mb-3 flex items-start justify-between gap-3">
        <h3 className="font-semibold">{ownerCard.title}</h3><SeverityBadge severity={finding.severity} />
      </div>
      <p className="mb-3 text-sm text-muted">{ownerCard.impact}</p>
      <p className="mb-3 break-all font-mono text-xs text-muted">{loc}</p>
      <OwnerFindingDetails card={ownerCard} />
      <details className="mt-4 text-sm">
        <summary>Details for a developer</summary>
        <div className="mt-3">{original}</div>
      </details>
    </div> : original}
  </li>;
}

export function PreviewHistory({ score }: { score: Score }) {
  const history = score.preview_history;
  const baseline = score.free_baseline;
  const full = baseline?.version === 1 ? (
    <section aria-label="Included free audit" className="my-6 space-y-3 rounded-lg border border-border p-4">
      <h2 className="text-lg font-semibold">Included free audit</h2>
      <p>{baseline.origin === "refreshed" ? "Free audit with refreshed dependency snapshot"
        : baseline.origin === "reused" ? "Reused same-archive free audit" : "Included in this paid audit"}.
        {" "}Status: {baseline.status}.</p>
      <p>The complete baseline is preserved below, including observations repeated in the paid review.
        It includes static observations, dependency matches and any model hypotheses; repeated observations are not independent confirmation or additional current-scan findings.</p>
      {baseline.origin === "refreshed" && <p>Dependency matching was attempted again against the recorded snapshot.
        Static observations and model hypotheses were reused without rerunning their checks.
        Earlier matches may be retained when the snapshot check is incomplete.</p>}
      {baseline.score ? <details><summary>Full baseline findings and scope</summary>
        <AuditCoverage score={baseline.score} findings={baseline.findings} />
        <ul className="space-y-3">{baseline.findings.map((finding, index) =>
          <FindingCard key={index} finding={finding} historical included={baseline.origin === "included"}
            refreshed={baseline.origin === "refreshed"} />)}</ul>
      </details> : <p>Free audit unavailable: {baseline.reason ?? "not recorded"}.</p>}
    </section>
  ) : null;
  if (history?.version !== 1) return full;
  return (
    <>{full}<section aria-label="Free audit history" className="my-6 space-y-3 rounded-lg border border-border p-4">
      <h2 className="text-lg font-semibold">Free audit history</h2>
      <p className="break-all text-sm text-muted">
        Preview {history.preview_audit_id} · engine {history.engine_version} · model {history.model ?? "not recorded"}.
      </p>
      <p className="text-sm text-muted">
        Matched by identical archive content and audit engine. {history.matched_count} unchanged observations
        already appear in this scan; {history.retained_findings.length} other preview observations are retained below.
      </p>
      <p className="text-sm text-muted">
        Not repeated does not mean fixed, disproved or confirmed. These are original preview records,
        not reassessed findings. They are excluded from current scan counts, scores and automatic fixes.
        Repetition is not independent evidence.
      </p>
      {score.analysis_reused_from && <p className="text-sm text-muted">
        The model analysis was reused from an existing audit; adding this history made no new LLM calls.
      </p>}
      <ul className="space-y-3">
        {history.retained_findings.map((finding, index) =>
          <FindingCard key={index} finding={finding} historical />)}
      </ul>
    </section></>
  );
}

function RelatedFindingCards({ findings, ownerCards, findingIndices }: {
  findings: Finding[]; ownerCards?: Map<Finding, OwnerReportCard>; findingIndices: Map<Finding, number>;
}) {
  return relatedFindingGroups(findings).map((group, index) => group.length === 1
    ? <FindingCard key={index} finding={group[0]} ownerCard={ownerCards?.get(group[0])} findingIndex={findingIndices.get(group[0])} />
    : <li key={index} className="rounded-lg border border-border p-3">
      <details open>
        <summary className="mb-3 font-semibold">Pickle file loading · {group.length} locations</summary>
        <ul className="flex flex-col gap-3">
          {group.map((finding, location) => <FindingCard key={location} finding={finding}
            ownerCard={ownerCards?.get(finding)} findingIndex={findingIndices.get(finding)} />)}
        </ul>
      </details>
    </li>);
}

export function FindingsList({ findings, context, projection }: {
  findings: Finding[]; context?: OwnerReportContext; projection?: OwnerReportProjection;
}) {
  if (!findings || findings.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface p-6 text-center">
        <p className="text-accent">No issues found by the current checks.</p>
        <p className="mt-1 text-sm text-muted">
          Absence of findings does not establish safety. See the audit scope and unchecked areas.
        </p>
      </div>
    );
  }
  // Give every input occurrence its own presentation identity, including callers
  // that repeat the same object reference. Original records remain unchanged.
  const currentFindings = findings.map(finding => ({ ...finding }));
  const sorted = sortFindings(currentFindings);
  // Keep preview/demo/legacy callers unchanged; current report adapters supply
  // the saved scan context. Map by original object before sorting and grouping.
  const ownerCards = new Map<Finding, OwnerReportCard>();
  const findingIndices = new Map(currentFindings.map((finding, index) => [finding, index]));
  const ownerProjection = projection ?? (context ? projectOwnerReport(findings, context) : null);
  if (ownerProjection) for (const card of ownerProjection.cards) {
    ownerCards.set(currentFindings[card.finding_index], card);
  }
  const contradicted = sorted.filter(syntaxContradicted);
  const informational = sorted.filter(f => !syntaxContradicted(f) && isInformational(f));
  const unsupported = sorted.filter((f) => !syntaxContradicted(f) && !isInformational(f) && unsupportedTransport(f));
  const unresolved = sorted.filter((f) => !syntaxContradicted(f) && !isInformational(f) && !unsupportedTransport(f));
  const production = unresolved.filter((f) => !isNonProductionFinding(f));
  const examples = unresolved.filter(isNonProductionFinding);
  return (
    <>
      <ul className="flex flex-col gap-3">
        <RelatedFindingCards findings={production} ownerCards={ownerCards} findingIndices={findingIndices} />
      </ul>
      {examples.length > 0 && (
        <section className="mt-6" aria-label="In tests, examples and scaffolding">
          <h3 className="font-semibold">In tests, examples and scaffolding</h3>
          <p className="my-2 text-sm text-muted">
            These paths or contexts suggest tests, examples or scaffolding;
            deployment has not been checked. Confirm whether a credential is
            synthetic. A real secret still requires action even when it is
            committed in a test.
          </p>
          <ul className="flex flex-col gap-3">
            <RelatedFindingCards findings={examples} ownerCards={ownerCards} findingIndices={findingIndices} />
          </ul>
        </section>
      )}
      {informational.length > 0 && <section className="mt-6" aria-label="Deployment inventory">
        <h3 className="font-semibold">Deployment inventory</h3>
        <ul className="flex flex-col gap-3">
          {informational.map((f, i) => <FindingCard key={i} finding={f} findingIndex={findingIndices.get(f)} />)}
        </ul>
      </section>}
      {unsupported.length > 0 && <section className="mt-6" aria-label="Credential transport hypotheses">
        <h3 className="font-semibold">Credential transport hypotheses</h3>
        <p className="my-2 text-sm text-muted">
          These transport-only hypotheses lack demonstrated credential exposure. They are retained for review
          and excluded from unresolved finding counts and score penalties. Credential safety remains unverified.
        </p>
        <ul className="flex flex-col gap-3">
          {unsupported.map((f, i) => <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} findingIndex={findingIndices.get(f)} />)}
        </ul>
      </section>}
      {contradicted.length > 0 && <section className="mt-6" aria-label="Contradicted syntax premises">
        <h3 className="font-semibold">Contradicted syntax premises</h3>
        <p className="my-2 text-sm text-muted">
          These model claims contradict the bounded syntax check. They are retained for traceability
          and excluded from unresolved finding counts and score penalties. This does not establish
          that the surrounding code is safe.
        </p>
        <ul className="flex flex-col gap-3">
          {contradicted.map((f, i) => <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} findingIndex={findingIndices.get(f)} />)}
        </ul>
      </section>}
    </>
  );
}
