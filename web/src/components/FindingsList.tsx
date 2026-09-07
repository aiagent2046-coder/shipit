import { AuditCoverage } from "@/components/AuditCoverage";
import type { Finding, Score, Severity } from "@/lib/types";
import { SEVERITY_META, sortFindings } from "@/lib/format";
import { isInformational, claimEvidenceRows, evidenceLabel, isNonProductionFinding, sourceSeverityCounts, syntaxContradicted } from "@/lib/evidence";
import { plainFields } from "@/lib/plain";

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

function FindingCard({ finding, historical = false, included = false }: { finding: Finding; historical?: boolean; included?: boolean }) {
  const { what, risk, fix } = plainFields(finding);
  const loc = finding.file
    ? `${finding.file}${finding.line ? `:${finding.line}` : ""}`
    : "";
  const tech = [finding.title, loc, finding.masked].filter(Boolean).join(" · ");
  const model = finding.source === "llm" || finding.rule_id?.startsWith("llm-");
  const contradicted = syntaxContradicted(finding);
  const evidence = <dl className="my-3 space-y-2 whitespace-pre-line text-sm">
    {claimEvidenceRows(finding).map(([label, value], index) => (
      <div key={`${label}-${index}`}><dt className="font-medium">{label}</dt><dd className="text-muted">{value}</dd></div>
    ))}
  </dl>;
  return (
    <li className="rounded-lg border border-border bg-surface p-4">
      <div className="mb-2 flex items-start justify-between gap-3">
        <p className="font-medium">{what}</p>
        {historical ? <span className="text-sm text-muted">{included ? "Free-model result — included in this audit" : "Previous preview — not reassessed"}
          {isNonProductionFinding(finding) && " · Test/example context"}</span>
          : contradicted ? <span className="text-sm text-muted">Syntax premise contradicted</span>
          : isInformational(finding) ? <span className="text-sm text-muted">Informational</span>
          : <SeverityBadge severity={finding.severity} />}
      </div>
      <p className="mb-2 text-sm text-muted">{evidenceLabel(finding)}</p>
      {risk && <p className="mb-2 text-sm text-muted">
        {model && <strong>Possible consequence — unverified: </strong>}{risk}
      </p>}
      {model ? evidence : <details className="my-3 text-sm"><summary>Evidence and conditions</summary>{evidence}</details>}
      {fix && (contradicted || historical) && <details className="my-3 text-sm text-muted">
        <summary>{historical ? (included ? "Free-model suggestion — unverified" : "Original preview suggestion — not reassessed")
          : "Original model suggestion — premise contradicted"}</summary>{fix}
      </details>}
      {fix && !contradicted && !historical && (
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
    </li>
  );
}

export function PreviewHistory({ score }: { score: Score }) {
  const history = score.preview_history;
  const baseline = score.free_baseline;
  const full = baseline?.version === 1 ? (
    <section aria-label="Included free-model report" className="my-6 space-y-3 rounded-lg border border-border p-4">
      <h2 className="text-lg font-semibold">Included free-model report</h2>
      <p>{baseline.origin === "reused" ? "Reused same-archive free audit" : "Included in this paid audit"}.
        {" "}Status: {baseline.status}.</p>
      <p>The complete baseline is preserved below, including observations repeated in the paid review.
        It is a separate model result, not independent confirmation or additional current-scan findings.</p>
      {baseline.score ? <details><summary>Full baseline findings and scope</summary>
        <AuditCoverage score={baseline.score} findings={baseline.findings} />
        <ul className="space-y-3">{baseline.findings.map((finding, index) =>
          <FindingCard key={index} finding={finding} historical included={baseline.origin === "included"} />)}</ul>
      </details> : <p>Free-model stage unavailable: {baseline.reason ?? "not recorded"}.</p>}
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

export function FindingsList({ findings }: { findings: Finding[] }) {
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
  const sorted = sortFindings(findings);
  const contradicted = sorted.filter(syntaxContradicted);
  const informational = sorted.filter(isInformational);
  const unresolved = sorted.filter((f) => !syntaxContradicted(f) && !isInformational(f));
  const production = unresolved.filter((f) => !isNonProductionFinding(f));
  const examples = unresolved.filter(isNonProductionFinding);
  return (
    <>
      <ul className="flex flex-col gap-3">
        {production.map((f, i) => (
          <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} />
        ))}
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
            {examples.map((f, i) => (
              <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} />
            ))}
          </ul>
        </section>
      )}
      {informational.length > 0 && <section className="mt-6" aria-label="Deployment inventory">
        <h3 className="font-semibold">Deployment inventory</h3>
        <ul className="flex flex-col gap-3">
          {informational.map((f, i) => <FindingCard key={i} finding={f} />)}
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
          {contradicted.map((f, i) => <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} />)}
        </ul>
      </section>}
    </>
  );
}
