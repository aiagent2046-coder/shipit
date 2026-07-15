import type { Finding, Severity } from "@/lib/types";
import { SEVERITY_META, sortFindings, severityCounts } from "@/lib/format";
import { plainFields } from "@/lib/plain";

function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.low;
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-semibold ${meta.badgeClass}`}
    >
      <span aria-hidden="true">{meta.emoji}</span>
      {meta.label}
    </span>
  );
}

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  const counts = severityCounts(findings);
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const present = order.filter((s) => counts[s] > 0);
  if (present.length === 0) {
    return <span className="text-sm text-accent">No issues found</span>;
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

function FindingCard({ finding }: { finding: Finding }) {
  const { what, risk, fix } = plainFields(finding);
  const loc = finding.file
    ? `${finding.file}${finding.line ? `:${finding.line}` : ""}`
    : "";
  const tech = [finding.title, loc, finding.masked].filter(Boolean).join(" · ");
  return (
    <li className="rounded-lg border border-border bg-surface p-4">
      <div className="mb-2 flex items-start justify-between gap-3">
        <p className="font-medium">{what}</p>
        <SeverityBadge severity={finding.severity} />
      </div>
      {risk && <p className="mb-2 text-sm text-muted">{risk}</p>}
      {fix && (
        <p className="mb-2 text-sm text-accent">
          <span aria-hidden="true">→ </span>
          {fix}
        </p>
      )}
      {tech && (
        <p className="break-all font-mono text-xs text-muted">{tech}</p>
      )}
    </li>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface p-6 text-center">
        <p className="text-accent">No issues found by the current checks.</p>
        <p className="mt-1 text-sm text-muted">
          That&apos;s a clean bill from the static + LLM scan — nice work.
        </p>
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-3">
      {sortFindings(findings).map((f, i) => (
        <FindingCard key={`${f.rule_id}-${f.file}-${i}`} finding={f} />
      ))}
    </ul>
  );
}
