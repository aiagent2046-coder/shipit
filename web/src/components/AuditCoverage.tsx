import type { Finding, Score } from "@/lib/types";
import { coverageRows, manifestRows } from "@/lib/evidence";

export function AuditCoverage({ score, findings }: { score: Score; findings: Finding[] }) {
  return (
    <section aria-label="Audit coverage">
      <dl className="space-y-2 text-sm">
        {coverageRows(score, findings).map(([name, label]) => (
          <div key={name} className="flex flex-wrap justify-between gap-2">
            <dt>{name}</dt>
            <dd className="text-muted">{label}</dd>
          </div>
        ))}
      </dl>
      <details className="mt-4 text-sm">
        <summary>Scan record</summary>
        <dl className="mt-2 space-y-2 break-all">
          {manifestRows(score).map(([label, value]) => (
            <div key={label}><dt>{label}</dt><dd className="text-muted">{value}</dd></div>
          ))}
        </dl>
        <p className="mt-2 text-muted">File presence is not a deployment check.
          Submitted files may be excerpted; submission does not prove full review.
          Model cost is not recorded in this report.</p>
      </details>
      <p className="mt-4 text-sm text-muted">
        This is a source review. Static signals and model hypotheses need
        verification. A repeated model claim is not independent evidence.
      </p>
      <p className="mt-2 text-sm text-muted">
        Runtime behaviour, payment replay and crash recovery, user isolation,
        and live deployment configuration have not been verified here.
        Check the cited code and reproduce the claimed consequence in an
        isolated test environment before applying a suggested fix.
      </p>
    </section>
  );
}
