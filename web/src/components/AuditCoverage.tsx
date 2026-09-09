import type { Finding, Score } from "@/lib/types";
import { coverageRows, manifestRows, modelAcceptanceNotice, modelStatusNotice, observationSummary, reviewContributionRows } from "@/lib/evidence";

export function AuditCoverage({ score, findings }: { score: Score; findings: Finding[] }) {
  const notice = modelStatusNotice(score);
  const acceptance = modelAcceptanceNotice(score);
  const contribution = reviewContributionRows(score);
  return (
    <section aria-label="Audit coverage">
      <p className="mb-4 text-sm">{observationSummary(findings)}</p>
      {acceptance && <aside aria-label="Model observation acceptance" className="mb-4 rounded-lg border border-amber-500 p-4">
        <h3 className="font-semibold">{acceptance[0]}</h3>
        <p className="mt-1 text-sm">{acceptance[1]}</p>
      </aside>}
      {contribution.length > 0 && <section aria-label="Model review contribution" className="mb-4 text-sm">
        <h3 className="font-semibold">Model review contribution</h3>
        <table className="my-2 w-full text-left">
          <thead><tr><th scope="col">Recorded work</th><th scope="col">Free audit</th><th scope="col">Paid review</th></tr></thead>
          <tbody>{contribution.map(([label, free, paid]) => <tr key={label}>
            <th scope="row">{label}</th><td>{free}</td><td>{paid}</td>
          </tr>)}</tbody>
        </table>
        <p>Model hypotheses may repeat the free audit; these are not counts of new or confirmed problems.
          Zero retained hypotheses does not establish safety. Submitted files may be excerpted.</p>
        {score.analysis_reused_from && <p>Paid analysis was reused; these counts describe the stored review.</p>}
      </section>}
      {notice && <aside aria-label="Model review status" className="mb-4 rounded-lg border border-amber-500 p-4">
        <h3 className="font-semibold">{notice[0]}</h3>
        <p className="mt-1 text-sm">{notice[1]}</p>
      </aside>}
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
            <div key={label}><dt>{label}</dt><dd translate="no" className="text-muted">{value}</dd></div>
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
