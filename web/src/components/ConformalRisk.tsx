import { conformalRiskRows, normalizeConformalRisk } from "@/lib/evidence";

export function ConformalRisk({ value }: { value: unknown }) {
  const record = normalizeConformalRisk(value);
  if (!record) return null;

  const { auto_fix_eligible, human_review, damped_advisory } = record.zones;
  const rows = conformalRiskRows(record);

  return (
    <details aria-label="Conformal risk control" className="mt-4 min-w-0 max-w-full break-words text-sm">
      <summary className="cursor-pointer">
        Conformal risk stratification · auto-fix eligible: {auto_fix_eligible} · human review: {human_review} · damped advisory: {damped_advisory}
      </summary>
      <dl className="mt-2 min-w-0 space-y-2 whitespace-pre-line break-words">
        {rows.map(([label, detail]) => (
          <div key={label} className="min-w-0">
            <dt className="font-medium">{label}</dt>
            <dd translate="no" className="break-all text-muted">{detail}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-2 text-xs text-muted">
        Thresholds partition active observations by nonconformity score across calibrated rule strata;
        runtime reachability and live deployment state are not verified.
      </p>
    </details>
  );
}
