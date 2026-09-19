import { patternReview } from "@/lib/securityAgent";

function ReviewRows({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="mt-2 min-w-0 space-y-2 whitespace-pre-line break-words">
      {rows.map(([label, value], index) => (
        <div key={`${label}-${index}`} className="min-w-0">
          <dt className="font-medium">{label}</dt>
          <dd className="break-all text-muted">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function PatternReview({ value }: { value: unknown }) {
  const review = patternReview(value);
  if (!review) return null;

  return (
    <details aria-label="Pattern review" className="mt-4 min-w-0 max-w-full break-words text-sm">
      <summary className="cursor-pointer">
        Pattern review · {review.status} · observations: {review.observations.length}
      </summary>
      <ReviewRows rows={review.rows} />
      {review.observations.map((observation, index) => (
        <section key={`${observation.id}-${index}`} aria-label={`Pattern observation ${index + 1}`}
          className="mt-4 min-w-0 border-t border-border pt-3">
          <h3 className="break-words font-semibold">{observation.title}</h3>
          <p translate="no" className="mt-1 break-all font-mono text-xs text-muted">
            {observation.file}:{observation.line}
          </p>
          <ReviewRows rows={observation.rows} />
        </section>
      ))}
    </details>
  );
}
