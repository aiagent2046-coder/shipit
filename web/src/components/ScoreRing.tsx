import { scoreColor, scoreVerdict } from "@/lib/format";

export function ScoreRing({ total }: { total: number }) {
  const color = scoreColor(total);
  const pct = Math.max(0, Math.min(100, (total / 10) * 100));
  return (
    <div className="flex items-center gap-4">
      <div
        className="relative flex h-24 w-24 shrink-0 items-center justify-center rounded-full"
        style={{
          background: `conic-gradient(${color} ${pct}%, var(--border) ${pct}%)`,
        }}
        role="img"
        aria-label={`Production readiness score ${total.toFixed(1)} out of 10`}
      >
        <div className="flex h-[76px] w-[76px] flex-col items-center justify-center rounded-full bg-bg">
          <span className="font-mono text-2xl font-bold tabular-nums">
            {total.toFixed(1)}
          </span>
          <span className="text-[10px] text-muted">/ 10</span>
        </div>
      </div>
      <div>
        <p className="text-sm text-muted">Production Readiness</p>
        <p className="text-lg font-semibold" style={{ color }}>
          {scoreVerdict(total)}
        </p>
      </div>
    </div>
  );
}

export function CategoryBars({
  categories,
}: {
  categories: Record<string, number>;
}) {
  return (
    <div className="flex flex-col gap-2">
      {Object.entries(categories).map(([name, value]) => (
        <div key={name} className="flex items-center gap-3 text-sm">
          <span className="w-24 shrink-0 text-muted">{name}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-border">
            <div
              className="h-full rounded-full"
              style={{
                width: `${(value / 10) * 100}%`,
                background: scoreColor(value),
              }}
            />
          </div>
          <span className="w-8 shrink-0 text-right font-mono tabular-nums">
            {value.toFixed(1)}
          </span>
        </div>
      ))}
    </div>
  );
}
