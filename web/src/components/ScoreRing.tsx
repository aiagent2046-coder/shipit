import { scoreColor, scoreVerdict } from "@/lib/format";
import type { GateReason } from "@/lib/types";

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

/** Why the total is capped, in one sentence, under the bars it contradicts.
 *
 * A capped score used to be self-explanatory: the gate only fired when a
 * safety category fell below the threshold, so the short bar was the
 * explanation. A single critical finding now caps it too, and that case has
 * no visual tell — every bar can sit above 7.0 while the ring reads 6.5.
 * Without this line the breakdown appears to contradict the headline, which
 * is the reader's cue to trust neither.
 *
 * Renders nothing when `gated_by` is absent (an audit stored before the
 * scorer recorded reasons: unknown, not ungated) or empty (not gated).
 */
function GateNote({ reasons }: { reasons?: GateReason[] }) {
  if (!reasons || reasons.length === 0) return null;

  const criticals = reasons.filter((r) => r.kind === "critical");
  const low = reasons.filter((r) => r.kind === "subscore");
  const parts: string[] = [];
  if (criticals.length > 0) {
    const named = [...new Set(criticals.map((r) => r.title || r.rule_id))];
    parts.push(`a critical finding (${named.join(", ")})`);
  }
  if (low.length > 0) {
    const named = low.map((r) => `${r.category} ${r.value?.toFixed(1)}`);
    parts.push(`a failing safety category (${named.join(", ")})`);
  }

  // No threshold or cap number is restated here. GATE_THRESHOLD and GATED_MAX
  // live in app/scan/scoring.py and TypeScript cannot import them, so any
  // figure written into this copy is a second, unsynchronised original — it
  // would keep printing 7.0 the day the rule moves. The reasons already carry
  // the only numbers the reader needs: the failing subscore's own value.
  return (
    <p className="mt-3 text-sm text-muted">
      This score is capped because the audit found {parts.join(" and ")}.
      Categories are scored independently and can read higher than the total:
      the cap is on what the headline is allowed to claim while something
      disqualifying is open.
    </p>
  );
}

export function CategoryBars({
  categories,
  gatedBy,
}: {
  categories: Record<string, number>;
  gatedBy?: GateReason[];
}) {
  return (
    <>
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
      <GateNote reasons={gatedBy} />
    </>
  );
}
