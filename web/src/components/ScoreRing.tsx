import {
  categoryBand,
  scoreColor,
  scoreVerdict,
  seriousCategories,
} from "@/lib/format";
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
    // Names only. This printed "Security 1.9, Auth 1.6, Money & Data 3.9" on
    // audit 2230094e — the exact category numbers the bars above are no longer
    // allowed to publish, restated three lines under them. Withholding a number
    // in one place and printing it in the next is not a smaller claim; it is
    // the same claim, made where nobody thought to check it.
    const named = [...new Set(low.map((r) => r.category))].sort();
    parts.push(`a failing safety category (${named.join(", ")})`);
  }

  // No threshold or cap number is restated here. GATE_THRESHOLD and GATED_MAX
  // live in app/scan/scoring.py and TypeScript cannot import them, so any
  // figure written into this copy is a second, unsynchronised original — it
  // would keep printing 7.0 the day the rule moves.
  //
  // The sentence used to end "...the only numbers the reader needs: the
  // failing subscore's own value". That was the justification for printing
  // them, and it stopped being true when the bars became bands: a value whose
  // measured swing is 1.3 is not a number the reader needs, on any surface.
  // The third route in, and the only one that can fire alone on a repository
  // where every category is clean. "The audit found X" is the wrong frame for
  // it: a critical says the code is dangerous, this says the report may not be
  // about the code that runs. Kept as its own sentence for that reason — and
  // because it is the reason a 9.8 with a green ring was misleading enough to
  // need a gate at all.
  const scope = reasons.filter((r) => r.kind === "unaudited_deployment");
  const scopeNamed = [...new Set(scope.map((r) => r.title || r.rule_id))];

  return (
    <p className="mt-3 text-sm text-muted">
      {parts.length > 0 && (
        <>This score is capped because the audit found {parts.join(" and ")}. </>
      )}
      {scope.length > 0 && (
        <>
          {parts.length > 0
            ? "It is also capped because "
            : "This score is capped because "}
          the audit may not describe the code you actually run (
          {scopeNamed.join(", ")}). A score is a statement about what we read.{" "}
        </>
      )}
      Categories are scored independently and can read higher than the total:
      the cap is on what the headline is allowed to claim while something
      disqualifying is open.
    </p>
  );
}

export function CategoryBars({
  categories,
  gatedBy,
  unexamined,
  unexaminedWithFindings,
  scored = true,
  findings = [],
}: {
  categories: Record<string, number>;
  gatedBy?: GateReason[];
  /** False on a free scan. Drives two things, exactly as in
   * app/report/html.py: a category the free scan DID look at is marked
   * "partly checked" rather than banded, and the cap paragraph is withheld
   * because there is no published score for it to explain.
   *
   * Without it this component drew Deploy and Testing as full green
   * "nothing serious found" on audit 2b957672 -- a free scan that decides
   * those two by asking whether a file exists. The HTML report for the same
   * audit said "partly checked" on all three rows it examined. Banding made
   * that worse rather than better: "10.0" was a number a reader could
   * distrust, "nothing serious found" is a sentence that asserts. */
  scored?: boolean;
  /** Categories nothing produced a finding for, from the scorer. They sit at
   * 10.0 for want of a producer, and drawing that as a full bar answers "is
   * my auth safe?" with a yes nobody checked — issue #181, at the row level.
   * Read from the score rather than derived here: the rule for which
   * categories an LLM-less scan cannot fill lives in app/scan/scoring.py. */
  unexamined?: string[];
  /** The subset of `unexamined` that holds a finding anyway. Those rows say
   * "not surveyed — see findings" instead of "not checked", because "not
   * checked" was printed above an Auth finding reading "service-role key,
   * bypassing Row Level Security — found in 21 places" on the same page.
   *
   * Read from the score rather than derived, and it matters here: this
   * component is handed the findings the PAGE shows, which on a free depth
   * is not necessarily all of them. Deriving would then quietly under-report
   * exactly the row this exists to correct. The fallback below is for stored
   * rows that predate the key. */
  unexaminedWithFindings?: string[];
  /** The audit's findings, for the serious-finding band override: a category
   * holding a confident critical or high may not claim the top band, because
   * the table below marks those rows "Important". See seriousCategories in
   * lib/format.ts and _serious_categories in app/report/html.py. */
  findings?: { category?: string; severity: string; confidence?: number }[];
}) {
  const skipped = new Set(unexamined ?? []);
  const holds = new Set(
    unexaminedWithFindings ??
      findings
        .map((f) => f.category ?? "")
        .filter((c) => skipped.has(c)),
  );
  const serious = seriousCategories(findings);
  return (
    <>
      <div className="flex flex-col gap-2">
        {Object.entries(categories).map(([name, value]) => {
          const band = categoryBand(value, serious.has(name));
          const partial = !scored && !skipped.has(name);
          return (
          <div key={name} className="flex items-center gap-3 text-sm">
            <span className="w-24 shrink-0 text-muted">{name}</span>
            {skipped.has(name) && holds.has(name) ? (
              // Nobody surveyed this category, and something landed in it
              // anyway. No bar and no number -- neither is earned -- but
              // "not checked" is false to the reader who scrolls to the
              // table and finds a row filed under this very name.
              <>
                <div className="h-2 flex-1 rounded-full bg-border/40" />
                <span className="shrink-0 text-right text-xs text-muted">
                  not surveyed — see findings
                </span>
              </>
            ) : skipped.has(name) ? (
              <>
                <div className="h-2 flex-1 rounded-full bg-border/40" />
                <span className="shrink-0 text-right text-xs text-muted">
                  not checked
                </span>
              </>
            ) : partial ? (
              // Not "not checked" -- something did run, and saying nothing
              // ran would send the reader hunting for an audit that already
              // happened. Not a band either: the free scan reads Security
              // with regexes and one pass of the cheapest model, and Deploy
              // and Testing by asking whether a file exists.
              <>
                <div className="h-2 flex-1 rounded-full bg-border/40" />
                <span className="shrink-0 text-right text-xs text-muted">
                  partly checked
                </span>
              </>
            ) : (
              <>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-border">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${band.pct}%`,
                      background: band.color,
                    }}
                  />
                </div>
                <span className="shrink-0 text-right text-xs text-muted">
                  {band.label}
                </span>
              </>
            )}
          </div>
          );
        })}
      </div>
      {/* Only where a score is published. This paragraph explains a headline
          number and a free scan has none, so on the free page it opened
          "This score is capped..." under a header that says there is no
          score -- and named the failing category while every row above it
          declined to. The report fixed this on its side; this copy did not
          have the flag to fix it with until now. */}
      {scored && <GateNote reasons={gatedBy} />}
    </>
  );
}
