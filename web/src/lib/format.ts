import type { Severity } from "./types";

// Mirrors app/report/plain_language.py TIERS (reader-facing labels) and
// app/report/html.py colors, so the web UI and the HTML report agree.
export const SEVERITY_META: Record<
  Severity,
  { label: string; emoji: string; color: string; badgeClass: string }
> = {
  critical: {
    label: "Fix before launch",
    emoji: "🔥",
    color: "#e5484d",
    badgeClass: "bg-critical/15 text-critical border-critical/30",
  },
  high: {
    label: "Important",
    emoji: "⚠️",
    color: "#f76b15",
    badgeClass: "bg-high/15 text-high border-high/30",
  },
  medium: {
    label: "Worth fixing",
    emoji: "👀",
    color: "#eab308",
    badgeClass: "bg-mediumsev/15 text-mediumsev border-mediumsev/30",
  },
  low: {
    label: "Good to know",
    emoji: "📝",
    color: "#8b8d98",
    badgeClass: "bg-low/15 text-low border-low/40",
  },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ONE PLACE THAT PUTS A CURRENCY NEXT TO A NUMBER.
//
// There were five, each writing its own. When the product was repriced from
// dollars to roubles on 2026-08-23, /pricing was updated and the others were
// not — so the audit page, which is the page a buyer actually pays from,
// rendered "$990.00 RUB". A dollar sign in front of a rouble amount, on the
// screen a payment aggregator's reviewer reaches, four days after they
// rejected the site for not stating a price properly.
//
// The defect was not the missed edit. It was that a currency symbol could be
// typed as a literal beside a value that carries its own currency code —
// nothing connected the two, so nothing could notice they disagreed.
const CURRENCY_SYMBOLS: Record<string, string> = {
  RUB: "₽",
};

/**
 * An amount with its currency, the way a reader should see it.
 *
 * The symbol follows the number, which is the convention for the rouble and
 * reads acceptably for a bare code. A currency with no symbol here renders as
 * its ISO code rather than a guess: an unknown currency should look unfamiliar,
 * not look like dollars.
 */
export function formatMoney(
  amount: string | number,
  currency: string | null | undefined,
): string {
  const code = (currency ?? "").trim();
  if (!code) return String(amount);
  return `${amount} ${CURRENCY_SYMBOLS[code] ?? code}`;
}

export function sortFindings<T extends { severity: Severity; confidence?: number }>(
  findings: T[],
): T[] {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      (b.confidence ?? 0) - (a.confidence ?? 0),
  );
}

// Same thresholds as app/report/html.py _score_color.
//
// For the TOTAL only. The total is published as a number and earns one: across
// three byte-identical runs of the same repository it moved 0.1. A category
// does not — see categoryBand.
export function scoreColor(total: number): string {
  if (total >= 8) return "#10b981";
  if (total >= 5) return "#eab308";
  return "#e5484d";
}

// A category is published as a band, not as a number, because a number is more
// precision than the measurement has. Three audits of Avisafety-1/blank-slate,
// same revision, same model, byte-identical input:
//
//     Security       3.1   1.8   2.2      swing 1.3
//     Money & Data   0.0   0.3   1.1      swing 1.1
//     Auth           6.9   7.5   6.8      swing 0.7
//     total          4.1   4.0   4.1      swing 0.1
//
// One decimal place on a category claims +/-0.05 where the measurement carries
// +/-1.3.
//
// THIS IS A SECOND COPY of app/report/html.py _band, and the duplication is
// deliberate but not free. TypeScript cannot import GATE_THRESHOLD from
// app/scan/scoring.py, and the alternative -- shipping the band in the audit
// payload -- leaves every audit stored before the key existed with no band and
// a renderer that must fall back to printing the number, which is the defect.
// tests/test_web_score_parity.py reads this file and fails if these numbers or
// these words stop matching the Python. Change one, change both; the test will
// say so.
//
// This page is the surface the customer sees FIRST -- the HTML report sits
// behind a link on it -- and it kept publishing exact category numbers for a
// full release after the report stopped. Audit 2230094e drew "Auth 1.6,
// Security 1.9, Money & Data 3.9" with proportional bars while the report for
// the same audit drew bands.
const GATE_THRESHOLD = 7.0;
const BAND_FLOOR = GATE_THRESHOLD / 2;

export interface CategoryBand {
  /** What the row says instead of a number. */
  label: string;
  /** How full the bar is drawn. Snapped to the band: a proportional fill
   * would restate the exact value in pixels -- the same claim, in a channel
   * nobody thought to check. */
  pct: number;
  /** The bar's colour, from the band and not from the value. Keying this on
   * the value leaves two rows in one band looking different with nothing on
   * the page to say why: the report drew Security 5.3 yellow and Money & Data
   * 3.9 red under identical text and identical width. */
  color: string;
}

export function categoryBand(
  value: number,
  holdsSerious: boolean = false,
): CategoryBand {
  if (value >= GATE_THRESHOLD) {
    if (holdsSerious) {
      // Forbids the top band; never lifts a row already below it.
      return { label: "problems found", pct: 60, color: "#eab308" };
    }
    return { label: "nothing serious found", pct: 100, color: "#10b981" };
  }
  if (value >= BAND_FLOOR) {
    return { label: "problems found", pct: 60, color: "#eab308" };
  }
  return { label: "serious problems", pct: 25, color: "#e5484d" };
}

// The categories whose rows may not claim the top band: they hold a finding
// the same page marks "Fix before launch" or "Important". One high costs
// 1.0 x confidence against a threshold of 7.0, so a category needs four
// confident highs to leave the top band on arithmetic alone -- audit
// ba360e21 top-banded Auth over an unauthenticated endpoint and unsalted
// SHA-256 passwords, and audit b4bf9c07 top-banded Auth over "No
// authentication on any API endpoint", with "⚠️ Important" rows directly
// below the sentence. Render-side so stored audits are fixed too; see
// app/report/html.py _serious_categories for the full reasoning.
//
// 0.7 is CRITICAL_GATE_MIN_CONFIDENCE -- the scorer's own floor for letting
// one finding make a categorical claim. A second unsynchronised copy, like
// GATE_THRESHOLD above; tests/test_web_score_parity.py holds both to the
// Python values.
const SERIOUS_BAND_MIN_CONFIDENCE = 0.7;

export function seriousCategories(
  findings: { category?: string; severity: string; confidence?: number }[],
): Set<string> {
  return new Set(
    findings
      .filter(
        (f) =>
          (f.severity === "critical" || f.severity === "high") &&
          (f.confidence ?? 0) >= SERIOUS_BAND_MIN_CONFIDENCE &&
          f.category,
      )
      .map((f) => f.category as string),
  );
}

export function scoreVerdict(total: number): string {
  if (total >= 8) return "Ready to ship";
  if (total >= 5) return "Some work before launch";
  return "Not production-ready yet";
}

export function severityCounts(
  findings: { severity: Severity }[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
