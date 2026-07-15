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
export function scoreColor(total: number): string {
  if (total >= 8) return "#10b981";
  if (total >= 5) return "#eab308";
  return "#e5484d";
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
