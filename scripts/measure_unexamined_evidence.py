#!/usr/bin/env python3
"""What would it cost to stop discarding evidence found in an unexamined category?

    psql "$DB_URL" -At -c "select json_build_object('id',id,'repo_url',repo_url,
      'created_at',created_at,'score_json',score_json,
      'findings_json',coalesce(findings_json,'[]'::jsonb))
      from audits where status='completed'" > /root/audits-dump.jsonl
    python scripts/measure_unexamined_evidence.py /root/audits-dump.jsonl

THE DEFECT. compute_scores drops a category nothing examined from the mean and
from the gate -- rightly, because a clean 10.0 nobody earned must not vote. But
the drop is unconditional, so a finding a static producer DID emit into that
category is dropped with it. Demonstrated by construction: adding a route that
reads the Supabase service-role key to a clean Next app moves Auth 10.0 -> 9.3
and moves the headline by exactly nothing.

`_gating_criticals` states the premise out loud -- "on a static-only audit
nothing ran that could have produced an Auth or Money & Data finding" -- and
app/scan/service_role.py has produced exactly that since 2026-08-19.

THE PROPOSAL MEASURED HERE, and it is asymmetric on purpose. Silence in a
category with no examiner stays excluded; a category holding at least one
finding re-enters the mean and the gate. Absence of evidence keeps proving
nothing; presence of evidence stops proving nothing too.

READ-ONLY, and off a dump rather than off the database. Re-auditing these
repositories to answer a scoring question would write fresh rows for repositories
already in the corpus -- the mistake DRYDOCK_LENS_PLAN.md records as the one
that killed the 56.5% figure.

THE ROWS THAT DO NOT REPRODUCE ARE REPORTED, NOT DROPPED QUIETLY. The stored
`categories` blob carries subscores AFTER the critical-ceiling was applied, so a
gated row cannot be re-derived from what was stored. Any row whose recomputed
CURRENT total disagrees with its stored total is excluded from the shift and
counted, because a delta measured off a reconstruction that does not reproduce
the original is not a measurement of anything.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.scoring import (  # noqa: E402
    CATEGORIES,
    _RAW_CATEGORY_WEIGHT,
    _apply_gate,
    _gate_reasons,
    ScoredFinding,
)

# Repositories that are ours: fixtures and canaries we audited to test the
# product. Counted in a column of their own rather than filtered out, the same
# way #421 reported the not_react shift -- a mean that quietly mixes our own
# fixtures into a customer-facing calibration is how a number stops meaning
# what its label says.
OURS_MARKERS = ("aiagent2046-coder/", "shipit-fixpack-canary",
                "drydock-fixpack-e2e-test", "drydock-vite-react-fixture")


def _is_ours(repo_url: str) -> bool:
    return any(m in (repo_url or "") for m in OURS_MARKERS)


def _finding(raw: dict) -> ScoredFinding:
    """Rebuild only the fields the scoring rules read. `title` and the prose
    fields are carried because _gate_reasons puts the title in its reason."""
    return ScoredFinding(
        rule_id=str(raw.get("rule_id") or ""),
        title=str(raw.get("title") or ""),
        severity=str(raw.get("severity") or ""),
        confidence=float(raw.get("confidence") or 0.0),
        category=str(raw.get("category") or ""),
    )


def _total(by_cat: dict[str, float], counted: list[str],
           findings: list[ScoredFinding]) -> float:
    """The headline, computed by the shipping rules rather than by a copy.

    Mirrors compute_scores' tail: weighted mean over the counted categories,
    then the gate, then the 10.0-with-findings correction.
    """
    divisor = sum(_RAW_CATEGORY_WEIGHT[c] for c in counted)
    if not divisor:
        return 0.0
    # by_cat[c], not by_cat.get(c, 10.0): main() has already refused any row
    # whose stored categories do not cover CATEGORIES, so a missing key here
    # would be a bug rather than an old row, and a default would hide it.
    total = sum(by_cat[c] * _RAW_CATEGORY_WEIGHT[c]
                for c in counted) / divisor
    total = round(_apply_gate(total, _gate_reasons(by_cat, counted, findings)), 1)
    if findings and total == 10.0:
        total = 9.9
    return total


def main(path: str) -> int:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()
            if line.strip()]

    affected: list[tuple[str, str, float, float, list[str]]] = []
    unreproducible = 0
    examined_rows = 0
    absent_categories: dict[str, int] = {}

    for row in rows:
        score = row.get("score_json") or {}
        by_cat = dict(score.get("categories") or {})
        if not by_cat or score.get("total") is None:
            continue
        examined_rows += 1

        # A row scored by an engine whose category set differs from today's.
        # MEASURED: the first real dump raised KeyError('Money & Data') here,
        # because rows exist that were written before that category did. Such
        # a row is refused rather than patched: filling the gap with 10.0
        # would invent a subscore the audit never assigned and then report a
        # shift relative to the invention. Which names are missing is printed,
        # because that is a fact about the ledger worth knowing.
        missing = [c for c in CATEGORIES if c not in by_cat]
        if missing:
            for name in missing:
                absent_categories[name] = absent_categories.get(name, 0) + 1
            continue

        unexamined = set(score.get("unexamined") or [])
        elsewhere = set((score.get("reported_elsewhere") or {}).keys())
        counted = [c for c in CATEGORIES
                   if c not in unexamined and c not in elsewhere]
        findings = [_finding(f) for f in (row.get("findings_json") or [])]

        # Reproduce the stored number first. Anything else is a delta between
        # two numbers of unknown provenance.
        if abs(_total(by_cat, counted, findings) - float(score["total"])) > 0.05:
            unreproducible += 1
            continue

        with_evidence = sorted(
            c for c in unexamined
            if any(f.category == c for f in findings))
        if not with_evidence:
            continue

        after = _total(by_cat, counted + with_evidence, findings)
        affected.append((str(row.get("id")), str(row.get("repo_url") or ""),
                         float(score["total"]), after, with_evidence))

    print(f"{len(rows)} rows in dump, {examined_rows} scored, "
          f"{unreproducible} could not be reproduced from what was stored "
          f"(gated rows: the ceiling rewrote their subscores)")
    if absent_categories:
        named = ", ".join(f"{name} ({count})"
                          for name, count in sorted(absent_categories.items()))
        print(f"refused, scored under a different category set: {named}")
    print(f"{len(affected)} rows hold a finding in a category the score "
          f"marked unexamined\n")

    if not affected:
        print("no measurable shift: the proposal moves nothing already stored")
        return 0

    for audit_id, repo_url, before, after, cats in sorted(
            affected, key=lambda r: r[3] - r[2]):
        mark = "ours " if _is_ours(repo_url) else "3rd  "
        print(f"  {mark} {audit_id[:8]}  {before:4.1f} -> {after:4.1f} "
              f"({after - before:+.2f})  {','.join(cats)}  {repo_url}")

    for label, subset in (("third-party", [a for a in affected
                                           if not _is_ours(a[1])]),
                          ("ours", [a for a in affected if _is_ours(a[1])])):
        if not subset:
            print(f"\n  {label:12s} no rows")
            continue
        before = sum(a[2] for a in subset) / len(subset)
        after = sum(a[3] for a in subset) / len(subset)
        print(f"\n  {label:12s} {len(subset):3d} rows   "
              f"{before:.2f} -> {after:.2f}   ({after - before:+.2f})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
