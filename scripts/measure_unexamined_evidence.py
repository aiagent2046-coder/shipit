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

TWO ROUTES ARE MEASURED, AND ONE OF THEM IS REFUSED BY ITS OWN NUMBER.

  ROUTE A -- a category holding a finding rejoins the MEAN. Measured, then
  refused: on a weak repository Auth at 9.3 sits above the mean, so admitting
  it RAISES the total (3.4 -> 4.0 on a constructed pair). Two otherwise
  identical repositories, and the one with the service-role bypass would score
  higher. It stays in this report with its number, because a rejected proposal
  without its measurement is only an assertion.

  ROUTE B -- a confident critical GATES from wherever it sits. A gate only
  ever compresses downward, so this direction cannot invert. Reachable today
  and not hypothetically: a preview runs one rubric, the model files its
  finding by what it IS (#10), and a CRITICAL categorised Auth lands outside
  `llm_categories`. The same finding scored 6.6 with the gate firing on a full
  audit and 9.9 with it silent on a preview.

  SHIPPED 2026-09-04, on 0 affected rows in the ledger. This script therefore
  reproduces a stored total under the PRE-change gate (`pre_change_gate`) --
  the engine that wrote those rows is no longer today's, and reproducing them
  under today's rules would silently reclassify as "unreproducible" exactly
  the rows the change is about.

THE WORDING is a third question and it has a WIDER denominator, so it is
counted separately and printed first: how many already-delivered reports said
"not checked" over a category that holds a finding. It needs no arithmetic, so
the rows the routes must refuse are counted here -- they render today, saying
it. `unexamined` is read through app/db.py's read-time backfill, because that
is the moment the report renders.

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

from app.db import _backfill_unexamined  # noqa: E402
from app.scan.scoring import (  # noqa: E402
    CATEGORIES,
    CRITICAL_GATE_MIN_CONFIDENCE,
    GATED_CATEGORIES,
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


def _deaf_criticals(by_cat: dict[str, float], counted: list[str],
                    findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Criticals the PRE-2026-09-04 gate could not hear.

    `_gating_criticals` used to filter by `counted`, on the stated premise
    that "on a static-only audit nothing ran that could have produced an Auth
    or Money & Data finding". Two producers contradict it: service_role.py
    files statically under Auth, and a rubric that DID run files a finding by
    what it IS (#10), so a preview whose one rubric is Security can return a
    confident CRITICAL categorised Auth. That filter is gone as of the change
    this script measured; the set is still computed here because it is the
    difference between the two engines, which is what a shift is measured
    across.
    """
    return [f for f in findings
            if f.severity == "critical"
            and f.confidence >= CRITICAL_GATE_MIN_CONFIDENCE
            and f.category in GATED_CATEGORIES
            and f.category in by_cat
            and f.category not in counted]


def _total(by_cat: dict[str, float], counted: list[str],
           findings: list[ScoredFinding], *,
           pre_change_gate: bool = False) -> float:
    """The headline, computed by the shipping rules rather than by a copy.

    Mirrors compute_scores' tail: weighted mean over the counted categories,
    then the gate, then the 10.0-with-findings correction.

    `pre_change_gate` walks the gate BACK to the engine that wrote the stored
    rows, by dropping the critical reasons whose category went unexamined --
    subtracted from the shipping rule rather than reimplemented beside it, so
    the baseline cannot drift from the real one in any other respect.

    It is a subtraction and not an addition because the change shipped: a
    confident critical now gates from wherever it sits. Reproducing a stored
    total means modelling the engine that produced it, and after the change
    that is no longer today's engine. The mean is untouched by any of this --
    admitting a category to the mean because it holds a finding was measured
    and REFUSED (route A): a category at 9.3 sitting above a weak
    repository's mean raises the total, so finding a vulnerability would
    improve the score.
    """
    divisor = sum(_RAW_CATEGORY_WEIGHT[c] for c in counted)
    if not divisor:
        return 0.0
    # by_cat[c], not by_cat.get(c, 10.0): main() has already refused any row
    # whose stored categories do not cover CATEGORIES, so a missing key here
    # would be a bug rather than an old row, and a default would hide it.
    total = sum(by_cat[c] * _RAW_CATEGORY_WEIGHT[c]
                for c in counted) / divisor
    reasons = _gate_reasons(by_cat, counted, findings)
    if pre_change_gate:
        deaf = {(f.rule_id, f.category)
                for f in _deaf_criticals(by_cat, counted, findings)}
        reasons = [r for r in reasons
                   if r.get("kind") != "critical"
                   or (r.get("rule_id"), r.get("category")) not in deaf]
    total = round(_apply_gate(total, reasons), 1)
    if findings and total == 10.0:
        total = 9.9
    return total


def main(path: str) -> int:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()
            if line.strip()]

    affected: list[tuple[str, str, float, float, list[str]]] = []
    deaf: list[tuple[str, str, float, float, list[str]]] = []
    unreproducible = 0
    examined_rows = 0
    refused_rows = 0
    measurable = 0
    absent_categories: dict[str, int] = {}
    mislabelled: dict[str, int] = {}
    mislabelled_rows = 0

    for row in rows:
        score = row.get("score_json") or {}
        by_cat = dict(score.get("categories") or {})
        if not by_cat or score.get("total") is None:
            continue
        examined_rows += 1

        # THE WORDING, counted BEFORE the refusals below and over every scored
        # row. The two routes need a reconstructed total, so they must drop
        # rows whose category set predates today's. This question needs no
        # arithmetic at all -- only "did a row say `not checked` above a
        # finding" -- and those dropped rows are on somebody's screen right
        # now, saying it. A denominator that excluded them would report the
        # defect as rarer than it is.
        #
        # `unexamined` is read through app/db.py's own backfill rather than
        # off the blob: a row stored before the key existed has it filled in
        # at READ time, which is exactly the moment the report renders. Taking
        # the raw blob would call those rows unaffected while the page they
        # produce carries the label.
        labelled = set(
            (_backfill_unexamined(score) or {}).get("unexamined") or [])
        holding = sorted(labelled & {str(f.get("category"))
                                     for f in (row.get("findings_json") or [])})
        if holding:
            mislabelled_rows += 1
            for name in holding:
                mislabelled[name] = mislabelled.get(name, 0) + 1

        # A row scored by an engine whose category set differs from today's.
        # MEASURED: the first real dump raised KeyError('Money & Data') here,
        # because rows exist that were written before that category did. Such
        # a row is refused rather than patched: filling the gap with 10.0
        # would invent a subscore the audit never assigned and then report a
        # shift relative to the invention. Which names are missing is printed,
        # because that is a fact about the ledger worth knowing.
        missing = [c for c in CATEGORIES if c not in by_cat]
        if missing:
            refused_rows += 1
            for name in missing:
                absent_categories[name] = absent_categories.get(name, 0) + 1
            continue

        unexamined = set(score.get("unexamined") or [])
        elsewhere = set((score.get("reported_elsewhere") or {}).keys())
        counted = [c for c in CATEGORIES
                   if c not in unexamined and c not in elsewhere]
        findings = [_finding(f) for f in (row.get("findings_json") or [])]

        # Reproduce the stored number first, under the gate of the engine that
        # WROTE it. Anything else is a delta between two numbers of unknown
        # provenance -- and after the route-B change shipped, today's gate is
        # no longer the one these rows were scored by.
        if abs(_total(by_cat, counted, findings, pre_change_gate=True)
               - float(score["total"])) > 0.05:
            unreproducible += 1
            continue

        measurable += 1
        stored = float(score["total"])
        audit_id = str(row.get("id"))
        repo_url = str(row.get("repo_url") or "")

        # ROUTE A -- the mean. Measured and REFUSED: see _total's docstring.
        # Kept in the report because a rejected proposal with its number
        # beside it is the record; deleting it would leave only the assertion.
        with_evidence = sorted(
            c for c in unexamined
            if any(f.category == c for f in findings))
        if with_evidence:
            affected.append((audit_id, repo_url, stored,
                             _total(by_cat, counted + with_evidence, findings,
                                    pre_change_gate=True),
                             with_evidence))

        # ROUTE B -- the gate, now SHIPPED. A confident critical gates from
        # wherever it sits; `stored` is what the old engine said and the
        # second number is what today's says. This one can only lower.
        deaf_here = _deaf_criticals(by_cat, counted, findings)
        if deaf_here:
            deaf.append((audit_id, repo_url, stored,
                         _total(by_cat, counted, findings),
                         sorted({f.category for f in deaf_here})))

    print(f"{len(rows)} rows in dump, {examined_rows} scored, "
          f"{refused_rows} refused, {unreproducible} could not be reproduced "
          f"from what was stored (gated rows: the ceiling rewrote their "
          f"subscores)")
    if absent_categories:
        named = ", ".join(f"{name} ({count})"
                          for name, count in sorted(absent_categories.items()))
        print(f"  refused because the row predates a category: {named}")
    # The denominator, printed rather than left to be inferred from the counts
    # above. Naming which categories were missing said nothing about how many
    # ROWS that removed, so "2 rows are affected" had no population behind it.
    print(f"{measurable} rows measurable\n")

    # Printed first because it is the one number here that describes rows
    # already delivered rather than a proposal about future ones.
    print("THE WORDING -- rows whose report said \"not checked\" over a "
          "category that holds a finding")
    print(f"  {mislabelled_rows} of {examined_rows} scored rows"
          + (f"   ({', '.join(f'{n} ({c})' for n, c in sorted(mislabelled.items()))})"
             if mislabelled else ""))
    print("  counted over every scored row, refusals included: the question "
          "needs no arithmetic\n")

    _report("ROUTE A -- category rejoins the mean (REFUSED: measured to raise "
            "a weak repository's total, so finding a vulnerability would "
            "improve its score)", affected)
    _report("ROUTE B -- a confident critical gates from wherever it sits "
            "(SHIPPED 2026-09-04; can only lower)", deaf)
    return 0


def _report(title: str,
            rows: list[tuple[str, str, float, float, list[str]]]) -> None:
    print(f"{title}\n  {len(rows)} rows")
    if not rows:
        print("  moves nothing already stored\n")
        return
    for audit_id, repo_url, before, after, cats in sorted(
            rows, key=lambda r: r[3] - r[2]):
        mark = "ours " if _is_ours(repo_url) else "3rd  "
        print(f"  {mark} {audit_id[:8]}  {before:4.1f} -> {after:4.1f} "
              f"({after - before:+.2f})  {','.join(cats)}  {repo_url}")
    for label, subset in (("third-party", [r for r in rows
                                           if not _is_ours(r[1])]),
                          ("ours", [r for r in rows if _is_ours(r[1])])):
        if not subset:
            print(f"  {label:12s} no rows")
            continue
        before = sum(r[2] for r in subset) / len(subset)
        after = sum(r[3] for r in subset) / len(subset)
        print(f"  {label:12s} {len(subset):3d} rows   "
              f"{before:.2f} -> {after:.2f}   ({after - before:+.2f})")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
