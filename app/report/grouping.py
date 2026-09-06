"""Group one rule's repeats for DISPLAY, without touching what they scored.

MEASURED across 199 repositories: the heaviest produces 33 RLS findings against
a median of 3 for the repositories that produce any. Thirty-three rows that
differ only in a table name are not thirty-three things to read; the reader
learns nothing from the thirty-first that the second did not tell them, and
every other finding in the report is buried underneath.

WHY THIS IS NOT app/scan/collapse.py, which exists for the same complaint.
That one runs BEFORE compute_scores and keeps a single representative, so the
repeats stop costing anything. That is right for its rules — the same anon key
copied into 47 migrations is one fact — and wrong here:

    one write finding   penalty 1.5  -> Security 8.5, above the 7.0 gate
    forty open tables   the same, if collapsed the same way

A repository handing forty tables to the public key must not present a
Security subscore of 8.5 and pass the gate. So the penalty is left exactly as
it was, all N of it, and only the rendering changes. Nothing here runs before
scoring, and nothing here is stored: `findings_json` keeps every row, the Fix
Pack still sees each table, and re-running this over the stored findings
reproduces the same view.

The consequence of leaving the score alone is worth stating rather than
discovering: Security saturates to 0.0 at about seven open tables, so the
subscore stops distinguishing seven from forty. That is pre-existing, it is
shared with every rule that can fire many times, and above three tables the
repository is gated anyway — the total is capped at 6.9 either way. Changing
it would mean inventing a curve for how much the fortieth table matters, and
an unmeasured calibration is the thing this project distrusts most.
"""

from __future__ import annotations

from app.report.evidence import is_non_production
from app.scan.rls import RULE_ID as RLS_READ_RULE_ID
from app.scan.rls import WRITE_RULE_ID as RLS_WRITE_RULE_ID

# Rules whose repeats are one finding about many tables. Deliberately a small
# explicit set: a rule that fires once per genuinely distinct issue must keep
# its own row, and the default is to leave a rule alone.
GROUPABLE = frozenset({RLS_READ_RULE_ID, RLS_WRITE_RULE_ID})

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def group_for_display(findings: list[dict]) -> list[dict]:
    """One row per groupable rule, carrying the rest with it.

    Order is preserved: a group takes the position of its first member, so a
    report does not reshuffle because two of its rows merged.
    """
    groups: dict[tuple[str, bool], list[dict]] = {}
    out: list[dict | None] = []
    slots: dict[tuple[str, bool], int] = {}

    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        if rule_id not in GROUPABLE:
            out.append(finding)
            continue
        key = (rule_id, is_non_production(finding))
        if key not in groups:
            slots[key] = len(out)
            groups[key] = []
            out.append(None)      # reserved, filled below
        groups[key].append(finding)

    for rule_id, members in groups.items():
        out[slots[rule_id]] = _one_row(members)

    return [f for f in out if f is not None]


def _one_row(members: list[dict]) -> dict:
    """The representative, or the single finding unchanged.

    A group of one is returned AS IS. Rewriting a lone finding's title to say
    "in 1 table" would be a worse sentence than the one the detector wrote, and
    the median affected repository has three findings — most groups are small.
    """
    if len(members) == 1:
        return members[0]

    # Most severe first, then most confident: the row that survives has to be
    # the one whose severity the reader should act on, not whichever table
    # happened to sort first.
    rep = dict(min(members, key=lambda f: (
        _SEV_RANK.get(str(f.get("severity")), 9),
        -float(f.get("confidence", 0)),
    )))

    titles = [str(f.get("title", "")) for f in members]
    rep["occurrence_count"] = len(members)
    # The individual titles, kept whole. Each already names its table in the
    # sentence the detector wrote, so nothing has to parse one back out — and
    # a parser here would be a second copy of the one in the Fix Pack.
    rep["occurrence_titles"] = titles

    base = str(rep.get("title", ""))
    rep["title"] = f"{base} — and {len(members) - 1} more like it"
    rep["explanation"] = (
        f"{rep.get('explanation', '')}\n\n"
        f"This applies to {len(members)} tables in your schema, not just the "
        f"one named above. Each is the same finding about a different table:\n"
        + "\n".join(f"  · {t}" for t in titles)
    ).strip()
    return rep
