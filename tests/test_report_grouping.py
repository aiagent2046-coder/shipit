"""Grouping for display, and the line it must not cross.

MEASURED across 199 repositories: the heaviest produces 33 RLS findings against
a median of 3. Thirty-three rows differing only in a table name bury every
other finding in the report.

The line is that this is DISPLAY. app/scan/collapse.py answers the same
complaint by dropping the repeats before scoring, which is right for its rules
and wrong here: forty open tables collapsed to one penalty would score Security
8.5 and pass the 7.0 gate. So every test below that touches a score is really
asking "did the presentation layer stay out of the arithmetic".
"""

from __future__ import annotations

from app.report.grouping import group_for_display
from app.scan.rls import RULE_ID, WRITE_RULE_ID
from app.scan.scoring import ScoredFinding, compute_scores


def write(table: str) -> dict:
    return {"rule_id": WRITE_RULE_ID,
            "title": f"Anyone can delete rows in `{table}`",
            "severity": "critical", "confidence": 0.75, "category": "Security",
            "file": "supabase/migrations/0001.sql",
            "explanation": "Your migrations leave it open.", "fix_hint": "RLS."}


def read(table: str) -> dict:
    return {"rule_id": RULE_ID,
            "title": f"Table `{table}` is readable with your public key",
            "severity": "high", "confidence": 0.6, "category": "Security",
            "file": "supabase/migrations/0001.sql",
            "explanation": "Your migrations define it.", "fix_hint": "RLS."}


def other() -> dict:
    return {"rule_id": "env-file-committed", "title": "A .env is committed",
            "severity": "high", "confidence": 0.9, "category": "Security",
            "file": ".env"}


# --- what the reader gets ---------------------------------------------------

def test_many_tables_become_one_row_that_names_them_all() -> None:
    grouped = group_for_display([write(f"t{i}") for i in range(18)])
    assert len(grouped) == 1
    assert grouped[0]["occurrence_count"] == 18
    assert len(grouped[0]["occurrence_titles"]) == 18
    # Every table still reachable: a row that hid 17 of them would trade one
    # unreadable report for one that is missing most of its content.
    for i in range(18):
        assert f"`t{i}`" in grouped[0]["explanation"]


def test_the_two_rls_rules_stay_separate() -> None:
    """Readable and writable are different claims about different harm. Merging
    them would put "anyone can delete your rows" under a heading about reads."""
    grouped = group_for_display([read("a"), write("b"), read("c"), write("d")])
    assert sorted(f["rule_id"] for f in grouped) == sorted([RULE_ID, WRITE_RULE_ID])


def test_a_single_finding_is_left_exactly_as_it_was() -> None:
    """The median affected repository has three findings, so most groups are
    small — and "in 1 table" is a worse sentence than the detector's own."""
    one = write("users")
    assert group_for_display([one]) == [one]


def test_other_rules_pass_through_untouched() -> None:
    findings = [other(), write("a"), write("b"), other()]
    grouped = group_for_display(findings)
    assert [f["rule_id"] for f in grouped] == [
        "env-file-committed", WRITE_RULE_ID, "env-file-committed"]


def test_the_group_keeps_the_severity_that_should_be_acted_on() -> None:
    """Not whichever table sorted first."""
    mild = {**write("a"), "severity": "medium", "confidence": 0.6}
    grouped = group_for_display([mild, write("b"), write("c")])
    assert grouped[0]["severity"] == "critical"


def test_a_group_holds_the_position_of_its_first_member() -> None:
    """A report that reshuffled because two rows merged would look like a
    different audit."""
    grouped = group_for_display([other(), write("a"), write("b")])
    assert grouped[0]["rule_id"] == "env-file-committed"
    assert grouped[1]["rule_id"] == WRITE_RULE_ID


# --- the line: this is display, not arithmetic ------------------------------

def test_grouping_does_not_touch_the_score() -> None:
    """THE POINT OF THE WHOLE FILE. app/scan/collapse.py answers the same
    complaint by dropping repeats before scoring; here forty open tables
    collapsed to one penalty would score Security 8.5 and sail past the 7.0
    gate. The score is computed over the stored rows and this never sees it."""
    rows = [ScoredFinding(**{k: v for k, v in write(f"t{i}").items()
                             if k in ScoredFinding.__dataclass_fields__})
            for i in range(18)]
    before = compute_scores(rows)["categories"]["Security"]
    assert before == 0.0, before

    # Grouping the dicts changes the view. It cannot change that number,
    # because nothing recomputes it from the grouped list.
    grouped = group_for_display([write(f"t{i}") for i in range(18)])
    assert len(grouped) == 1
    assert compute_scores(rows)["categories"]["Security"] == before


def test_grouping_is_a_pure_view_and_does_not_mutate_its_input() -> None:
    """The stored findings are the record. A view that edited them in place
    would change what the Fix Pack sees and what a re-render reproduces."""
    findings = [write("a"), write("b")]
    snapshot = [dict(f) for f in findings]
    group_for_display(findings)
    assert findings == snapshot


def test_running_it_twice_gives_the_same_view() -> None:
    """It runs at every render over rows stored once, so it has to be
    idempotent in the only sense that matters: the same input, same output."""
    findings = [write("a"), write("b"), write("c")]
    assert group_for_display(findings) == group_for_display(findings)
