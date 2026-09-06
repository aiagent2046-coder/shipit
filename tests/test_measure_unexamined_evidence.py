"""The measurement that decides whether the unexamined-evidence rule ships.

A scoring change is argued from the number this script prints, so the script
itself has to be wrong in no way that the number would hide: it must reproduce
what was stored before it reports a delta from it, it must move a category only
on evidence, and it must not fold our own fixtures into a customer-facing mean.
"""

from __future__ import annotations

import json

from scripts.measure_unexamined_evidence import _is_ours, _total, main
from app.scan.scoring import ScoredFinding


def _row(audit_id: str, repo_url: str, *, total: float,
         categories: dict, unexamined: list[str],
         findings: list[dict]) -> dict:
    return {"id": audit_id, "repo_url": repo_url,
            "score_json": {"total": total, "categories": categories,
                           "unexamined": unexamined, "gated_by": [],
                           "reported_elsewhere": {}},
            "findings_json": findings}


_ALL_CLEAN = {"Security": 10.0, "Auth": 10.0, "Money & Data": 10.0,
              "Frontend": 10.0, "Deploy": 10.0, "Testing": 10.0}
_AUTH_FINDING = {"rule_id": "supabase-service-role-route", "title": "x",
                 "severity": "high", "confidence": 0.7, "category": "Auth"}


def _dump(tmp_path, rows: list[dict]):
    path = tmp_path / "dump.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(path)


def test_route_a_the_refused_one_is_still_measured_and_printed(tmp_path, capsys):
    """Route A rejoins the category to the mean. It was MEASURED AND REFUSED --
    on a weak repository it raises the total, so finding a vulnerability would
    improve the score -- and it stays in the report with its number beside it.
    A rejected proposal without its measurement is just an assertion."""
    cats = {**_ALL_CLEAN, "Auth": 9.3}
    rows = [_row("aaaaaaaa", "https://github.com/third/app",
                 total=_total(dict(cats), ["Security", "Frontend", "Deploy",
                                           "Testing"],
                              [ScoredFinding(**{**_AUTH_FINDING})]),
                 categories=cats, unexamined=["Auth", "Money & Data"],
                 findings=[_AUTH_FINDING])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    assert "0 could not be reproduced" in out
    assert "ROUTE A" in out and "1 rows" in out
    assert "-0.1" in out


def test_silence_in_an_unexamined_category_still_moves_nothing(tmp_path, capsys):
    """The asymmetry is the point. A category nobody examined and that holds
    nothing keeps its 10.0 out of the mean -- if this row moved, the proposal
    would be "count unexamined categories", which is the defect
    LLM_ONLY_CATEGORIES exists to prevent."""
    rows = [_row("bbbbbbbb", "https://github.com/third/app",
                 total=_total(dict(_ALL_CLEAN),
                              ["Security", "Frontend", "Deploy", "Testing"], []),
                 categories=dict(_ALL_CLEAN),
                 unexamined=["Auth", "Money & Data"], findings=[])]

    main(_dump(tmp_path, rows))

    assert "moves nothing already stored" in capsys.readouterr().out


def test_a_row_that_cannot_be_reproduced_is_counted_not_shifted(tmp_path, capsys):
    """A gated row's stored subscores were rewritten by the critical ceiling,
    so it cannot be re-derived from what was stored. Reporting a delta off a
    reconstruction that does not reproduce the original would be measuring two
    numbers of unknown provenance against each other."""
    cats = {**_ALL_CLEAN, "Auth": 9.3}
    rows = [_row("cccccccc", "https://github.com/third/app",
                 total=2.0,           # nothing like what these categories give
                 categories=cats, unexamined=["Auth", "Money & Data"],
                 findings=[_AUTH_FINDING])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    assert "1 could not be reproduced" in out
    assert "moves nothing already stored" in out


def test_a_row_scored_under_a_different_category_set_is_refused(tmp_path, capsys):
    """MEASURED: the first run against the real ledger died here with
    KeyError('Money & Data') -- rows exist that were written before that
    category did.

    Refused rather than patched. Filling the gap with 10.0 would invent a
    subscore the audit never assigned and then report a shift relative to the
    invention, which is the same species of error as measuring a delta off a
    reconstruction that does not reproduce the original.
    """
    cats = {k: v for k, v in _ALL_CLEAN.items() if k != "Money & Data"}
    rows = [_row("ffffffff", "https://github.com/third/app", total=9.6,
                 categories={**cats, "Auth": 9.3},
                 unexamined=["Auth"], findings=[_AUTH_FINDING])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    assert "predates a category: Money & Data (1)" in out
    assert "1 refused" in out
    assert "moves nothing already stored" in out


def test_our_own_fixtures_are_counted_in_their_own_column(tmp_path, capsys):
    """#421's rule, kept: a mean that mixes our canaries into a customer-facing
    calibration stops meaning what its label says."""
    cats = {**_ALL_CLEAN, "Auth": 9.3}
    total = _total(dict(cats), ["Security", "Frontend", "Deploy", "Testing"],
                   [ScoredFinding(**{**_AUTH_FINDING})])
    rows = [_row("dddddddd", "https://github.com/aiagent2046-coder/canary",
                 total=total, categories=cats,
                 unexamined=["Auth", "Money & Data"], findings=[_AUTH_FINDING]),
            _row("eeeeeeee", "https://github.com/third/app",
                 total=total, categories=cats,
                 unexamined=["Auth", "Money & Data"], findings=[_AUTH_FINDING])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    assert "third-party    1 rows" in out
    assert "ours           1 rows" in out


_CRITICAL_IN_AUTH = {"rule_id": "llm-security",
                     "title": "Endpoint runs shell commands with no login",
                     "severity": "critical", "confidence": 0.95,
                     "category": "Auth"}


def test_route_b_finds_the_critical_the_gate_cannot_hear(tmp_path, capsys):
    """A preview runs one rubric, the model files its finding by what it IS
    (#10), and the category `llm_categories` does not cover is marked
    unexamined -- so a confident CRITICAL gates on nothing. Demonstrated
    against compute_scores: the same finding scores 6.6 with the gate firing
    on a full audit and 9.9 with it silent on a preview."""
    cats = {**_ALL_CLEAN, "Auth": 8.1}
    # The total the OLD engine wrote -- this is a stored row, and the gate it
    # was scored by is the one that could not hear this critical. Using
    # today's here would make the row reproduce as already-gated and the
    # route show nothing, which is the whole thing being measured.
    rows = [_row("77777777", "https://github.com/third/app",
                 total=_total(dict(cats), ["Security", "Frontend", "Deploy",
                                           "Testing"],
                              [ScoredFinding(**_CRITICAL_IN_AUTH)],
                              pre_change_gate=True),
                 categories=cats, unexamined=["Auth", "Money & Data"],
                 findings=[_CRITICAL_IN_AUTH])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    route_b = out.split("ROUTE B")[1]
    assert "1 rows" in route_b
    assert "Auth" in route_b


def test_route_b_never_raises_a_total_and_route_a_does(tmp_path, capsys):
    """The property that makes this the half worth shipping.

    Route A inverts because a category sitting above the mean pulls it up. A
    gate has no such direction: it compresses into [0, GATED_MAX] preserving
    order, so it lowers a strong row and leaves an already-weak one where it
    is -- never above it. Both cases are asserted, because "can only lower"
    read as "always lowers" would be a claim this does not support.
    """
    weak = {**_ALL_CLEAN, "Auth": 8.1, "Security": 4.0, "Frontend": 5.0}
    strong = {**_ALL_CLEAN, "Auth": 8.1}
    counted = ["Security", "Frontend", "Deploy", "Testing"]
    findings = [ScoredFinding(**_CRITICAL_IN_AUTH)]

    for cats in (weak, strong):
        before = _total(dict(cats), counted, findings, pre_change_gate=True)
        after = _total(dict(cats), counted, findings)
        assert after <= before, "a gate must never raise a total"

    # Strong row: the gate bites, and the refused route pulls the other way.
    before = _total(dict(strong), counted, findings, pre_change_gate=True)
    assert _total(dict(strong), counted, findings) < before
    assert _total(dict(weak), counted + ["Auth"], findings,
                  pre_change_gate=True) > _total(
        dict(weak), counted, findings,
        pre_change_gate=True), "the refused route raises it, as measured"


def test_the_wording_count_includes_rows_the_routes_had_to_refuse(tmp_path, capsys):
    """Different question, different denominator, and this one is wider.

    The routes need a reconstructed total, so they drop rows whose category
    set predates today's. "Did this report say `not checked` above a finding"
    needs no arithmetic, and those dropped rows are on somebody's screen right
    now saying it. Counting them out would report the defect as rarer than it
    is -- the artefact that put the Frontend incidence at 87% instead of 78%.
    """
    cats = {k: v for k, v in _ALL_CLEAN.items() if k != "Money & Data"}
    rows = [_row("11111111", "https://github.com/third/old", total=9.6,
                 categories={**cats, "Auth": 9.3},
                 unexamined=["Auth"], findings=[_AUTH_FINDING])]

    main(_dump(tmp_path, rows))
    out = capsys.readouterr().out

    assert "1 refused" in out                      # the routes could not use it
    assert "1 of 1 scored rows" in out             # the wording count still did
    assert "Auth (1)" in out


def test_the_wording_count_honours_the_read_time_backfill(tmp_path, capsys):
    """A row stored before `unexamined` existed has it filled in by
    app/db.py at READ time -- the moment the report renders. Reading the raw
    blob would call such a row unaffected while the page it produces carries
    the label."""
    row = _row("22222222", "https://github.com/third/ancient", total=9.6,
               categories=dict(_ALL_CLEAN), unexamined=[],
               findings=[_AUTH_FINDING])
    del row["score_json"]["unexamined"]
    row["score_json"]["basis"] = "static_only"

    main(_dump(tmp_path, [row]))

    assert "1 of 1 scored rows" in capsys.readouterr().out


def test_a_row_with_no_finding_in_an_unexamined_category_is_not_counted(
        tmp_path, capsys):
    """The label is only wrong when something was found there. Without this
    the count would just be "rows that have unexamined categories", which is
    nearly all of them and says nothing."""
    rows = [_row("33333333", "https://github.com/third/app", total=9.6,
                 categories=dict(_ALL_CLEAN),
                 unexamined=["Auth", "Money & Data"],
                 findings=[{"rule_id": "no-dockerfile", "title": "y",
                            "severity": "low", "confidence": 0.9,
                            "category": "Deploy"}])]

    main(_dump(tmp_path, rows))

    assert "0 of 1 scored rows" in capsys.readouterr().out


def test_ours_is_recognised_by_owner_and_by_fixture_name():
    assert _is_ours("https://github.com/aiagent2046-coder/anything")
    assert _is_ours("https://github.com/someone/drydock-vite-react-fixture")
    assert not _is_ours("https://github.com/vercel/next.js")
    assert not _is_ours("")
