"""Tests for the HTML report. The escaping tests matter most: file
names and titles come from a hostile archive and from the LLM.
"""

import re

from app.report.html import render_report


def result(findings: list[dict]) -> dict:
    return {
        "stack": "nextjs",
        "score": {"total": 6.4, "categories": {"Security": 5.0, "Auth": 10.0,
                                               "Correctness": 10.0, "Config": 10.0,
                                               "Testing": 9.6, "Deploy": 9.8}},
        "findings": findings,
    }


def _finding() -> dict:
    """The plainest production finding: enough to render a row, nothing more."""
    return {
        "severity": "critical", "confidence": 0.9,
        "title": "AWS key in code", "file": "src/config.ts", "line": 3,
        "masked": "AKIA****(20 chars)",
    }


def test_report_contains_score_stack_and_findings():
    html = render_report(result([{
        "severity": "critical", "confidence": 0.9,
        "title": "AWS key in code", "file": "src/config.ts", "line": 3,
        "masked": "AKIA****(20 chars)",
    }]), project_name="demo")
    assert "6.4" in html
    assert "nextjs" in html
    assert "AWS key in code" in html
    assert "src/config.ts:3" in html
    assert "1 critical" in html


def test_hostile_filename_and_title_are_escaped():
    html = render_report(result([{
        "severity": "high", "confidence": 0.5,
        "title": '<img src=x onerror=alert(1)>',
        "file": '<script>alert("xss")</script>.py', "line": 1,
        "masked": "",
    }]))
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_hostile_project_name_escaped():
    html = render_report(result([]), project_name="<svg onload=alert(1)>")
    assert "<svg onload" not in html


def test_findings_sorted_by_severity():
    html = render_report(result([
        {"severity": "low", "confidence": 0.9, "title": "ZLOW", "file": "a"},
        {"severity": "critical", "confidence": 0.9, "title": "ACRIT", "file": "b"},
    ]))
    assert html.index("ACRIT") < html.index("ZLOW")


def test_empty_findings_render_clean_state():
    html = render_report(result([]))
    assert "No issues found" in html


def test_report_endpoint_renders_persisted_audit():
    import app.main as main_mod
    from fastapi.testclient import TestClient

    def _row(audit_id):
        return {
            "id": audit_id,
            "score_json": {"total": 4.2, "basis": "static+llm",
                           "categories": {c: 5.0 for c in
                                          ("Security", "Auth", "Correctness",
                                           "Config", "Testing", "Deploy")}},
            "findings_json": [
                {"rule_id": "env-file-committed", "title": "Env file",
                 "severity": "critical", "confidence": 0.9,
                 "category": "Security", "file": ".env", "line": 0,
                 "masked": ""}],
        }

    class FakeRepo:
        # The report endpoint uses get_authorized, not get: only "known-id"
        # exists and only the matching token unlocks it.
        async def get_authorized(self, audit_id, access_token):
            if audit_id != "known-id" or access_token != "t0k":
                return None
            return _row(audit_id)

    main_mod.app.dependency_overrides[main_mod.get_audit_repo] = lambda: FakeRepo()
    try:
        client = TestClient(main_mod.app)
        r = client.get("/v1/audits/known-id/report?token=t0k")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "Fix before launch" in r.text
        # Right id, no/wrong token -> 404 (doesn't confirm the id exists).
        assert client.get("/v1/audits/known-id/report").status_code == 404
        assert client.get(
            "/v1/audits/known-id/report?token=wrong").status_code == 404
        assert client.get(
            "/v1/audits/unknown/report?token=t0k").status_code == 404
    finally:
        main_mod.app.dependency_overrides.pop(main_mod.get_audit_repo, None)


def test_report_endpoint_422s_on_missing_score_json():
    """A row with a null/malformed score_json must yield a clean 422,
    not an unhandled KeyError -> 500 from inside render_report."""
    import app.main as main_mod
    from fastapi.testclient import TestClient

    class FakeRepo:
        async def get_authorized(self, audit_id, access_token):
            return {"id": audit_id, "score_json": None, "findings_json": []}

    main_mod.app.dependency_overrides[main_mod.get_audit_repo] = lambda: FakeRepo()
    try:
        client = TestClient(main_mod.app)
        r = client.get("/v1/audits/any-id/report?token=t0k")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "report_unavailable"
    finally:
        main_mod.app.dependency_overrides.pop(main_mod.get_audit_repo, None)


def test_collapsed_occurrence_note_surfaces_in_html():
    """The "appears in N files" note that collapse_repeats appends must
    reach the rendered HTML, even for rule_ids with a hardcoded plain
    translation (which otherwise replaces the explanation wholesale)."""
    from app.scan.collapse import collapse_repeats

    findings = [{
        "rule_id": "supabase-anon-key", "title": "anon key",
        "severity": "low", "confidence": 0.3, "category": "Security",
        "file": f"migrations/{i}.sql", "line": 1,
        "masked": "eyJh****(210 chars)", "explanation": "", "fix_hint": "",
    } for i in range(6)]
    collapsed = collapse_repeats(findings)
    assert len(collapsed) == 1

    html = render_report(result(collapsed))
    assert "found in 6 places" in html   # title-derived count (tech line)
    assert "6 files" in html             # occurrence note surfaced in the risk text


# --- production / non-production split ---
#
# The report used to be one flat table, which asked the reader to tell a
# secret in a running handler from a secret in a test fixture by squinting at
# the file path. Readers don't: they either treat every row as urgent or, after
# the first false alarm, none of them. Findings are still all present -- the
# split is about ordering attention, not about hiding.

_PROD = {
    "severity": "critical", "confidence": 0.95,
    "title": "AWS Access Key ID", "file": "src/config.ts", "line": 3,
    "masked": "AKIA****(20 chars)",
}
_TEST_FILE = {
    "severity": "medium", "confidence": 0.33,
    "title": "AWS Access Key ID (test file)", "file": "tests/test_secrets.py",
    "line": 12, "masked": "AKIA****(20 chars)", "context": "test_file",
}


def test_test_findings_go_under_their_own_heading():
    html = render_report(result([_PROD, _TEST_FILE]))
    assert "In tests, examples and documentation" in html
    # Both are present; the production one comes first.
    assert html.index("src/config.ts") < html.index("tests/test_secrets.py")
    assert html.index("In tests, examples and documentation") < html.index(
        "tests/test_secrets.py")


def test_no_heading_when_everything_is_production_code():
    html = render_report(result([_PROD]))
    assert "In tests, examples and documentation" not in html


def test_clean_production_code_is_said_out_loud():
    """The case this whole split exists for: nothing wrong with the running
    app, findings only in fixtures. Silence there reads as "we found problems"
    when the truth is the opposite."""
    html = render_report(result([_TEST_FILE]))
    assert "Nothing found in the code your app runs." in html
    assert "In tests, examples and documentation" in html
    assert "tests/test_secrets.py" in html


def test_llm_findings_without_context_are_split_by_path():
    """LLM findings carry no `context` field, so the split falls back to the
    path. Without this, an LLM finding about a fixture lands in the production
    section next to real ones."""
    html = render_report(result([{
        "severity": "high", "confidence": 0.7,
        "title": "Webhook mutates database without authentication",
        "file": "tests/fixtures/unauthenticated_webhook.ts", "line": 11,
    }]))
    assert "Nothing found in the code your app runs." in html
    assert "In tests, examples and documentation" in html


def test_migration_findings_stay_in_the_production_section():
    """A migration is applied state. `examples/migrations/` must not slip into
    the non-production section on the strength of its first path segment."""
    html = render_report(result([{
        "severity": "critical", "confidence": 0.95,
        "title": "Hardcoded secret in SQL/PLpgSQL assignment (committed database migration)",
        "file": "examples/migrations/0007_seed.sql", "line": 4,
    }]))
    assert "In tests, examples and documentation" not in html


def test_free_scan_publishes_no_mark_out_of_ten():
    """This test asserted the opposite until a second repository settled it.

    The free tier first published no number, because the score ROSE when
    fewer checks ran: 7.2 with the auth and injection rubrics on audit
    ed402e63, 9.1 without them. The number came back once unexamined
    categories stopped voting and one confident critical could cap the total
    -- recomputed on that same audit, 5.4 full against 6.1 static-only: a 0.7
    gap, both failing.

    That reasoning rested on one repository. On kristina_agent_center the same
    comparison is 9.9 static-only against 4.7 full, a gap of 5.2, with the
    free number reading as a clean bill of health on a codebase that lets an
    unauthenticated caller run commands as root over SSH. The protection
    covers Auth, Money & Data and Frontend; it cannot cover Security, which
    both tiers fill -- with the static rules finding only "no Dockerfile",
    Security read 10.0 and carried the mean.

    So: no mark out of ten from a scan that cannot earn one. What the free
    report shows is what it looked at and what it found. The scope
    requirement did not go away -- it is asserted below exactly as before.
    """
    r = result([_finding()])
    r["score"]["basis"] = "static_only"
    r["score"]["unexamined"] = ["Auth", "Money & Data"]
    html = render_report(r)

    assert 'class="ring"' not in html, "the headline score ring is back"
    assert 'class="noring"' in html
    # The whole claim, not a fragment of it: asserting "out of ten" passed
    # against a mutation that flipped the sentence to "produces a summary out
    # of ten". A substring is not a statement.
    assert "does not produce a mark out of ten" in html
    # Scope still travels with the report, which is what mattered all along.
    assert "Auth" in html and "Money &amp; Data" in html
    assert "Nothing here examined" in html


def test_an_unexamined_category_is_never_drawn_as_a_passing_bar():
    """The reason the score was withheld in the first place, kept as an
    invariant rather than as a blanket ban on the number.

    An unexamined category sits at 10.0 for want of a producer. Rendering
    that as a full bar answers "is my auth safe?" with a confident yes that
    nothing checked -- which is worse than any headline, because it is
    specific.
    """
    r = result([_finding()])
    r["score"]["basis"] = "static_only"
    r["score"]["categories"] = {"Security": 5.0, "Auth": 10.0,
                                "Testing": 9.6, "Deploy": 9.8}
    r["score"]["unexamined"] = ["Auth"]
    html = render_report(r)

    # Matched on the label span, not on the word: "Auth" also appears in the
    # scope note above the bars, and splitting on it picked up the preamble.
    auth_row = next(row for row in html.split('<div class="cat">')
                    if row.startswith('<span class="cat-name">Auth</span>'))
    assert "not checked" in auth_row
    assert "10.0" not in auth_row
    assert "fill" not in auth_row, "an unexamined category must draw no bar"


def test_a_stored_audit_without_the_unexamined_key_says_something_honest():
    """Rows written before the scorer recorded `unexamined` cannot name the
    categories. They still must not imply the scan covered everything."""
    r = result([_finding()])
    r["score"]["basis"] = "static_only"
    r["score"].pop("unexamined", None)
    html = render_report(r)

    assert "does not review your authentication" in html


def test_full_report_is_unchanged_and_missing_basis_keeps_its_score():
    """The paid shape still scores, and so does an audit from before `basis`.

    Rows written before the field existed must keep rendering as they always
    did rather than silently losing their score to a policy they predate.
    """
    scored = result([_finding()])
    scored["score"]["basis"] = "static+llm"
    html = render_report(scored)
    assert 'class="ring"' in html and "6.4" in html

    legacy = result([_finding()])          # no basis key at all
    html2 = render_report(legacy)
    assert 'class="ring"' in html2 and "6.4" in html2


# --- why a score was capped -------------------------------------------------

def _gated(reasons: list[dict], basis: str = "static+llm") -> dict:
    return {
        "stack": "nextjs",
        "score": {"total": 6.5, "basis": basis,
                  "categories": {"Security": 8.2, "Auth": 10.0,
                                 "Testing": 9.6, "Deploy": 9.8},
                  "gated_by": reasons},
        "findings": [_finding()],
    }


def test_capped_score_says_a_critical_caused_it():
    """The case with no visual tell: every bar above 7.0, headline 6.5.

    Without this line the breakdown appears to contradict the headline, and a
    reader who cannot reconcile the two has no reason to trust either.
    """
    html = render_report(_gated([
        {"kind": "critical", "category": "Security",
         "rule_id": "env-file-committed", "title": "Committed .env file"},
    ]))
    assert "cannot exceed" in html
    assert "Committed .env file" in html


def test_capped_score_names_the_failing_category():
    html = render_report(_gated([
        {"kind": "subscore", "category": "Security", "value": 5.9},
    ]))
    assert "Security" in html


def test_the_cap_note_names_the_category_without_its_number():
    """Measured on a real report: audit b504326, Drydock auditing itself.

    The bars had just stopped publishing category numbers, because three
    byte-identical runs of the same repository moved Security by 1.3. Three
    lines below them this paragraph printed "a safety category below 7.0
    (Security 5.3, Money & Data 3.9)" -- the numbers back, in a place nobody
    re-read when the bars changed. The threshold stays: it is the boundary
    the rows are already drawn against, so naming a category here says what
    its row says and no more.

    Two categories, because one would let a bare category name pass by
    accident from the joining comma.
    """
    html = render_report(_gated([
        {"kind": "subscore", "category": "Security", "value": 5.3},
        {"kind": "subscore", "category": "Money & Data", "value": 3.9},
    ]))
    assert "below 7.0 (Money &amp; Data, Security)" in html
    assert "5.3" not in html
    assert "3.9" not in html


def test_the_note_describes_compression_not_a_flat_ceiling():
    """The gate scales the mean; it does not clip it.

    The sentence said "capped at 6.9" -- the flat ceiling _apply_gate tried
    first and rejected for flattening 40% of failing repos onto one number.
    A real audit (ai-co-founder-matching) then published 5.1 directly above
    those words, with 6.9 appearing nowhere else on the page: its category
    mean was 7.4 and the gate compressed it. A reader who tries to reconcile
    5.1 with "capped at 6.9" cannot, which is the headline contradicting the
    text beside it -- the exact defect the gate exists to remove.

    The total is set below GATED_MAX deliberately: at 6.5 the old wording
    looked close enough to pass, and only a value that is plainly not the
    cap can tell the two explanations apart.
    """
    row = _gated([{"kind": "subscore", "category": "Security", "value": 5.9}])
    row["score"]["total"] = 5.1
    html = render_report(row)

    assert "cannot exceed 6.9" in html
    assert "compressed" in html
    assert "capped at 6.9" not in html, (
        "describes the flat ceiling that was measured and rejected")


def test_a_page_with_no_score_does_not_explain_the_score():
    """Measured on a real free report, audit 544b91bd.

    The page opened "A free scan does not produce a mark out of ten, because
    it does not look at enough to earn one", marked Security "partly checked"
    rather than giving it a number, and then printed:

        This score cannot exceed 6.9 because the audit found a safety
        category below 7.0 (Security 5.5).

    Three things wrong at once. It says "this score" where there is none. It
    publishes the exact category number the page two paragraphs above had
    declined to publish. And 6.9 appears nowhere else on a free page, so the
    reader has nothing to reconcile it against.

    Withholding a number in one section and printing it in the next is not a
    smaller claim than publishing it. It is the same claim, made where nobody
    thought to look for it.
    """
    reasons = [{"kind": "subscore", "category": "Security", "value": 5.5}]

    for basis in ("static+preview", "static_only"):
        html = render_report(_gated(reasons, basis=basis))
        assert "cannot exceed" not in html, basis
        assert "Security 5.5" not in html, basis

    # ...and the paid page still carries it, which is the whole point of the
    # paragraph: a headline that contradicts every bar above it needs saying.
    # It names the category; the number stayed withheld everywhere, which is
    # what the free page was originally wrong about.
    paid = render_report(_gated(reasons))
    assert "cannot exceed" in paid and "Security" in paid
    assert "5.5" not in paid


def test_hostile_gate_reason_title_is_escaped():
    """gated_by carries an LLM-authored title straight from the finding."""
    html = render_report(_gated([
        {"kind": "critical", "category": "Security", "rule_id": "llm-security",
         "title": "<script>alert(1)</script>"},
    ]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_ungated_and_legacy_rows_print_no_cap_note():
    """Empty means the gate did not fire; absent means an audit stored before
    the scorer recorded reasons. Neither may print an explanation -- and the
    legacy row must not be described as ungated either, so it says nothing.
    """
    assert "cannot exceed" not in render_report(_gated([]))
    legacy = _gated([])
    del legacy["score"]["gated_by"]
    assert "cannot exceed" not in render_report(legacy)


# --- joining the bars to the table ------------------------------------------

def test_a_finding_names_the_bar_it_scored_in():
    """The page draws six category bars and a table, and nothing joined them.

    Audit fb00b177 published Security 9.0 above a table holding predictable
    hardcoded passwords for a hundred accounts, an SSRF and a service-role key
    used to derive user passwords. Both halves can be right -- findings are
    filed by what they are, not by which rubric found them -- but the reader
    was given no way to establish that. The score is checkable arithmetic,
    10.0 - sum(weight x confidence), and the one input it needs was the one
    thing the page did not print.
    """
    f = {**_finding(), "category": "Auth"}

    # Anchored to the row, not to the page: "Auth" is the name of a bar too,
    # so a bare substring check passes on a report that prints nothing here.
    assert '<div class="tech">Auth · ' in render_report(result([f]))


def test_a_moved_finding_says_where_it_came_from():
    """The question the bars raise most often: a category can read a perfect
    10.0 for the precise reason that everything it found now scores next
    door."""
    f = {**_finding(), "category": "Security", "origin_category": "Auth"}

    assert "Security (moved from Auth)" in render_report(result([f]))


def test_an_unmoved_finding_says_nothing_about_moving():
    f = {**_finding(), "category": "Security", "origin_category": "Security"}

    assert "moved from" not in render_report(result([f]))


def test_a_finding_with_no_category_renders_without_one():
    """Static rules predating the field, and stored rows written before it."""
    html = render_report(result([_finding()]))

    assert "AWS key in code" in html and "moved from" not in html


def test_a_hostile_category_is_escaped():
    """`category` is model-authored on every LLM finding."""
    f = {**_finding(), "category": "<script>alert(1)</script>"}

    assert "<script>alert(1)</script>" not in render_report(result([f]))


def test_a_capped_free_scan_names_nothing_it_did_not_publish():
    """The counterpart of the test above, on the case that reads worst.

    A committed .env is a static rule, so a lone critical capping a free scan
    is the common case rather than the exotic one -- which is exactly why the
    paragraph must not print here. The finding is in the table, at its own
    severity, where a free scan is entitled to put it. What the free page
    cannot do is explain the effect of that finding on a number it withheld.
    """
    html = render_report(_gated(
        [{"kind": "critical", "category": "Security",
          "rule_id": "env-file-committed", "title": "Committed .env file"}],
        basis="static_only"))
    assert "cannot exceed" not in html


def test_a_stored_row_predating_the_key_still_marks_auth_unchecked():
    """The dangerous edge of publishing the free tier's score.

    Rows written before the scorer recorded `unexamined` arrive without it.
    Treating absent as "everything was examined" would draw Auth as a full
    10.0 bar on every cached free audit -- the exact claim (issue #181) that
    keeping the score hidden used to prevent. The basis is enough to work it
    out, and it is worked out from the same constant compute_scores uses.
    """
    r = result([_finding()])
    r["score"]["basis"] = "static_only"
    r["score"].pop("unexamined", None)
    r["score"]["categories"] = {"Security": 5.0, "Auth": 10.0,
                                "Testing": 9.6, "Deploy": 9.8}
    html = render_report(r)

    auth_row = next(row for row in html.split('<div class="cat">')
                    if row.startswith('<span class="cat-name">Auth</span>'))
    assert "not checked" in auth_row
    assert "10.0" not in auth_row


def test_a_full_audit_never_marks_anything_unchecked():
    """The backfill keys on the basis, so it must not reach a paid audit --
    every category there really was examined."""
    r = result([_finding()])
    r["score"]["basis"] = "static+llm"
    r["score"].pop("unexamined", None)
    html = render_report(r)

    assert "not checked" not in html


def test_a_category_that_exported_its_findings_draws_no_bar():
    """Auth read 10.0 as a full green bar on a repository whose endpoint runs
    shell commands with no login check — because the model correctly filed
    that as Security, leaving Auth holding nothing.

    The row must say where the findings went. "not checked" would be a second
    falsehood: the rubric ran, and it found something.
    """
    row = _gated([])
    row["score"]["reported_elsewhere"] = {"Auth": ["Security"]}
    html = render_report(row)

    assert "reported under Security" in html
    # The number and its bar are what lied; both must be gone for this row.
    assert ">10.0<" not in html.split("Auth")[1].split("</div></div>")[0]
    # And it must not be described as unexamined.
    assert "not checked" not in html


def test_the_two_blanked_rows_do_not_borrow_each_others_wording():
    """`unexamined` and `reported_elsewhere` both blank a number, for opposite
    reasons. A report that renders them alike tells the reader the wrong thing
    in one of the two cases, and the wrong thing is the one that sends someone
    hunting for an audit that already happened."""
    row = _gated([], basis="static_only")
    # Both names must exist in `categories`, or no row is rendered for them
    # and the assertions below pass by measuring nothing.
    assert {"Testing", "Auth"} <= set(row["score"]["categories"])
    row["score"]["unexamined"] = ["Testing"]
    row["score"]["reported_elsewhere"] = {"Auth": ["Security"]}
    html = render_report(row)

    assert "not checked" in html
    assert "reported under Security" in html


def test_a_row_stored_before_the_key_existed_renders_unchanged():
    """Absent must read as "nothing was handed away" — the answer those rows
    already give — not as an error and not as a blanked row."""
    row = _gated([])
    assert "reported_elsewhere" not in row["score"]
    html = render_report(row)

    assert "reported under" not in html
    # Auth still draws its ordinary bar. Checked by the band it lands in
    # rather than by ">10.0<": categories publish a band now, because three
    # runs of one repository on one revision swung Security by 1.3 and a
    # decimal place claims a precision of 0.05.
    assert "nothing serious found" in html


# --- a category publishes a band, because a number is more than we measured ---
#
# Three audits of Avisafety-1/blank-slate, one revision, one model, and input
# identical to the byte (prompt_chars 4,161,116 and input_tokens 1,463,735 on
# all three):
#
#     Security       3.1   1.8   2.2      swing 1.3
#     Money & Data   0.0   0.3   1.1      swing 1.1
#     Auth           6.9   7.5   6.8      swing 0.7
#     total          4.1   4.0   4.1      swing 0.1
#
# A decimal place claims +/-0.05. The categories carry +/-1.3, so the decimal
# is a precision claim the engine cannot support. The TOTAL can: the static
# categories are constant and damp it.


def _scored(value: float) -> str:
    row = result([_finding()])
    row["score"]["basis"] = "static+llm"
    row["score"]["categories"] = {"Security": value}
    return render_report(row)


def test_a_category_says_which_band_it_is_in():
    assert "serious problems" in _scored(2.2)
    assert "problems found" in _scored(5.0)
    assert "nothing serious found" in _scored(8.0)


def test_the_band_does_not_move_with_the_measured_swing():
    """The point of the change in one assertion. Security read 3.1, 1.8 and
    2.2 across three runs of the same bytes; all three must say the same
    thing, or the coarsening has bought nothing."""
    assert len({_band_text(v) for v in (3.1, 1.8, 2.2)}) == 1


def _band_text(value: float) -> str:
    from app.report.html import _band
    return _band(value)[0]


def test_the_boundary_is_the_one_the_scorer_already_acts_on():
    """GATE_THRESHOLD, not a number chosen for looks: below it the scorer
    treats a safety category as failing and caps the total."""
    from app.scan.scoring import GATE_THRESHOLD

    assert _band_text(GATE_THRESHOLD) == "nothing serious found"
    assert _band_text(GATE_THRESHOLD - 0.1) != "nothing serious found"


def test_the_bar_width_does_not_republish_the_number():
    """A proportional fill would state the exact value in pixels -- the same
    claim, made where nobody thought to look for it.

    Read out of the RENDERED page, not out of _band: the helper returning one
    width for a band proves nothing about the renderer using it, and the
    mutation that made the fill proportional again left this green while it
    asked _band directly."""
    widths = {_rendered_width(v) for v in (1.0, 2.2, 3.4)}

    assert len(widths) == 1, widths


def _rendered_width(value: float) -> str:
    match = re.search(r'class="fill" style="width:(\d+)%', _scored(value))
    assert match, "no category bar was drawn"
    return match.group(1)


def test_the_bar_colour_does_not_republish_the_number():
    """The third channel, and the one that shipped broken.

    Text and width snapped to the band; the colour kept _score_color, whose
    boundaries are 8 and 5 where the bands' are 7.0 and 3.5. On a real report
    (audit b504326) Security 5.3 drew yellow and Money & Data 3.9 drew red
    under identical text and identical width -- the reader can see the two
    rows differ and the page never says by what.

    Rendered page again, for the reason above _rendered_width: asking _band
    for a colour would leave the renderer free to ignore it.
    """
    same_band = {_rendered_colour(v) for v in (3.6, 5.3, 6.9)}
    assert len(same_band) == 1, same_band

    # ...and the bands are still told apart, or one flat colour would pass.
    assert len({_rendered_colour(v) for v in (2.2, 5.3, 8.0)}) == 3


def _rendered_colour(value: float) -> str:
    match = re.search(r'class="fill" style="width:\d+%;background:(#\w+)',
                      _scored(value))
    assert match, "no category bar was drawn"
    return match.group(1)


def test_the_total_keeps_its_number():
    """Coarsening the headline too would throw away precision the engine does
    have: the same three runs moved it 4.1 / 4.0 / 4.1."""
    row = result([_finding()])
    row["score"]["basis"] = "static+llm"

    assert ">6.4<" in render_report(row)


# --- the free tier publishes findings, not numbers ---------------------------
#
# Two browser tabs on the same repository made this visible. The paid report
# found an SSRF, a service-role key used as an HMAC secret, hardcoded bot
# credentials and a rate limiter that fails open; the free report on the same
# code drew Security as a full green 10.0 bar and reported one low finding.
# The prose disclaimer was honest and nobody reads prose next to a green bar.


def _preview(categories: dict | None = None) -> dict:
    return {
        "stack": "nextjs",
        "score": {
            "total": 9.9, "basis": "static+preview",
            "categories": categories or {
                "Security": 10.0, "Auth": 10.0, "Testing": 10.0,
                "Deploy": 9.9, "Money & Data": 10.0, "Frontend": 10.0},
            "unexamined": ["Auth", "Money & Data", "Frontend"],
            "gated_by": [],
        },
        "findings": [_finding()],
    }


def test_a_preview_publishes_no_mark_out_of_ten():
    html = render_report(_preview())

    assert "Free scan" in html
    assert "does not produce a mark out of ten" in html
    # The headline number must be absent, not merely small. 9.9 is what this
    # repository scored on the free tier while its paid audit read 4.7.
    assert ">9.9<" not in html


def test_a_preview_marks_what_it_looked_at_as_partly_checked():
    """Neither a number nor "not checked".

    Security WAS examined -- by regexes and one rubric on the cheapest model --
    so calling it unchecked is false. But a 10.0 renders identically to a 10.0
    a full audit produced, and the visitor cannot tell which they are reading.
    """
    html = render_report(_preview())

    assert "partly checked" in html
    assert "not checked" in html          # Auth / Money & Data / Frontend
    # No category number survives anywhere on a free report.
    for value in ("10.0", "9.9"):
        assert f'class="cat-val">{value}<' not in html


def test_a_preview_says_it_ran_a_security_review_and_static_only_does_not():
    """The two free depths are different scans and must not share a claim.

    A static-only result reached no model at all -- the spend cap, or a
    provider failure. Printing the preview's wider scope over it would
    overstate the thinnest audit the product produces.
    """
    preview = render_report(_preview())
    row = _preview()
    row["score"]["basis"] = "static_only"
    static_only = render_report(row)

    assert "one quick security review" in preview
    assert "one quick security review" not in static_only
    assert "does not produce a mark out of ten" in static_only


def test_a_paid_audit_publishes_a_band_and_keeps_its_headline():
    """This test used to say a paid report is the one place a category number
    is earned. It is not, and the measurement is why.

    Three audits of Avisafety-1/blank-slate on one revision, one model and
    byte-identical input swung Security 3.1 / 1.8 / 2.2 and Money & Data
    0.0 / 0.3 / 1.1. A decimal place on a category claims a precision of
    0.05 against a measurement carrying 1.3 -- so the category publishes the
    band it lands in.

    The TOTAL keeps its number: the same three runs moved it 4.1 / 4.0 / 4.1,
    because the static categories are constant and damp it. Coarsening it too
    would throw away precision the engine does have."""
    row = _preview()
    row["score"]["basis"] = "static+llm"
    row["score"]["unexamined"] = []
    html = render_report(row)

    assert "partly checked" not in html
    assert 'class="cat-val cat-band">nothing serious found<' in html
    assert 'class="cat-val">9.9<' not in html
    assert ">9.9<" in html   # ...and the headline ring keeps its number
