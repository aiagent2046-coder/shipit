"""Tests for the HTML report. The escaping tests matter most: file
names and titles come from a hostile archive and from the LLM.
"""

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
    assert "Security 5.9" in html


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


def test_a_capped_free_scan_explains_the_cap_too():
    """The cap note used to be suppressed on a static-only audit, because
    there was no headline to explain. There is one now, and the free tier is
    where a lone critical most often caps it -- a committed .env is a static
    rule, so this is the common case, not the exotic one.
    """
    html = render_report(_gated(
        [{"kind": "critical", "category": "Security",
          "rule_id": "env-file-committed", "title": "Committed .env file"}],
        basis="static_only"))
    assert "cannot exceed" in html
    assert "Committed .env file" in html


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
    assert ">10.0<" in html  # Auth still draws its ordinary bar
