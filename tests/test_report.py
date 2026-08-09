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


def test_static_only_report_carries_no_readiness_score():
    """A free static scan must not publish a number.

    The score RISES when fewer checks run, because the findings that would lower
    it were never looked for: 7.2 with the auth and injection rubrics on audit
    ed402e63, 9.1 without them, Auth reading 10.0 for a repo whose subscriptions
    table has no write RLS policies. A static-only report carrying a score would
    be reassurance pointing the wrong way.
    """
    r = result([_finding()])
    r["score"]["basis"] = "static_only"
    html = render_report(r)

    assert "6.4" not in html                    # the total, gone everywhere
    assert 'class="ring"' not in html           # and its circle
    assert "Static scan" in html
    assert "no readiness score" in html
    # Category bars are part of the score and go with it.
    assert "Correctness" not in html
    # og:title must not leak the number into a link preview either.
    og = next(line for line in html.split("\n") if "og:title" in line)
    assert "6.4" not in og and "/10" not in og


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
    assert "capped" in html
    assert "Committed .env file" in html


def test_capped_score_names_the_failing_category():
    html = render_report(_gated([
        {"kind": "subscore", "category": "Security", "value": 5.9},
    ]))
    assert "Security 5.9" in html


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
    assert "capped" not in render_report(_gated([]))
    legacy = _gated([])
    del legacy["score"]["gated_by"]
    assert "capped" not in render_report(legacy)


def test_static_only_report_prints_no_cap_note():
    """A static-only audit publishes no score at all, so there is no headline
    for a cap note to explain -- printing one would reintroduce the number the
    free tier deliberately withholds."""
    html = render_report(_gated(
        [{"kind": "critical", "category": "Security",
          "rule_id": "env-file-committed", "title": "Committed .env file"}],
        basis="static_only"))
    assert "capped" not in html
