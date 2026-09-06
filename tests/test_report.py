"""Tests for the HTML report. The escaping tests matter most: file
names and titles come from a hostile archive and from the LLM.
"""

import pytest

from app.report.html import NON_PRODUCTION_HEADING, render_report


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


def test_report_contains_stack_and_findings_without_score():
    html = render_report(result([{
        "severity": "critical", "confidence": 0.9,
        "title": "AWS key in code", "file": "src/config.ts", "line": 3,
        "masked": "AKIA****(20 chars)",
    }]), project_name="demo")
    assert ">6.4<" not in html
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
        assert "Potential critical impact" in r.text
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


_CI_SERVICE = {
    "severity": "medium", "confidence": 0.18,
    "title": "Password in a connection string to a local/development host "
             "(CI service container)",
    "file": ".github/workflows/playwright.yaml", "line": 27,
    "masked": "post****(45 chars)", "context": "ci_service",
}


def test_every_damping_context_reaches_the_same_section():
    """The section is defined by NON_PRODUCTION_CONTEXTS, so a context added
    to that set and not to the renderer's understanding would leave a damped
    finding sitting in the main table -- damped where nobody looks and loud
    where everybody does."""
    from app.scan.secrets import NON_PRODUCTION_CONTEXTS

    for context in NON_PRODUCTION_CONTEXTS:
        html = render_report(result([dict(_TEST_FILE, context=context)]))
        head, _, section = html.partition(NON_PRODUCTION_HEADING)
        assert section, context
        assert "tests/test_secrets.py" in section, context


def test_the_section_does_not_tell_the_reader_these_files_never_run():
    """A CI workflow runs. Measured on dubinc/dub (audit `caa1b36b`):
    `.github/workflows/playwright.yaml` landed under a note reading "These
    files don't run in production", which is simply untrue of a workflow --
    the same defect as the advice this context was introduced to fix, one
    level up. What is true of every row here, and what the reassurance
    underneath actually rests on, is that none of it serves the reader's
    users."""
    from app.report.html import NON_PRODUCTION_NOTE

    html = render_report(result([_PROD, _CI_SERVICE]))
    _, _, section = html.partition(NON_PRODUCTION_HEADING)

    assert ".github/workflows/playwright.yaml" in section
    assert "run in production" not in NON_PRODUCTION_NOTE
    # ...and the reassurance the section exists to give is still given.
    assert "A real secret still requires action" in NON_PRODUCTION_NOTE


def test_test_findings_go_under_their_own_heading():
    html = render_report(result([_PROD, _TEST_FILE]))
    assert NON_PRODUCTION_HEADING in html
    # Both are present; the production one comes first.
    assert html.index("src/config.ts") < html.index("tests/test_secrets.py")
    assert html.index(NON_PRODUCTION_HEADING) < html.index(
        "tests/test_secrets.py")


def test_no_heading_when_everything_is_production_code():
    html = render_report(result([_PROD]))
    assert NON_PRODUCTION_HEADING not in html


def test_clean_production_code_is_said_out_loud():
    """The case this whole split exists for: nothing wrong with the running
    app, findings only in fixtures. Silence there reads as "we found problems"
    when the truth is the opposite."""
    html = render_report(result([_TEST_FILE]))
    assert "No findings outside the test and example section." in html
    assert NON_PRODUCTION_HEADING in html
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
    assert "No findings outside the test and example section." in html
    assert NON_PRODUCTION_HEADING in html


def test_migration_findings_stay_in_the_production_section():
    """A migration is applied state. `examples/migrations/` must not slip into
    the non-production section on the strength of its first path segment."""
    html = render_report(result([{
        "severity": "critical", "confidence": 0.95,
        "title": "Hardcoded secret in SQL/PLpgSQL assignment (committed database migration)",
        "file": "examples/migrations/0007_seed.sql", "line": 4,
    }]))
    assert NON_PRODUCTION_HEADING not in html


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


@pytest.mark.parametrize("basis", [None, "static_only", "static+preview", "static+llm", "static+partial"])
def test_every_tier_and_legacy_audit_withholds_unvalidated_scores(basis):
    row = result([dict(_finding(), rule_id="llm-auth", confidence=1.0)])
    row["score"].update(basis=basis, gated_by=[{
        "kind": "critical", "title": "Unverified model claim", "category": "Auth",
    }])
    html = render_report(row)
    assert 'class="ring"' not in html
    assert ">6.4<" not in html
    assert "Production Readiness Score" not in html
    assert "cannot exceed" not in html
    assert "nothing serious found" not in html
    assert "So a finding here is real" not in html
    assert "Model hypothesis — unverified" in html
    assert "Potential critical impact" in html
    assert "No readiness score out of 10" in html
    assert "Limits of this audit" in html


@pytest.mark.parametrize("source,rule,label", [
    ("static", "aws-access-key-id", "Static signal — unverified"),
    ("llm", "llm-auth", "Model hypothesis — unverified"),
    (None, "llm-auth", "Model hypothesis — unverified"),
    (None, "aws-access-key-id", "Legacy finding — verification not recorded"),
])
def test_producer_confidence_never_becomes_confirmation(source, rule, label):
    f = dict(_finding(), source=source, rule_id=rule, confidence=1.0)
    assert label in render_report(result([f]))


def test_coverage_distinguishes_skipped_partial_and_legacy():
    from app.report.evidence import coverage_rows

    f = dict(_finding(), category="Auth")
    score = {"basis": "static_only", "categories": {}}
    rows = dict(coverage_rows(score, [f]))
    assert rows["Auth"] == "Not surveyed — see findings · 1 unverified finding"
    assert rows["Money & Data"] == "Not checked"
    assert rows["Security"] == "Partly checked"
    assert dict(coverage_rows({"categories": {}}, []))["Auth"] == "Coverage not recorded"


def test_zero_findings_is_not_a_safety_verdict():
    html = render_report(result([]))
    assert "Absence of a finding does not establish safety" in html
    assert "have not been verified here" in html


def test_finding_count_is_not_changed_by_display_grouping():
    from app.scan.rls import RULE_ID

    f = dict(_finding(), rule_id=RULE_ID)
    # Count both records even though the table combines them into one row.
    html = render_report(result([f, dict(f, file="second.sql")]))
    assert '<div class="noring">2<small>source observations</small>' in html
    assert html.count('class="title"') == 1
