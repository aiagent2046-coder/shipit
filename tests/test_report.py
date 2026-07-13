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

    class FakeRepo:
        async def get(self, audit_id):
            if audit_id != "known-id":
                return None
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

    main_mod.app.dependency_overrides[main_mod.get_audit_repo] = lambda: FakeRepo()
    try:
        client = TestClient(main_mod.app)
        r = client.get("/v1/audits/known-id/report")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "Fix before launch" in r.text
        assert client.get("/v1/audits/unknown/report").status_code == 404
    finally:
        main_mod.app.dependency_overrides.pop(main_mod.get_audit_repo, None)
