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
