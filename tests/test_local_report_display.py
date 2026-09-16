"""The short terminal view must surface late findings without changing evidence."""
from copy import deepcopy
import json

from app import local_cli as cli


def report_with(findings):
    return {
        "findings": findings,
        "checks_not_run": [],
        "can_continue": False,
        "changes": {"baseline": True, "new": [str(n) for n in range(len(findings))]},
        "catalog": {"sha256": "a" * 64, "stale": False, "age_days": {"cvelist": 1}},
        "snapshot": {"excluded": {}},
        "dependency_cve": {"status": "partial", "status_counts": {"affected": 1},
                           "incomplete_manifests": {}},
        "limitations": ["static_source_only"],
    }


def finding(rule, severity, context=None):
    return {"rule_id": rule, "severity": severity, "context": context,
            "file": "source.py", "line": 1, "title": rule}


def test_late_dependency_finding_reaches_short_view_without_altering_report(capsys):
    findings = [finding(f"example-{n}", "low", "doc_example") for n in range(25)]
    findings += [finding("test-secret", "medium", "test_file"),
                 finding("production-secret", "medium"),
                 finding("dependency-cve-match", "high"),
                 finding("test-critical", "critical", "test_file")]
    report = report_with(findings)
    original = deepcopy(report)
    identities = [cli._identity(row) for row in findings]
    cli.display(report, False)
    text = capsys.readouterr().out
    rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"severity"')]
    assert [row["rule_id"] for row in rows[:4]] == [
        "test-critical", "dependency-cve-match", "production-secret", "test-secret"]
    assert len(rows) == 20
    assert "29 findings; baseline recorded" in text
    assert "29 newly reported" not in text
    assert '"low": 25' in text
    assert "Showing 20 findings by severity" in text
    assert report == original
    assert [cli._identity(row) for row in report["findings"]] == identities
    assert cli.exit_status(report, "high") == 1
    cli.display(report, True)
    assert json.loads(capsys.readouterr().out) == original


def test_equal_priority_keeps_order_and_terminal_controls_are_escaped(capsys):
    report = report_with([finding("first", "high"), finding("second", "high")])
    report["findings"][0]["file"] = "evil\x1b[2J\npath.py"
    report["changes"].update(baseline=False, new=[])
    cli.display(report, False)
    text = capsys.readouterr().out
    assert "0 newly reported" in text
    assert "\x1b" not in text
    rows = [json.loads(line) for line in text.splitlines() if line.startswith('{"severity"')]
    assert [row["rule_id"] for row in rows] == ["first", "second"]
    assert rows[0]["file"] == report["findings"][0]["file"]


def test_partial_coverage_explains_unknowns_dynamic_metadata_and_exclusions(capsys):
    report = report_with([])
    report["dependency_cve"].update(
        status_counts={"affected": 0, "unaffected": 255, "unknown": 10, "not_in_catalog": 319},
        unknown_reason_counts={"conflicting_advisory_sources": 7, "unsupported_version": 3},
        details=[{"package": "npm:undici", "version": "8.10.2", "manifest": "web/package-lock.json",
                  "advisory": f"CVE-2026-{10000 + n}", "reason": "conflicting_advisory_sources"}
                 for n in range(7)],
        details_truncated=3,
        incomplete_manifests={"local/pyproject.toml": "unresolved"},
        manifest_gap_details=[{"manifest": "local/pyproject.toml", "status": "unresolved",
                               "reason": "dynamic_dependencies_without_lock"}],
        excluded_manifests={"web/.next/package.json": "generated_next_build"},
    )
    cli.display(report, False)
    text = capsys.readouterr().out
    assert '"unknown": 10' in text
    assert '"conflicting_advisory_sources": 7' in text
    assert text.count("Unknown dependency: ") == 5
    assert "5 additional unknown assessments not shown" in text
    assert "dynamic_dependencies_without_lock" in text
    assert "generated_next_build" in text
    assert "not confirmed affected or unaffected" in text
    assert cli.exit_status(report, "none") == 2
