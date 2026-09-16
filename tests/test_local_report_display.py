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
    assert [row["rule_id"] for row in rows] == [
        "test-critical", "dependency-cve-match", "production-secret"]
    assert rows[-1]["context"] == "unknown"
    assert "29 findings; baseline recorded" in text
    assert "29 newly reported" not in text
    assert '"low": 25' in text
    assert '"findings": 26' in text
    assert "--show-contextual" in text
    assert report == original
    assert [cli._identity(row) for row in report["findings"]] == identities
    assert cli.exit_status(report, "high") == 1
    cli.display(report, True)
    assert json.loads(capsys.readouterr().out) == original


def dependency(advisory, *, package="sample", version="1.0.0", manifest="package-lock.json",
               ecosystem="npm", scope="development"):
    row = finding("dependency-cve-match", "high")
    row["title"] = "Deliberately identical titles"
    row["claim_evidence"] = {
        "ecosystem": ecosystem, "package": package, "installed_version": version, "manifest": manifest,
        "advisory_id": advisory, "advisory_ids": [advisory],
        "url": f"https://example.invalid/advisories/{advisory}",
        "dependency_scope": scope, "direct": False, "dependency_groups": ["test"],
        "matched_ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
    }
    return row


def terminal_rows(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith('{"severity"')]


def test_dependency_tasks_group_by_identity_not_title_and_preserve_all_evidence(capsys):
    findings = [dependency("CVE-2026-1000"), dependency("GHSA-aaaa-bbbb-cccc"),
                dependency("CVE-2026-1000", package="another"),
                dependency("CVE-2026-1000", version="1.0.1"),
                dependency("CVE-2026-1000", manifest="web/package-lock.json"),
                dependency("CVE-2026-1000", ecosystem="PyPI")]
    report = report_with(findings)
    original = deepcopy(report)
    identities = [cli._identity(row) for row in findings]
    cli.display(report, False)
    text = capsys.readouterr().out
    tasks = terminal_rows(text)
    assert len(tasks) == 5
    group = tasks[0]
    assert group["advisory_findings"] == 2
    assert group["advisory_ids"] == ["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"]
    assert group["dependency_scope"] == "development"
    assert group["direct"] is False
    assert group["dependency_groups"] == ["test"]
    assert group["advisories"][0]["url"].endswith("CVE-2026-1000")
    assert group["advisories"][0]["matched_ranges"][0]["events"][-1] == {"fixed": "2.0.0"}
    assert "not a safe version for all" in group["action"]
    assert "builds and CI" in group["action"]
    assert report == original
    assert [cli._identity(row) for row in findings] == identities
    assert cli.exit_status(report, "high") == 1
    cli.display(report, True, show_contextual=True)
    assert json.loads(capsys.readouterr().out) == original


def test_unknown_and_mixed_dependency_scopes_never_become_runtime(capsys):
    report = report_with([dependency("CVE-2026-1000", scope="runtime"),
                          dependency("CVE-2026-1001", scope="development"),
                          dependency("CVE-2026-1002", package="other", scope="unexpected")])
    cli.display(report, False)
    assert [row["dependency_scope"] for row in terminal_rows(capsys.readouterr().out)] == ["unknown", "unknown"]


def test_cna_source_bounds_and_status_changes_do_not_become_a_fix_promise(capsys):
    row = dependency("CVE-2026-1000")
    evidence = row["claim_evidence"]
    evidence["matched_ranges"] = [{
        "version": "1.0.0", "lessThanOrEqual": "3.0.0", "versionType": "semver", "status": "unaffected",
        "changes": [{"at": "1.5.0", "status": "affected"}, {"at": "2.0.0", "status": "unaffected"}],
    }]
    evidence["installed_version"] = "1.5.0"
    cli.display(report_with([row]), False)
    task = terminal_rows(capsys.readouterr().out)[0]
    assert task["advisories"][0]["matched_ranges"] == evidence["matched_ranges"]
    assert "safe version for all" in task["action"]


def test_contextual_expansion_keeps_urgent_secrets_visible_and_gates_unchanged(capsys):
    report = report_with([finding("example-token", "medium", "doc_example"),
                          finding("test-token", "high", "test_file"),
                          finding("private-key", "critical", "test_file"),
                          finding("no-dockerfile", "low"), finding("actual-check", "low")])
    original = deepcopy(report)
    cli.display(report, False)
    rows = terminal_rows(capsys.readouterr().out)
    assert [row["rule_id"] for row in rows] == ["private-key", "test-token", "actual-check"]
    cli.display(report, False, show_contextual=True)
    rows = terminal_rows(capsys.readouterr().out)
    assert {row["rule_id"] for row in rows} == {row["rule_id"] for row in report["findings"]}
    assert report == original
    assert cli.exit_status(report, "medium") == 1
    assert cli.exit_status(report, "none") == 0


def test_actionable_static_findings_have_short_advice_and_escaped_content(capsys):
    row = finding("custom-check", "high")
    row.update(explanation="Why\x1b[2J\n" + "x" * 500, fix_hint="Inspect\r\n\x1b[2J file")
    report = report_with([row])
    cli.display(report, False)
    text = capsys.readouterr().out
    result = terminal_rows(text)[0]
    assert "\x1b" not in text and "\r" not in text
    assert result["explanation"].endswith("[see --json]")
    assert result["action"] == row["fix_hint"]


def test_grouped_project_content_is_escaped_and_large_groups_are_bounded(capsys):
    findings = [dependency(f"CVE-2026-{1000 + n}") for n in range(30)]
    bad = "evil\x1b[2J\n"
    for row in findings:
        evidence = row["claim_evidence"]
        evidence.update(package=bad, manifest=bad, installed_version=bad,
                        url=bad, dependency_groups=[bad])
        evidence["matched_ranges"] = [{"type": bad, "events": [{"fixed": bad} for _ in range(12)]}] * 10
    report = report_with(findings)
    original = deepcopy(report)
    cli.display(report, False)
    text = capsys.readouterr().out
    assert "\x1b" not in text
    task = terminal_rows(text)[0]
    assert task["advisory_findings"] == 30
    assert len(task["advisory_ids"]) == 8 and task["additional_advisory_ids"] == 22
    assert len(task["advisories"]) == 5 and task["additional_advisory_details"] == 25
    assert task["advisories"][0]["additional_ranges"] == 8
    assert task["advisories"][0]["matched_ranges"][0]["additional_events"] == 6
    assert report == original


def test_incomplete_source_explanation_keeps_raw_reason_and_assessments(capsys):
    report = report_with([])
    report["dependency_cve"].update(
        unknown_reason_counts={"incomplete_advisory_sources": 1},
        details=[{"package": "npm:sample", "reason": "incomplete_advisory_sources", "assessments": [
            {"source": "cvelist", "status": "unknown", "reason": "unsupported_version"},
            {"source": "github-reviewed", "status": "unaffected", "reason": None}]}],
    )
    original = deepcopy(report)
    cli.display(report, False)
    text = capsys.readouterr().out
    assert '"incomplete_advisory_sources": 1' in text
    assert "not an affected/unaffected disagreement" in text
    assert report == original
    assert cli.exit_status(report, "none") == 0
    cli.display(report, True)
    assert json.loads(capsys.readouterr().out) == original


def test_show_contextual_cli_flag_is_wired_without_changing_json_or_exit(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    report = report_with([finding("test-medium", "medium", "test_file")])
    monkeypatch.setattr(cli, "poll_project", lambda *args: ((), report))
    args = ["--state-dir", str(tmp_path / "state"), "scan", str(project), "--show-contextual"]
    assert cli.main([*args, "--fail-on", "medium"]) == 1
    assert terminal_rows(capsys.readouterr().out)[0]["rule_id"] == "test-medium"
    assert cli.main([*args, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == report


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
