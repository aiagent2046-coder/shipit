"""SQL coverage survives product boundaries without erasing independent findings."""

from html import escape
import io
import json
import stat
import zipfile

import pytest

from app import local_cli
from app.report.evidence import RULE_COVERAGE_LABELS, manifest_rows, non_model_status_notices
from app.report.html import render_report
from app.scan import sql_injection, sql_injection_js
from app.scan.browser import ScanSession, scan_archive
from app.scan.manifest import scan_manifest


RULE_ID = "sql-injection-string-built-query"
PYTHON_QUERY = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
TYPESCRIPT_QUERY = 'db.query("SELECT * FROM users WHERE id = " + userId);\n'
CASES = [
    pytest.param("sql_injection", "py", PYTHON_QUERY,
                 "value = 0\n", "value = [\n", sql_injection, id="python"),
    pytest.param("sql_injection_js", "ts", TYPESCRIPT_QUERY,
                 "const value = 0;\n", "const value = [;\n", sql_injection_js, id="typescript"),
]


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
        for name, source in files:
            z.writestr(name, source)
    return output.getvalue()


def sql_findings(report):
    return [finding for finding in report["findings"] if finding["rule_id"] == RULE_ID]


def test_sql_exclusions_and_real_findings_survive_report_boundaries():
    files = []
    for suffix, positive in (("py", PYTHON_QUERY), ("ts", TYPESCRIPT_QUERY)):
        link = zipfile.ZipInfo(f"links/query.{suffix}")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        files.extend([
            (link, f"../src/positive.{suffix}"),
            (f".git/hooks/query.{suffix}", positive * 32),
            (f"src/positive.{suffix}", positive),
        ])
    data = archive(files)
    result = json.loads(json.dumps(scan_archive(data)))
    report = result["report"]
    findings = sql_findings(report)
    assert {(finding["file"], finding["line"]) for finding in findings} == {
        ("src/positive.py", 1), ("src/positive.ts", 1),
    }
    assert len(findings) == 2
    assert all(finding["verification_status"] == "unverified" for finding in findings)
    record = {
        "version": 1,
        "files_total": 6,
        "eligible_files": 1,
        "attempted_files": 1,
        "analyzed_files": 1,
        "excluded_files": 5,
        "skipped_files": 0,
        "exclusion_reasons": {"unsupported_extension": 1, "symlink": 2, "git_metadata": 2},
        "skip_reasons": {},
        "partial": False,
    }
    manifest = scan_manifest(data, "test", report, None, None)
    score = {"basis": "static_only", "categories": {}, "scan_manifest": manifest}
    rows = dict(manifest_rows(score))
    html = render_report({"score": score, "findings": report["findings"]})
    invocation = result["sarif"]["runs"][0]["invocations"][0]
    for check in ("sql_injection", "sql_injection_js"):
        assert report["rule_coverage"][check] == record
        assert manifest["rule_coverage"][check] == record
        assert invocation["properties"]["ruleCoverage"][check] == record
        label = RULE_COVERAGE_LABELS[check]
        assert rows[f"Files excluded: {label}"] == (
            "unsupported file types: 1, symbolic links: 2, Git metadata: 2"
        )
        assert rows[f"Files not fully analyzed: {label}"] == "None recorded"
        assert escape(rows[f"File coverage: {label}"]) in html
        assert escape(rows[f"Files excluded: {label}"]) in html
        assert not any(title == "Static checks incomplete" and label in detail
                       for title, detail in non_model_status_notices(score))
    exported = [row for row in result["sarif"]["runs"][0]["results"] if row["ruleId"] == RULE_ID]
    assert len(exported) == 2
    assert {row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for row in exported} == {
        "src/positive.py", "src/positive.ts",
    }


@pytest.mark.parametrize("check,suffix,positive,harmless,malformed,module", CASES)
def test_sql_parse_gap_cannot_report_success_with_retained_positive(
    tmp_path, capsys, check, suffix, positive, harmless, malformed, module,
):
    project = tmp_path / "project"
    project.mkdir()
    (project / f"positive.{suffix}").write_text(positive)
    broken = project / f"broken.{suffix}"
    broken.write_text(malformed)
    state = tmp_path / "state"
    command = ["--state-dir", str(state), "scan", str(project), "--json"]

    status = local_cli.main(command)
    report = json.loads(capsys.readouterr().out)
    assert status == 2
    assert report["checks_not_run"] == []
    assert report["can_continue"] is False
    findings = sql_findings(report)
    assert [(f["file"], f["line"]) for f in findings] == [(f"positive.{suffix}", 1)]
    assert findings[0]["verification_status"] == "unverified"
    assert findings[0]["claim_evidence"]["conditions_status"] == "not_checked"
    assert report["rule_coverage"][check]["skip_reasons"] == {"parse_error": 1}
    assert report["rule_coverage"][check]["partial"] is True

    # Repairing only the unread source changes coverage, not the independent
    # SQL observation or its identity. History is a change summary, not an
    # archival copy of rule coverage, and must not invent a verified fix.
    broken.write_text(harmless)
    assert local_cli.main(command) == 0
    repaired = json.loads(capsys.readouterr().out)
    assert repaired["rule_coverage"][check]["partial"] is False
    assert repaired["rule_coverage"][check]["skip_reasons"] == {}
    assert sql_findings(repaired) == findings
    assert repaired["changes"]["same_engine_and_catalog"] is True
    assert repaired["changes"]["new"] == repaired["changes"]["no_longer_reported"] == []
    assert local_cli.main(["--state-dir", str(state), "history", str(project)]) == 0
    history = json.loads(capsys.readouterr().out)
    assert len(history) == 2
    assert history[0]["findings"] == history[1]["findings"] == len(report["findings"])
    assert "not proof of a fix" in history[0]["changes"]["note"]


@pytest.mark.parametrize("check,suffix,positive,harmless,malformed,module", CASES)
@pytest.mark.parametrize("reason,reason_label", [
    ("decode_error", "decoding errors"),
    ("file_size_limit", "file size limit"),
    ("finding_limit", "finding limit"),
    ("analysis_limit", "expression analysis limit"),
])
def test_sql_gaps_and_positive_evidence_reach_browser_json_sarif_and_html(
    monkeypatch, check, suffix, positive, harmless, malformed, module, reason, reason_label,
):
    if reason == "decode_error":
        source = b"\xff"
    elif reason == "file_size_limit":
        source = ("#" if suffix == "py" else "//") + "x" * 400_001
    elif reason == "finding_limit":
        source = positive * 33
    else:
        # A small real visitor budget exercises exhaustion without making the
        # product-boundary test depend on AST parser limits or huge fixtures.
        monkeypatch.setattr(module, "_MAX_NODES", 64)
        source = harmless * 100
    data = archive([(f"src/positive.{suffix}", positive), (f"src/limited.{suffix}", source)])
    result = scan_archive(data)
    report = result["report"]
    assert report["checks_not_run"] == []
    record = report["rule_coverage"][check]
    assert record["skip_reasons"] == {reason: 1}
    assert record["partial"] is True
    assert record["eligible_files"] == 2
    assert record["analyzed_files"] == 1
    assert any(f["file"] == f"src/positive.{suffix}" for f in sql_findings(report))
    assert all(f["verification_status"] == "unverified" for f in sql_findings(report))

    # JSON serialization must keep actual counts, and SARIF's scope
    # must agree with the report even though its execution flag is not a
    # completeness verdict for every source file.
    restored = json.loads(json.dumps(result))
    invocation = restored["sarif"]["runs"][0]["invocations"][0]
    assert invocation["properties"]["ruleCoverage"][check] == record
    exported = [row for row in restored["sarif"]["runs"][0]["results"] if row["ruleId"] == RULE_ID]
    assert len(exported) == len(sql_findings(report))
    assert any(row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
               == f"src/positive.{suffix}" for row in exported)

    manifest = scan_manifest(data, "test", report, None, None)
    score = {"basis": "static_only", "categories": {}, "scan_manifest": manifest}
    label = RULE_COVERAGE_LABELS[check]
    rows = dict(manifest_rows(score))
    assert rows[f"Files not fully analyzed: {label}"] == reason_label + ": 1"
    notices = non_model_status_notices(score)
    assert any(title == "Static checks incomplete" and f"{label}: 1 of 2 eligible files analyzed" in detail
               for title, detail in notices)
    html = render_report({"score": score, "findings": report["findings"]})
    assert escape(rows[f"File coverage: {label}"]) in html
    assert 'aria-label="Static checks incomplete"' in html


@pytest.mark.parametrize("full_suffix,tail_suffix,full_signal,tail_signal", [
    ("py", "ts", PYTHON_QUERY, TYPESCRIPT_QUERY),
    ("ts", "py", TYPESCRIPT_QUERY, PYTHON_QUERY),
])
@pytest.mark.parametrize("prior_tail_findings", [0, 31])
def test_sql_continuation_keeps_language_finding_budgets_independent(
    full_suffix, tail_suffix, full_signal, tail_signal, prior_tail_findings,
):
    tail_check = "sql_injection" if tail_suffix == "py" else "sql_injection_js"
    harmless = "pass\n" if tail_suffix == "py" else "export const value = true;\n"
    files = [(f"src/full.{full_suffix}", full_signal * 32)]
    if prior_tail_findings:
        files += [(f"src/first.{tail_suffix}", tail_signal * prior_tail_findings)]
    files += [(f"src/file_{number:03}.{tail_suffix}", harmless)
              for number in range(400 - bool(prior_tail_findings))]
    files += [(f"src/tail.{tail_suffix}", tail_signal * (2 if prior_tail_findings else 1))]
    session = ScanSession(archive(files))
    initial = session.result()
    assert len(sql_findings(initial["report"])) == 32 + prior_tail_findings
    assert initial["report"]["rule_coverage"][tail_check]["skip_reasons"] == {"file_limit": 1}
    assert initial["can_continue"] is True

    final = session.continue_scan()
    assert final["report"]["checks_not_run"] == []
    assert len(sql_findings(final["report"])) == 33 + prior_tail_findings
    assert sum(f["file"] == f"src/tail.{tail_suffix}" for f in sql_findings(final["report"])) == 1
    record = final["report"]["rule_coverage"][tail_check]
    assert record["attempted_files"] == 401
    assert record["analyzed_files"] == (400 if prior_tail_findings else 401)
    assert record["skip_reasons"] == ({"finding_limit": 1} if prior_tail_findings else {})
    assert record["partial"] is bool(prior_tail_findings)
    assert final["can_continue"] is False
    assert final["sarif"]["runs"][0]["invocations"][0]["properties"]["ruleCoverage"][tail_check] == record
    assert initial["report"]["rule_coverage"][tail_check]["skip_reasons"] == {"file_limit": 1}
    assert session.continue_scan() == final


@pytest.mark.parametrize("check,suffix,positive,harmless,malformed,module", CASES)
def test_cli_resumes_sql_file_limit_but_keeps_an_earlier_parse_gap(
    tmp_path, capsys, check, suffix, positive, harmless, malformed, module,
):
    project = tmp_path / "project"
    project.mkdir()
    (project / f"a_broken.{suffix}").write_text(malformed)
    for number in range(399):
        (project / f"file_{number:03}.{suffix}").write_text(harmless)
    (project / f"z_positive.{suffix}").write_text(positive)
    status = local_cli.main(["--state-dir", str(tmp_path / "state"), "scan", str(project), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert status == 2
    assert report["can_continue"] is False
    assert report["checks_not_run"] == []
    record = report["rule_coverage"][check]
    assert record["eligible_files"] == record["attempted_files"] == 401
    assert record["analyzed_files"] == 400
    assert record["skip_reasons"] == {"parse_error": 1}
    assert [(f["file"], f["line"]) for f in sql_findings(report)] == [(f"z_positive.{suffix}", 1)]
