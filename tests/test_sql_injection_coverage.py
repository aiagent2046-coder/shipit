"""Bounded SQL analysis must distinguish a completed check from a coverage gap."""

from __future__ import annotations

import io
import stat
import zipfile
import zlib

import pytest

from app.scan import sql_injection as python_sql
from app.scan import sql_injection_js as javascript_sql
from app.scan.rule_coverage import mark_analysis_limit, resume_rule, track_analysis_limits
from app.scan.static import run_static_scan


CASES = [
    pytest.param(python_sql, python_sql.scan_sql_injection, "py", id="python"),
    pytest.param(javascript_sql, javascript_sql.scan_sql_injection_js, "ts", id="typescript"),
]
UNSAFE = 'db.execute("SELECT * FROM users WHERE id = " + user_id)\n'
SAFE = 'db.execute("SELECT " + "1")\n'


def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        for name, source in files:
            zipped.writestr(name, source)
    return buffer


def symlink(name):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def assert_coverage(record, *, total, eligible, attempted, analyzed, exclusions=None, skips=None):
    exclusions, skips = exclusions or {}, skips or {}
    assert record == {
        "version": 1,
        "files_total": total,
        "eligible_files": eligible,
        "attempted_files": attempted,
        "analyzed_files": analyzed,
        "excluded_files": sum(exclusions.values()),
        "skipped_files": sum(skips.values()),
        "exclusion_reasons": exclusions,
        "skip_reasons": skips,
        "partial": bool(skips),
    }
    assert total == eligible + record["excluded_files"]
    assert eligible == analyzed + record["skipped_files"]
    assert analyzed <= attempted <= eligible


@pytest.mark.parametrize("module,scanner,extension", CASES)
@pytest.mark.parametrize("total", [400, 401])
def test_file_budget_inventories_unread_tail(module, scanner, extension, total):
    coverage = {}
    files = [(f"app/query_{index}.{extension}", SAFE) for index in range(total)]
    assert scanner(archive(files), coverage=coverage) == []
    assert_coverage(coverage, total=total, eligible=total, attempted=400, analyzed=400,
                    skips={"file_limit": total - 400} if total > 400 else {})


@pytest.mark.parametrize("module,scanner,extension", CASES)
@pytest.mark.parametrize("signals,tail", [(32, 0), (33, 0), (33, 2)])
def test_finding_cap_marks_only_truncated_files(module, scanner, extension, signals, tail):
    coverage = {}
    files = [(f"app/query.{extension}", UNSAFE * signals)]
    files += [(f"app/tail_{index}.{extension}", SAFE) for index in range(tail)]
    findings = scanner(archive(files), coverage=coverage)
    assert [finding.line for finding in findings] == list(range(1, 33))
    partial = signals > 32
    assert_coverage(coverage, total=1 + tail, eligible=1 + tail, attempted=1,
                    analyzed=0 if partial else 1,
                    skips={"finding_limit": tail + 1} if partial else {})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_finding_cap_is_shared_between_files(module, scanner, extension):
    coverage = {}
    findings = scanner(archive([(f"app/first.{extension}", UNSAFE * 31),
                                (f"app/second.{extension}", UNSAFE * 2)]), coverage=coverage)
    assert len(findings) == 32
    assert findings[-1].file == f"app/second.{extension}"
    assert findings[-1].line == 1
    assert_coverage(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"finding_limit": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_decode_parse_and_byte_size_gaps_keep_independent_findings(module, scanner, extension):
    malformed = "def invalid(:\n" if extension == "py" else "const invalid = [;\n"
    coverage = {}
    files = [
        (f"app/undecodable.{extension}", b"\xff"),
        (f"app/unparseable.{extension}", malformed),
        # Characters fit the old text limit; UTF-8 bytes exceed the real file cap.
        (f"app/oversized.{extension}", "#" + "ж" * 200_000),
        (f"app/query.{extension}", UNSAFE),
    ]
    findings = scanner(archive(files), coverage=coverage)
    assert [(finding.file, finding.line) for finding in findings] == [(f"app/query.{extension}", 1)]
    assert_coverage(coverage, total=4, eligible=4, attempted=3, analyzed=1,
                    skips={"decode_error": 1, "parse_error": 1, "file_size_limit": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
@pytest.mark.parametrize("error", [zipfile.BadZipFile("Invalid CRC"), zlib.error("Invalid compressed data")])
def test_read_failure_keeps_later_file_scannable(monkeypatch, module, scanner, extension, error):
    original = zipfile.ZipFile.read

    def read(zipped, member, *args, **kwargs):
        if isinstance(member, zipfile.ZipInfo) and member.filename == f"app/unreadable.{extension}":
            raise error
        return original(zipped, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", read)
    coverage = {}
    findings = scanner(archive([(f"app/unreadable.{extension}", UNSAFE),
                                (f"app/query.{extension}", UNSAFE)]), coverage=coverage)
    assert [finding.file for finding in findings] == [f"app/query.{extension}"]
    assert_coverage(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"read_error": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_excluded_files_do_not_consume_sql_budget_and_case_variants_remain_supported(module, scanner, extension):
    coverage = {}
    files = [(f"project/node_modules/pkg/query_{index}.{extension}", UNSAFE) for index in range(401)]
    files += [
        ("project/", ""),
        (f"project/tests/query.{extension}", UNSAFE),
        (f"project/dist/query.{extension}", UNSAFE),
        ("project/app/main.rs", "fn main() {}"),
        (f"project/app/query.{extension.upper()}", UNSAFE),
    ]
    findings = scanner(archive(files), coverage=coverage)
    assert len(findings) == 1
    assert findings[0].file == f"project/app/query.{extension.upper()}"
    assert_coverage(coverage, total=405, eligible=1, attempted=1, analyzed=1,
                    exclusions={"dependency_tree": 401, "non_production_path": 1,
                                "generated_build": 1, "unsupported_extension": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_symlinks_do_not_consume_sql_file_budget(module, scanner, extension):
    coverage = {}
    files = [(symlink(f"app/linked_{index}.{extension}"), f"../shared/query.{extension}")
             for index in range(400)]
    files.append((f"app/query.{extension}", UNSAFE))

    findings = scanner(archive(files), coverage=coverage)

    assert [(finding.file, finding.line) for finding in findings] == [(f"app/query.{extension}", 1)]
    assert_coverage(coverage, total=401, eligible=1, attempted=1, analyzed=1,
                    exclusions={"symlink": 400})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_symlink_target_text_cannot_become_a_sql_finding(module, scanner, extension):
    coverage = {}
    files = [(symlink(f"app/linked.{extension}"), UNSAFE),
             (f"app/query.{extension}", UNSAFE)]

    findings = scanner(archive(files), coverage=coverage)

    assert [(finding.file, finding.line) for finding in findings] == [(f"app/query.{extension}", 1)]
    assert_coverage(coverage, total=2, eligible=1, attempted=1, analyzed=1,
                    exclusions={"symlink": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
@pytest.mark.parametrize("prefix", ["", "project/nested/"])
def test_git_metadata_does_not_consume_sql_finding_budget(module, scanner, extension, prefix):
    coverage = {}
    files = [(f"{prefix}.git/hooks/helper.{extension}", UNSAFE * 32),
             (f"{prefix}my.git/query.{extension}", UNSAFE),
             (f"{prefix}app/query.{extension}", UNSAFE)]

    findings = scanner(archive(files), coverage=coverage)

    assert [(finding.file, finding.line) for finding in findings] == [
        (f"{prefix}my.git/query.{extension}", 1), (f"{prefix}app/query.{extension}", 1),
    ]
    assert_coverage(coverage, total=3, eligible=2, attempted=2, analyzed=2,
                    exclusions={"git_metadata": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
@pytest.mark.parametrize("limit", ["nodes", "recursion"])
def test_real_analysis_limits_preserve_prior_and_other_file_findings(module, scanner, extension, limit):
    if limit == "nodes":
        # Both visitors exceed their real 80,000-step budget, below 400 KB.
        limited = "0\n" * 40_001
    else:
        limited = "x" + ".a" * 1_200 + "\n"
    coverage = {}
    findings = scanner(archive([(f"app/limited.{extension}", UNSAFE + limited + UNSAFE),
                                (f"app/complete.{extension}", UNSAFE)]), coverage=coverage)
    assert [(finding.file, finding.line) for finding in findings] == [
        (f"app/limited.{extension}", 1), (f"app/complete.{extension}", 1),
    ]
    assert_coverage(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"analysis_limit": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_exhausted_expression_never_fabricates_finding_for_literal_query(monkeypatch, module, scanner, extension):
    # Sweep every interruption point of a safe expression, including an
    # interrupted operand that older visitors converted to an unknown value.
    for budget in range(40):
        monkeypatch.setattr(module, "_MAX_NODES", budget)
        coverage = {}
        assert scanner(archive([(f"app/safe.{extension}", SAFE)]), coverage=coverage) == []
        assert coverage["skip_reasons"] in ({}, {"analysis_limit": 1})
        assert coverage["analyzed_files"] + coverage["skipped_files"] == 1


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_finding_limit_wins_when_same_file_also_reaches_analysis_limit(module, scanner, extension):
    coverage = {}
    source = UNSAFE * 33 + "x" + ".a" * 1_200
    assert len(scanner(archive([(f"app/query.{extension}", source)]), coverage=coverage)) == 32
    assert_coverage(coverage, total=1, eligible=1, attempted=1, analyzed=0, skips={"finding_limit": 1})


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_context_and_output_are_reset_between_scans(module, scanner, extension):
    coverage = {}
    limited = "x" + ".a" * 1_200
    with track_analysis_limits() as outer:
        scanner(archive([(f"app/query.{extension}", limited)]), coverage=coverage)
        assert outer == set()
        mark_analysis_limit()
        assert outer == {"analysis_limit"}
    scanner(archive([(f"app/query.{extension}", SAFE)]), coverage=coverage)
    assert_coverage(coverage, total=1, eligible=1, attempted=1, analyzed=1)
    assert scanner(archive([]), coverage=coverage) == []
    assert_coverage(coverage, total=0, eligible=0, attempted=0, analyzed=0)


@pytest.mark.parametrize("module,scanner,extension", CASES)
def test_continuation_preserves_archive_finding_cap(monkeypatch, module, scanner, extension):
    monkeypatch.setattr(module, "_MAX_FILES", 1)
    zipped = archive([(f"app/first.{extension}", UNSAFE * 31),
                      (f"app/second.{extension}", UNSAFE * 2),
                      (f"app/third.{extension}", UNSAFE)])
    previous = {}
    first = scanner(zipped, coverage=previous)
    assert len(first) == 31
    assert_coverage(previous, total=3, eligible=3, attempted=1, analyzed=1, skips={"file_limit": 2})
    continued = {}
    with resume_rule(previous, len(first)):
        second = scanner(zipped, coverage=continued)
    assert [(finding.file, finding.line) for finding in second] == [(f"app/second.{extension}", 1)]
    assert_coverage(continued, total=3, eligible=3, attempted=2, analyzed=1, skips={"finding_limit": 2})


@pytest.mark.parametrize("extension", ["js", "jsx", "ts", "tsx", "mts", "cts", "mjs", "cjs", "JsX", "TsX"])
def test_javascript_extensions_include_jsx_syntax(extension):
    coverage = {}
    source = UNSAFE
    if extension.lower().endswith("sx"):
        source += "const element = <div />;\n"
    findings = javascript_sql.scan_sql_injection_js(archive([(f"app/query.{extension}", source)]),
                                                   coverage=coverage)
    assert len(findings) == 1
    assert_coverage(coverage, total=1, eligible=1, attempted=1, analyzed=1)


def test_python_parser_recursion_is_recorded_without_hiding_other_files(monkeypatch):
    original = python_sql.ast.parse

    def parse(source, *args, **kwargs):
        if source.startswith("# parser depth"):
            raise RecursionError("AST parser exhausted")
        return original(source, *args, **kwargs)

    monkeypatch.setattr(python_sql.ast, "parse", parse)
    coverage = {}
    findings = python_sql.scan_sql_injection(archive([("app/deep.py", "# parser depth\n"),
                                                     ("app/query.py", UNSAFE)]), coverage=coverage)
    assert [finding.file for finding in findings] == ["app/query.py"]
    assert_coverage(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"ast_limit": 1})


def test_javascript_visitor_bug_is_a_check_failure_not_a_source_parse_gap(monkeypatch):
    def fail_visit(*args, **kwargs):
        raise ValueError("Broken visitor invariant")

    monkeypatch.setattr(javascript_sql._QueryFlow, "visit", fail_visit)
    report = run_static_scan(archive([("app/query.ts", UNSAFE), ("app/query.py", UNSAFE)]))
    assert report["checks_not_run"] == [{"check": "sql_injection_js", "reason": "check_error: ValueError"}]
    assert "sql_injection_js" not in report["checks_run"]
    assert report["rule_coverage"]["sql_injection_js"] == {}
    assert report["rule_coverage"]["sql_injection"]["partial"] is False
    sql_findings = [finding for finding in report["findings"] if finding["rule_id"] == python_sql.RULE_ID]
    assert [(finding["file"], finding["line"]) for finding in sql_findings] == [("app/query.py", 1)]
