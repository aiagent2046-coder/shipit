"""Actual bounded scans must distinguish completed checks from unread source."""

import pytest

from app.scan.outbound_url import scan_outbound_url
from app.scan.path_traversal import scan_path_traversal
from app.scan.rule_coverage import mark_analysis_limit, track_analysis_limits
from app.scan.tls_verification import scan_tls_verification
from app.scan.unsafe_deserialization import scan_unsafe_deserialization
from tests.test_dependency_scan_budget import CASES, archive


def assert_accounting(record, *, total, eligible, attempted, analyzed, exclusions=None, skips=None):
    exclusions = exclusions or {}
    skips = skips or {}
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


def harmless(filename):
    return "pass\n" if filename.endswith(".py") else "export const present = true;\n"


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("count", [400, 840])
def test_inventory_counts_own_files_after_the_real_400_file_limit(scanner, rule_id, filename, source, count):
    suffix = filename.rsplit(".", 1)[-1]
    files = [(f"app/module_{number}.{suffix}", harmless(filename)) for number in range(count - 1)]
    files.append((f"app/{filename}", source))
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert [finding.rule_id for finding in findings] == ([rule_id] if count == 400 else [])
    assert_accounting(coverage, total=count, eligible=count, attempted=400, analyzed=400,
                      skips={"file_limit": 440} if count == 840 else {})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_dependencies_exclusions_and_oversized_own_source_are_accounted_separately(
    scanner, rule_id, filename, source,
):
    files = [(f"project/.venv/lib/pkg/module_{number}/{filename}", source) for number in range(401)]
    files += [
        ("project/", ""),
        (f"project/app/oversized/{filename}", "#" * 400_001),
        (f"project/tests/{filename}", source),
        ("project/app/main.rs", "fn main() {}"),
        (f"project/app/{filename}", source),
    ]
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert [finding.rule_id for finding in findings] == [rule_id]
    assert_accounting(coverage, total=405, eligible=2, attempted=1, analyzed=1,
                      exclusions={"dependency_tree": 401, "non_production_path": 1,
                                  "unsupported_extension": 1},
                      skips={"file_size_limit": 1})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_decode_and_parse_failures_never_count_as_analyzed(scanner, rule_id, filename, source):
    malformed = "@ invalid python [\n" if filename.endswith(".py") else "const rejectUnauthorized = [;\n"
    files = [
        (f"app/undecodable/{filename}", b"# @ rejectUnauthorized\n\xff"),
        (f"app/unparseable/{filename}", malformed),
        (f"app/{filename}", source),
    ]
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert [finding.rule_id for finding in findings] == [rule_id]
    assert_accounting(coverage, total=3, eligible=3, attempted=3, analyzed=1,
                      skips={"decode_error": 1, "parse_error": 1})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("budget", ["nodes", "depth"])
def test_real_ast_limits_are_partial_even_when_no_finding_is_returned(scanner, rule_id, filename, source, budget):
    if filename.endswith(".py"):
        large = "value = 0\n" * 6_000 if budget == "nodes" else "value = " + "name + " * 110 + "name\n"
        large += "# @\n"
    else:
        large = "const value = 0;\n" * 5_000 if budget == "nodes" else "const value = " + "a ? a : " * 110 + "a;\n"
        large += "// rejectUnauthorized\n"
    assert len(large.encode("utf-8")) < 400_000
    coverage = {}
    assert scanner(archive([(f"app/{filename}", large)]), coverage=coverage) == []
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=0, skips={"ast_limit": 1})


def multiple_signals(scanner, filename, count):
    if scanner is scan_tls_verification:
        if filename.endswith(".py"):
            return "import requests\n" + 'requests.get("https://example.com", verify=False)\n' * count
        return 'import https from "node:https";\n' + "new https.Agent({rejectUnauthorized: false});\n" * count
    if scanner is scan_unsafe_deserialization:
        return "import pickle\n" + "pickle.loads(payload)\n" * count
    sink = "httpx.get(value)" if scanner is scan_outbound_url else "open(value).read()"
    header = "from fastapi import FastAPI\nimport httpx\napp = FastAPI()\n"
    return header + "".join(
        f'@app.get("/{number}")\ndef handler_{number}(value: str):\n    return {sink}\n'
        for number in range(count)
    )


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("tail", [0, 3])
def test_more_than_32_signals_in_one_file_reports_current_file_and_unread_tail(
    scanner, rule_id, filename, source, tail,
):
    files = [(f"app/{filename}", multiple_signals(scanner, filename, 33))]
    files += [(f"app/tail_{number}/{filename}", harmless(filename)) for number in range(tail)]
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert len(findings) == 32
    assert {finding.rule_id for finding in findings} == {rule_id}
    assert_accounting(coverage, total=tail + 1, eligible=tail + 1, attempted=1, analyzed=0,
                      skips={"finding_limit": tail + 1})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_finding_budget_shared_between_files_counts_only_the_incomplete_second_file(
    scanner, rule_id, filename, source,
):
    files = [
        (f"app/first/{filename}", multiple_signals(scanner, filename, 31)),
        (f"app/second/{filename}", multiple_signals(scanner, filename, 2)),
    ]
    coverage = {}
    findings = scanner(archive(files), coverage=coverage)
    assert len(findings) == 32
    assert_accounting(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"finding_limit": 1})


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES[:3])
def test_exactly_32_fully_collected_signals_are_complete(scanner, rule_id, filename, source):
    coverage = {}
    findings = scanner(archive([(f"app/{filename}", multiple_signals(scanner, filename, 32))]), coverage=coverage)
    assert len(findings) == 32
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=1)


@pytest.mark.parametrize("scanner,filename,source", [
    (scan_outbound_url, "route.py", "not syntactically valid Python [\n"),
    (scan_path_traversal, "route.py", "not syntactically valid Python [\n"),
    (scan_tls_verification, "client.ts", "not syntactically valid TypeScript [;\n"),
])
def test_safe_negative_prefilters_complete_supported_check_without_parsing(scanner, filename, source):
    coverage = {}
    assert scanner(archive([(f"app/{filename}", source)]), coverage=coverage) == []
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=1)


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
def test_empty_archive_has_zero_coverage_and_clears_reused_output(scanner, rule_id, filename, source):
    coverage = {"stale": "earlier result"}
    assert scanner(archive([]), coverage=coverage) == []
    assert_accounting(coverage, total=0, eligible=0, attempted=0, analyzed=0)


def expansion_route(scanner, *, budget="slots", over_limit=True, subsequent_findings=0):
    sink = "httpx.get" if scanner is scan_outbound_url else "open"
    source = ('from fastapi import FastAPI\nimport httpx\napp = FastAPI()\n'
              '@app.get("/expand")\ndef expand(value: str, other: str):\n')
    if budget == "slots":
        source += "    value = value + value\n" * (9 if over_limit else 8)
    else:
        # Including the one-byte input slot, the resulting template straddles
        # the real 16,000-byte cap without also exceeding the AST or file caps.
        source += f"    value = value + {'x' * (16_000 if over_limit else 15_999)!r}\n"
    source += f"    {sink}(value)\n"
    source += f"    {sink}(other)\n" * subsequent_findings
    return source


@pytest.mark.parametrize("scanner", [scan_outbound_url, scan_path_traversal])
@pytest.mark.parametrize("budget", ["slots", "template"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_resource_limits_mark_partial_while_later_findings_are_retained(scanner, budget, over_limit):
    source = expansion_route(scanner, budget=budget, over_limit=over_limit, subsequent_findings=1)
    coverage = {}
    findings = scanner(archive([("app/route.py", source)]), coverage=coverage)
    assert len(findings) == (1 if over_limit else 2)
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=0 if over_limit else 1,
                      skips={"analysis_limit": 1} if over_limit else {})


@pytest.mark.parametrize("scanner", [scan_outbound_url, scan_path_traversal])
def test_analysis_limit_does_not_leak_to_other_files_or_scans(scanner):
    limited = expansion_route(scanner)
    complete = expansion_route(scanner, over_limit=False)
    coverage = {}
    assert len(scanner(archive([("app/limited.py", limited), ("app/complete.py", complete)]),
                       coverage=coverage)) == 1
    assert_accounting(coverage, total=2, eligible=2, attempted=2, analyzed=1, skips={"analysis_limit": 1})
    assert len(scanner(archive([("app/complete.py", complete)]), coverage=coverage)) == 1
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=1)


@pytest.mark.parametrize("field_count", [256, 257])
def test_model_field_budget_reports_partial_and_keeps_other_request_findings(field_count):
    source = ('from fastapi import FastAPI\nfrom pydantic import BaseModel\nimport httpx\n'
              'app = FastAPI()\nclass Payload(BaseModel):\n')
    source += "".join(f"    target_{number}: str\n" for number in range(field_count))
    source += ('@app.post("/model")\ndef fetch(payload: Payload, other: str):\n'
               '    httpx.get(payload.target_0)\n    httpx.get(other)\n')
    coverage = {}
    findings = scan_outbound_url(archive([("app/route.py", source)]), coverage=coverage)
    assert len(findings) == (1 if field_count == 257 else 2)
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=0 if field_count == 257 else 1,
                      skips={"analysis_limit": 1} if field_count == 257 else {})


@pytest.mark.parametrize("scanner", [scan_outbound_url, scan_path_traversal])
def test_finding_limit_takes_precedence_when_analysis_limit_also_occurs(scanner):
    coverage = {}
    findings = scanner(archive([("app/route.py", expansion_route(scanner, subsequent_findings=33))]),
                       coverage=coverage)
    assert len(findings) == 32
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=0, skips={"finding_limit": 1})


@pytest.mark.parametrize("scanner", [scan_outbound_url, scan_path_traversal])
@pytest.mark.parametrize("subsequent_findings", [0, 33])
def test_scanner_restores_outer_limit_context_after_completion_or_early_stop(scanner, subsequent_findings):
    with track_analysis_limits() as outer:
        scanner(archive([("app/route.py", expansion_route(scanner, subsequent_findings=subsequent_findings))]))
        assert outer == set(), "The file's resource limit must not mark an enclosing scan."
        mark_analysis_limit()
        assert outer == {"analysis_limit"}, "The enclosing context must be restored even after an early stop."
