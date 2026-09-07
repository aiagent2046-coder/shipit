"""Operation context is reproducible navigation evidence, never a verdict."""
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.scan import operation_context as context
from app.scan.source_facts import collect_source_facts, facts_prompt
from app.report.evidence import manifest_rows
from app.report.html import render_report


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, source in files.items():
            zf.writestr(path, source)
    buf.seek(0)
    return buf


def test_python_context_finds_input_and_guard_without_executing_or_persisting_literals(tmp_path):
    marker = tmp_path / "never-executed"
    source = f'''import subprocess
def run_sql(sql):
    if not enabled:
        return
    cmd = ["psql", "credential-must-not-appear"]
    return subprocess.run(cmd, input=sql)
run_sql("private-sql-must-not-appear")
open({str(marker)!r}, "w").write("executed")
'''
    record = context.collect_operation_context(archive({"runner.py": source}))
    fact, = record["records"]
    assert fact["line"] == 6 and fact["scope"] == "run_sql"
    assert "Keyword input: Name; names: sql" in fact["detail"]
    assert "Earlier assignment at line 5: List" in fact["detail"]
    assert "Preceding if with exit syntax at line 3" in fact["detail"]
    assert "Same-file call spelling at line 7: Constant" in fact["detail"]
    assert "must-not-appear" not in json.dumps(record)
    assert not marker.exists()


def test_js_fetch_records_wrapper_callers_without_claiming_ssrf_or_leaking_url():
    source = '''async function request(input: string) { return fetch(input); }
request(`${API_BASE_URL}/private-path-must-not-appear`);
request(attackerInput);
const noise = "fetch(untrusted)";
// fetch(untrusted)
'''
    record = context.collect_operation_context(archive({"api.ts": source}))
    fact, = record["records"]
    assert fact["scope"] == "request"
    assert "template_string; names: API_BASE_URL" in fact["detail"]
    assert "identifier; names: attackerInput" in fact["detail"]
    assert "does not establish SSRF" in fact["detail"]
    assert "private-path" not in json.dumps(record)


def test_arrow_fetch_and_shadowed_names_remain_syntax_only():
    record = context.collect_operation_context(archive({
        "api.ts": "const request = (fetch, url) => fetch(url); request(custom, external);"}))
    fact, = record["records"]
    assert fact["scope"] == "request"
    assert "Names are not resolved" in record["scope"]
    assert "browser/server execution" in fact["detail"]


@pytest.mark.parametrize("source", [
    'const {token = "private-literal"} = () => fetch(url);',
    'class Client { ["private-literal"](){return fetch(url);} }',
    'class Client { "private-literal"(){return fetch(url);} }',
])
def test_js_non_identifier_names_never_copy_source_literals(source):
    record = context.collect_operation_context(archive({"a.ts": source}))
    assert len(record["records"]) == 1
    assert "private-literal" not in json.dumps(record)


def test_js_method_does_not_inherit_enclosing_function_identity():
    source = 'function outer(){ class Client { send(){return fetch(url);} } } outer(secret);'
    fact, = context.collect_operation_context(archive({"a.ts": source}))["records"]
    assert fact["scope"] == "<method>"
    assert "Same-file call spelling" not in fact["detail"]


def test_numeric_examples_rebut_exact_binary_claim_without_asserting_application_safety():
    source = '''def expected(row):
    return f"{float(row.get('amount') or 0):.2f}"
'''
    fact, = context.collect_operation_context(archive({"payment.py": source}))["records"]
    assert fact["kind"] == "numeric_examples"
    assert "990.07 -> 990.07 (binary exact: False)" in fact["detail"]
    assert "490.00 -> 490.00 (binary exact: True)" in fact["detail"]
    assert "do not execute the uploaded expression" in fact["detail"]
    assert "cover all numeric inputs" in fact["detail"]


@pytest.mark.parametrize("source", [
    'x = "float(value):.2f"', 'x = f"{float(value):.3f}"',
    'x = f"{float(value):{fmt}}"', 'x = f"{float(value)!r:.2f}"',
    'x = f"{other.float(value):.2f}"',
])
def test_unsupported_numeric_shapes_do_not_receive_experiments(source):
    assert context.collect_operation_context(archive({"a.py": source}))["records"] == []


def test_budget_and_invalid_files_are_visible_and_test_code_is_not_app_evidence(monkeypatch):
    monkeypatch.setattr(context, "MAX_FILE_BYTES", 150)
    record = context.collect_operation_context(archive({
        "repo/tests/fixture.py": "subprocess.run(cmd)", "repo/vendor/a.ts": "fetch(url)",
        "a.py": "subprocess.run(cmd)", "broken.ts": "function {", "big.py": "#" * 151}))
    assert record["parsed_files"] == 1 and record["excluded_files"] == 2
    assert record["limitations"] == ["file_size_or_path_limit", "unparseable_source"]
    monkeypatch.setattr(context, "MAX_RECORDS", 1)
    record = context.collect_operation_context(archive({"a.py": "subprocess.run(a)\nsubprocess.run(b)"}))
    assert len(record["records"]) == 1
    assert record["limitations"] == ["record_limit_reached"]
    monkeypatch.setattr(context, "MAX_TOTAL_BYTES", 1)
    record = context.collect_operation_context(archive({"a.py": "subprocess.run(cmd)"}))
    assert record["records"] == [] and record["limitations"] == ["scan_budget_reached"]


def test_duplicate_archive_paths_are_unknown():
    buf = archive({"a.py": "subprocess.run(cmd)"})
    with pytest.warns(UserWarning), zipfile.ZipFile(buf, "a") as zf:
        zf.writestr("a.py", "subprocess.run(other)")
    record = context.collect_operation_context(buf)
    assert not record["records"]
    assert record["limitations"] == ["ambiguous_archive_path"]


def test_context_reaches_prompt_and_report_even_without_compare_digest_facts():
    record = collect_source_facts(archive({"api.ts": "function request(url) { return fetch(url); }"}))
    assert record["facts"] == []
    prompt = facts_prompt(record)
    assert "javascript_fetch_context" in prompt
    rows = dict(manifest_rows({"scan_manifest": {"source_facts": record}}))
    assert "request: fetch" in rows["Operation context 1"]
    original = json.dumps(record, sort_keys=True)
    assert facts_prompt(record, max_chars=20) == ""
    assert json.dumps(record, sort_keys=True) == original


def test_report_escapes_context_and_keeps_historical_fixture_label():
    record = collect_source_facts(archive({"<unsafe>.ts": "fetch(url)"}))
    score = {"total": 0, "categories": {}, "basis": "static+llm",
             "scan_manifest": {"source_facts": record},
             "preview_history": {"version": 1, "retained_findings": [{
                 "title": "Fixture", "file": "tests/fixtures/a.py", "severity": "high"}]}}
    html = render_report({"score": score, "findings": [], "stack": "unknown"})
    assert "&lt;unsafe&gt;.ts" in html and "<unsafe>" not in html
    assert "Previous preview — not reassessed · Test/example context" in html


@pytest.mark.parametrize(("path", "call"), [
    ("web/src/lib/api.ts", "fetch"), ("scripts/migration_manager.py", "subprocess.run"),
    ("app/routes/yookassa.py", "float(...):.2f"),
])
def test_actual_report_targets_have_context_without_importing_them(path, call):
    data = (Path(__file__).resolve().parents[1] / path).read_bytes()
    record = context.collect_operation_context(archive({path: data}))
    assert any(r["call"] == call for r in record["records"])
