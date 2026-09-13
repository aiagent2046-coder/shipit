"""Browser startup and reporting with genuinely unavailable native packages."""
import io
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import zipfile

import pytest

from app.capabilities import CHECKS_RUN
from app.ingest.validators import ArchiveValidationError
from app.scan.browser import scan_archive
from app.scan.static import run_static_scan


def archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zf:
        zf.writestr("config.py", 'api_key = ' + repr('sk_' + 'live_' + 'a' * 24) + '\n')
        zf.writestr("supabase/migrations/001.sql", "CREATE TABLE public.orders (id uuid PRIMARY KEY);")
    return output.getvalue()


def isolated_scan():
    # A fresh interpreter is essential: deleting selected cached modules can
    # accidentally leave native-backed functions usable and fake portability.
    code = textwrap.dedent('''
        import importlib.abc, io, json, sys, zipfile
        class NoNative(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] in {
                    "tree_sitter", "tree_sitter_typescript", "tree_sitter_javascript", "pglast"
                }:
                    raise ModuleNotFoundError("native dependency deliberately absent", name=fullname)
                if fullname in {"app.scan.pipeline", "app.scan.llm_scan", "app.sca.osv"}:
                    raise AssertionError("browser imported a remote stage")
        sys.meta_path.insert(0, NoNative())
        from app.scan.browser import scan_archive
        from app.ingest.validators import ArchiveValidationError
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as zf:
            zf.writestr("config.py", 'api_key = ' + repr('sk_' + 'live_' + 'a' * 24) + '\\n')
            zf.writestr("supabase/migrations/001.sql", "CREATE TABLE public.orders (id uuid PRIMARY KEY);")
        result = scan_archive(data.getvalue())
        try:
            scan_archive(b"not a zip")
        except ArchiveValidationError as exc:
            result["invalid_zip_reason"] = exc.reason
        print(json.dumps(result))
    ''')
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
        text=True, capture_output=True, check=True,
    )
    return json.loads(completed.stdout)


def test_browser_boots_without_native_dependencies_and_reports_real_findings():
    result = isolated_scan()
    report = result["report"]
    assert "stripe-live-key" in {finding["rule_id"] for finding in report["findings"]}
    assert "rls" in report["checks_run"]
    failures = report["checks_not_run"]
    assert {entry["check"] for entry in failures} == {
        "sql_injection_js", "tls_verification", "session_cookie", "http_success",
    }
    assert all(entry["reason"] == "check_error: ImportError" for entry in failures)
    assert all(report["coverage"][entry["check"]].startswith("Did not run") for entry in failures)
    assert set(report["checks_run"]).isdisjoint(entry["check"] for entry in failures)
    assert set(report["checks_run"]) | {entry["check"] for entry in failures} == set(CHECKS_RUN)
    assert len(report["checks_run"]) + len(failures) == len(CHECKS_RUN) == 17
    assert "score" not in report
    assert report["runtime_verified"] is False
    assert result["invalid_zip_reason"] == "not_a_zip"

    invocation = result["sarif"]["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["staticChecksNotRun"] == failures
    assert invocation["properties"]["limitations"] == report["limitations"]
    assert {"dependency_check_not_run", "runtime_tests_not_run", "static_source_only",
            "native_parsers_unavailable"} <= set(report["limitations"])


def test_no_native_scan_preserves_evidence_but_withholds_unguarded_advice():
    result = isolated_scan()
    report = result["report"]
    assert "recommendation_enrichment_unavailable" in report["limitations"]
    assert report["findings"]
    assert all(finding["fix_hint"] == "" for finding in report["findings"])
    secret = next(f for f in report["findings"] if f["rule_id"] == "stripe-live-key")
    assert secret["severity"] == "critical"
    assert secret["masked"]
    assert secret["file"] == "config.py"
    assert secret["line"] == 1
    assert ('sk_' + 'live_' + 'a' * 24) not in json.dumps(result)
    # The normal SARIF plain-language dictionary must not restore omitted advice.
    rules = result["sarif"]["runs"][0]["tool"]["driver"]["rules"]
    assert all(rule["help"]["text"].startswith("Advice omitted:") for rule in rules)
    assert len(result["sarif"]["runs"][0]["results"]) == len(report["findings"])


def test_browser_native_path_matches_shared_static_stage():
    pytest.importorskip("tree_sitter_typescript")
    pytest.importorskip("pglast")
    data = archive()
    static = run_static_scan(io.BytesIO(data))
    result = scan_archive(data)
    for key in ("findings", "checks_run", "checks_not_run", "coverage", "rule_coverage"):
        assert result["report"][key] == static[key]
    assert static["checks_not_run"] == []
    assert "recommendation_enrichment_unavailable" not in result["report"]["limitations"]
    assert "native_parsers_unavailable" not in result["report"]["limitations"]
    assert result["sarif"]["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_secret_advice_reaches_json_and_sarif_without_claiming_live_credentials():
    data = io.BytesIO()
    literal = "browser-probe-" + "a1b2c3d4"
    with zipfile.ZipFile(data, "w") as zf:
        for name in ("src/config.py", "tests/test_config.py"):
            zf.writestr(name, f'api_key = "{literal}"\n')
    result = scan_archive(data.getvalue())
    findings = [f for f in result["report"]["findings"] if f["rule_id"] == "generic-assignment"]
    assert len(findings) == 2
    for finding in findings:
        assert "does not establish" in finding["explanation"]
        assert "synthetic test data" in finding["fix_hint"]
        assert finding["verification_status"] == "unverified"
        assert finding["claim_evidence"]["conditions_status"] == "not_checked"
        sarif_result = next(r for r in result["sarif"]["runs"][0]["results"]
                            if r["ruleId"] == "generic-assignment"
                            and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == finding["file"])
        assert finding["explanation"] in sarif_result["message"]["text"]
    test_finding = next(f for f in findings if f["file"].startswith("tests/"))
    assert "test, example or comment context" in test_finding["explanation"]
    assert literal not in json.dumps(result)


@pytest.mark.parametrize("data,reason", [(b"not a zip", "not_a_zip"), (b"", "not_a_zip")])
def test_browser_rejects_invalid_zip(data, reason):
    with pytest.raises(ArchiveValidationError) as error:
        scan_archive(data)
    assert error.value.reason == reason


def test_browser_rejects_duplicate_paths():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr("a.py", "pass")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("a.py", "pass")
    with pytest.raises(ArchiveValidationError) as error:
        scan_archive(data.getvalue())
    assert error.value.reason == "duplicate_path"


def test_optional_imports_preserve_real_callable_identity():
    pytest.importorskip("tree_sitter_typescript")
    from app.scan import static
    from app.scan.sql_injection_js import scan_sql_injection_js
    assert static.scan_sql_injection_js is scan_sql_injection_js


@pytest.mark.parametrize("error", [
    RuntimeError("bad initialization"),
    ImportError("application import bug", name="app.scan.missing"),
    ImportError("unidentified import bug"),
])
def test_optional_imports_do_not_hide_application_errors(monkeypatch, error):
    from app.scan import check_loading

    def fail(_module):
        raise error

    monkeypatch.setattr(check_loading, "import_module", fail)
    with pytest.raises(type(error)) as caught:
        check_loading.optional_native_function("app.scan.example", "scan")
    assert caught.value is error
