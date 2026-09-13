"""A failing check must not take the scan with it, and must not vanish either.

MEASURED 2026-09-13: one raising scanner killed the WHOLE scan — every other
finding went with it — both server-side and in a browser build that had no
TypeScript grammar. The browser build is what forced the question, but the
defect was never about the browser: a customer whose archive trips one scanner
gets no report at all instead of "this check did not run".

"Did not run" is not "ran and found nothing", so the check leaves `checks_run`
and is named in `checks_not_run` with the exception TYPE only — scanner messages
can quote the input being scanned, and this dict travels into the report.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.capabilities import CHECKS_RUN
from app.scan import static
from app.scan.error_boundary import MOUNT_UNKNOWN
from app.scan.manifest import scan_manifest
from tests.detector_samples import expand_samples

SECRET_FILE = "src/gh.ts"
SECRET_BODY = expand_samples('const token = "@DRYDOCK_SAMPLE:GITHUB@";')
LEAKING_MESSAGE = "value-was-secret-value-was-secret"


def make_zip(files: dict[str, str] | None = None) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in (files or {SECRET_FILE: SECRET_BODY}).items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def explode(*_args, **_kwargs):
    raise RuntimeError(LEAKING_MESSAGE)


def test_a_normal_scan_runs_every_check_and_names_none_as_not_run():
    """The premise of every case below: without a failure, all seventeen run and
    the secret this fixture carries is actually found."""
    result = static.run_static_scan(make_zip())
    assert result["checks_run"] == list(CHECKS_RUN)
    assert result["checks_not_run"] == []
    assert [f["rule_id"] for f in result["findings"] if f["rule_id"] == "github-pat"]


@pytest.mark.parametrize(("target", "check", "survivor"), [
    ("scan_secrets", "secrets", "no-tests"),            # produced by run_checks
    ("scan_tls_verification", "tls_verification", "github-pat"),
    ("scan_cookie_flags", "session_cookie", "github-pat"),
    ("scan_error_boundary", "error_boundary", "github-pat"),
    ("collect_source_facts", "http_success", "github-pat"),
    ("run_checks", "project_files", "github-pat"),
])
def test_a_failing_check_is_named_and_every_other_check_still_reports(monkeypatch, target, check, survivor):
    monkeypatch.setattr(static, target, explode)

    result = static.run_static_scan(make_zip())

    # The check is named, with a reason that carries the type and not the text.
    assert result["checks_not_run"] == [{"check": check, "reason": "check_error: RuntimeError"}]
    # It left checks_run, and nothing else did: "did not run" is not "found nothing".
    assert result["checks_run"] == [name for name in CHECKS_RUN if name != check]
    # A finding produced by a DIFFERENT check survived the failure. The survivor is
    # named per case, so killing one check cannot pass by accident.
    assert survivor in [f["rule_id"] for f in result["findings"]]
    assert LEAKING_MESSAGE not in json.dumps(result)


def test_a_check_that_did_not_run_carries_its_own_sentence(monkeypatch):
    """The coverage text says why, so a reader of the report cannot take the
    check's silence for a clean result. The boundary check is the one whose
    coverage string and mount value the report renders."""
    monkeypatch.setattr(static, "scan_error_boundary", explode)

    result = static.run_static_scan(make_zip())

    coverage = result["coverage"]["error_boundary"]
    assert "This check did not run" in coverage and "not a clean result" in coverage
    assert result["score"]["frontend_scan"]["mount"] == MOUNT_UNKNOWN
    assert result["score"]["frontend_scan"]["mount"] != "no_mount"


def test_the_manifest_carries_the_checks_that_did_not_run(monkeypatch):
    """The manifest is what a stored audit keeps, so the difference has to survive
    storage: a shortened static_checks with no companion list would read as "it
    ran and found nothing"."""
    monkeypatch.setattr(static, "scan_secrets", explode)
    data = make_zip().getvalue()
    scan = static.run_static_scan(io.BytesIO(data))

    manifest = scan_manifest(data, "test", scan, {}, None)

    assert manifest["static_checks_not_run"] == [
        {"check": "secrets", "reason": "check_error: RuntimeError"}]
    assert "secrets" not in manifest["static_checks"]
    assert "session_cookie" in manifest["static_checks"]
