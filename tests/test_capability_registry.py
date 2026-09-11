"""The capability registry is only worth serving if it cannot drift from the engine.

`GET /v1/capabilities` tells a customer what the audit can look for. A manifest
that omits a rule the engine emits, names one it cannot, or lists a check the
static stage no longer runs is worse than no manifest: it is a confident
description of a different product. These are the contracts that keep it honest,
and each one fails on a real drift rather than on a style preference.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.capabilities import (CAPABILITIES, CHECKS_RUN, DECLARED_RULE_IDS,
                              EXCLUSIONS_NOTE, HTTP_SUCCESS_SCOPE_PREFIX, SCOPE, manifest)
from app.main import app
from app.scan.pipeline import AUDIT_ENGINE_VERSION
from app.scan.static import run_static_scan
from tests.detectors.test_golden_corpus import emitted_rule_ids

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "detectors"

# Checks whose scope sentence the scan composes at run time instead of reporting
# the declared sentence verbatim.
COMPOSED_CHECKS = {"secrets", "error_boundary", "http_success"}


def _archive() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/routes.py", "from fastapi import APIRouter\n\nrouter = APIRouter()\n")
        zf.writestr("package.json", '{"name": "probe"}\n')
    buf.seek(0)
    return buf


def test_the_registry_declares_every_rule_id_the_engine_can_emit_and_no_other():
    """Both directions. An id missing here is a capability the customer cannot
    read about; an id here that the engine cannot emit is a promise it cannot
    keep, and that is the direction a reviewer should fear more."""
    emitted = emitted_rule_ids()
    assert DECLARED_RULE_IDS - emitted == set(), "declared but not emitted"
    assert emitted - DECLARED_RULE_IDS == set(), "emitted but not declared"


@pytest.mark.parametrize("rule_id", sorted(DECLARED_RULE_IDS))
def test_every_declared_rule_id_has_a_positive_and_a_negative_case(rule_id):
    """The manifest's evidence claim, enforced where the evidence lives. A rule id
    declared without both polarities is described to a customer on the strength of
    nothing: a positive alone proves it fires, never that it discriminates."""
    for polarity in ("positive", "negative"):
        directory = CORPUS / rule_id / polarity
        assert directory.is_dir(), f"{rule_id}: no {polarity} directory"
        cases = [case for case in directory.iterdir() if case.is_dir()]
        assert cases, f"{rule_id}: {polarity} directory holds no case"


def test_the_registry_lists_exactly_the_checks_a_scan_reports_running():
    """Order included: the report's `checks_run` is built from this list, so a
    check added to the stage without a registry entry shows up here."""
    result = run_static_scan(_archive())
    assert result["checks_run"] == list(CHECKS_RUN)


def test_every_capability_declares_a_title_and_a_scope_worth_reading():
    assert len({capability.check for capability in CAPABILITIES}) == len(CAPABILITIES), "duplicate check key"
    for capability in CAPABILITIES:
        assert capability.title.strip(), f"{capability.check}: no title"
        assert len(capability.scope) >= 80, f"{capability.check}: scope is a placeholder"
        assert capability.rule_ids, f"{capability.check}: no rule ids"


def test_the_scan_reports_the_declared_scope_rather_than_a_second_copy():
    """One home per sentence. Where a check has a coverage entry, it is the
    registry's sentence verbatim unless it is composed from a constant declared
    there. Seven checks ship no coverage sentence at all (rls, schema_drift,
    project_files, ci_deploy_source, service_role, sql_injection,
    sql_injection_js); for those the manifest sentence is the only declaration,
    which is exactly why it lives in the registry."""
    coverage = run_static_scan(_archive())["coverage"]
    assert set(coverage) <= set(CHECKS_RUN), "coverage names a check the registry does not declare"
    for check, sentence in coverage.items():
        if check in COMPOSED_CHECKS:
            continue
        assert sentence == SCOPE[check], check
    assert coverage["http_success"].startswith(HTTP_SUCCESS_SCOPE_PREFIX)
    assert EXCLUSIONS_NOTE in coverage["secrets"]


def test_the_endpoint_serves_the_manifest_of_the_engine_that_ran():
    response = TestClient(app).get("/v1/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert body == manifest(AUDIT_ENGINE_VERSION)
    assert body["engine_version"] == AUDIT_ENGINE_VERSION
    assert {entry["check"] for entry in body["capabilities"]} == set(CHECKS_RUN)
