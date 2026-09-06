"""Regression contract from the free/paid Drydock reports of commit 28bb61d.

The reviewed claims are a calibration set, NOT production suppression rules.
Until an independent verifier exists, a model can still emit these claims;
the product must never present them as confirmed, even after repeated passes.
"""

import json
from pathlib import Path

import pytest

from app.llm.client import LLMClient
from app.report.html import render_report
from app.scan.pipeline import run_scan
from tests.test_audit_llm_wiring import AUTH_ZIP, FakeLLM, make_zip

CASES = json.loads((Path(__file__).parent / "data/audit_truthfulness_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_reviewed_false_or_unsubstantiated_claims_never_become_confirmed(case):
    # A plausible claim about real code is still not independent evidence.
    finding = {"rule_id": "llm-auth", "category": "Auth", "confidence": 1.0,
               "title": case["title"], "file": case["file"], "severity": case["severity"]}
    html = render_report({
        "score": {"basis": "static+llm", "total": 4.9, "categories": {"Auth": 6.0}},
        "findings": [finding],
    })
    assert "Model hypothesis — unverified" in html
    assert "Potential " + case["severity"] + " impact" in html
    assert "Fix before launch" not in html
    assert ">4.9<" not in html


def test_model_cannot_supply_its_own_confirmation_through_the_pipeline():
    claim = {
        "file": "app/auth.ts", "line_start": 1, "line_end": 1,
        "evidence": "const password = 'x'", "severity": "high",
        "confidence": 1.0, "title": "Hardcoded credential",
        "explanation": "A hypothesis", "fix_hint": "Verify the value",
        "source": "static", "verification_status": "confirmed",
        "verification_method": "runtime_test",
    }
    scan = run_scan(make_zip(AUTH_ZIP).getvalue(), FakeLLM(response=json.dumps([claim])),
                    llm_passes=2)
    findings = [f for f in scan["findings"] if f["rule_id"].startswith("llm-")]
    assert findings
    for f in findings:
        assert f["source"] == "llm"
        assert f["verification_status"] == "unverified"
        assert f["verification_method"] == "model_review"


def test_static_matches_are_retained_with_provenance_including_test_secrets():
    # Synthetic value; no network or credential verification takes place.
    data = make_zip({
        "repo/app/config.py": b"AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'",  # scan-allow: synthetic AWS format fixture
        "repo/tests/test_config.py": b"AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'",  # scan-allow: synthetic AWS format fixture
    }).getvalue()
    scan = run_scan(data, LLMClient(providers=[]))
    assert scan["score"]["readiness_score_validated"] is False
    keys = [f for f in scan["findings"] if f["rule_id"] == "aws-access-key-id"]
    assert keys
    assert any("tests/" in f["file"] for f in keys)
    assert any("app/" in f["file"] for f in keys)
    for f in keys:
        assert f["source"] == "static"
        assert f["verification_status"] == "unverified"
        assert f["verification_method"] == "source_pattern"


def test_reported_money_examples_do_not_reproduce_the_claim():
    for amount in ("990.00", "990.07"):
        assert f"{float(amount):.2f}" == amount
