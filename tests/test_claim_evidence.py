"""Pin the boundary between a matching quote and a verified consequence."""
import json

import pytest

from app.llm.client import LLMClient
from app.report.evidence import claim_evidence_rows
from app.report.html import render_report
from app.scan.claim_evidence import model_claim_evidence, quote_match_window
from app.scan.pipeline import run_scan
from tests.conftest import run_audit_job
from tests.test_audit_llm_wiring import FakeLLM, make_zip


FILES = {"app/auth.py": b"def handler():\n    return lookup(payment_id)\n"}
CLAIM = {
    "file": "app/auth.py", "line_start": 2, "line_end": 2, "evidence": "lookup(payment_id)",
    "severity": "high", "confidence": 1.0, "title": "Payment lookup by identifier",
    "observation": "The handler calls lookup with payment_id.",
    "explanation": "If an unauthorized caller can reach this handler, another payment might be read.",
    "required_conditions": ["The caller can reach this route without operator authorization."],
    "fix_hint": "Check route and middleware authorization before changing the lookup.",
}


def test_quote_check_records_its_actual_window_without_storing_source_literals():
    files = {"app/auth.py": "# synthetic-private-value\na = 1\nb = 2\nc = 3\nd = 4\ne = 5\n"}
    raw = {**CLAIM, "line_start": 3, "line_end": 3, "evidence": "synthetic-private-value"}
    record = model_claim_evidence(raw, files)
    assert record["source_check"] == {"kind": "quote_match", "line_start": 1, "line_end": 5}
    assert "synthetic-private-value" not in json.dumps(record)
    # The old +/-2 tolerance is explicit. A quote outside it is not checked.
    assert quote_match_window({**raw, "line_start": 5, "line_end": 5}, files) is None


@pytest.mark.parametrize("invalid", [None, [], {"checked": True}, float("inf")])
def test_invalid_model_coordinates_are_not_evidence(invalid):
    assert quote_match_window({**CLAIM, "line_start": invalid}, {"app/auth.py": FILES["app/auth.py"].decode()}) is None


async def test_storage_keeps_conditions_but_cannot_accept_model_supplied_confirmation():
    raw = {**CLAIM, "verification_status": "confirmed", "source": "static",
           "claim_evidence": {"version": 1, "source_check": {"kind": "runtime_test"},
                              "conditions_status": "passed", "consequence_status": "confirmed"}}
    row = await run_audit_job(make_zip(FILES).getvalue(), llm_client=FakeLLM(response=json.dumps([raw])),
                              account_id="44444444-4444-4444-4444-444444444444")
    finding = next(f for f in row["findings_json"] if f["source"] == "llm")
    record = finding["claim_evidence"]
    assert record["source_check"] == {"kind": "quote_match", "line_start": 1, "line_end": 2}
    assert record["observation"] == CLAIM["observation"]
    assert record["required_conditions"] == CLAIM["required_conditions"]
    assert record["conditions_status"] == record["consequence_status"] == "not_checked"
    assert finding["verification_status"] == "unverified"


@pytest.mark.parametrize("conditions", [None, [], {}, [None, 1, " "]])
def test_missing_or_malformed_conditions_never_mean_satisfied(conditions):
    raw = {**CLAIM, "required_conditions": conditions, "observation": {"confirmed": True}}
    scan = run_scan(make_zip(FILES).getvalue(), FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    finding = next(f for f in scan["findings"] if f["source"] == "llm")
    assert finding["claim_evidence"]["required_conditions"] is None
    assert finding["claim_evidence"]["observation"] is None
    html = render_report(scan)
    assert "Not recorded; do not assume the conditions for harm are satisfied." in html
    assert "Possible consequence — unverified:" in html


def test_conditions_are_not_silently_truncated():
    raw = {**CLAIM, "required_conditions": ["condition " * 100] * 8}
    record = model_claim_evidence(raw, {"app/auth.py": FILES["app/auth.py"].decode()})
    assert record["required_conditions"] == [c.strip() for c in raw["required_conditions"]]


def test_static_record_does_not_claim_to_have_verified_the_consequence():
    scan = run_scan(make_zip({"app.py": b"print('synthetic')"}).getvalue(), LLMClient(providers=[]))
    finding = next(f for f in scan["findings"] if f["rule_id"] == "no-dockerfile")
    assert finding["claim_evidence"]["source_check"] == {"kind": "static_rule"}
    assert finding["claim_evidence"]["consequence_status"] == "not_checked"


def test_older_findings_do_not_acquire_a_retrospective_quote_check():
    finding = {"rule_id": "llm-auth", "title": "Older claim", "severity": "high", "source": "llm"}
    for record in (None, {"version": 99, "source_check": {"kind": "quote_match"}}):
        rows = dict(claim_evidence_rows({**finding, "claim_evidence": record}))
        assert rows["Source check"].startswith("Not recorded")
        assert rows["Consequence check"] == "No independent verification recorded."


def test_report_escapes_model_conditions_and_keeps_them_visible():
    raw = {**CLAIM, "observation": "<script>bad()</script>", "required_conditions": ["<img src=x onerror=bad()>"]}
    scan = run_scan(make_zip(FILES).getvalue(), FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    html = render_report({**scan, "findings": [f for f in scan["findings"] if f["source"] == "llm"]})
    assert "&lt;script&gt;bad()&lt;/script&gt;" in html
    assert "<script>bad()" not in html
    assert "Required conditions — not checked" in html
    assert "<details>" not in html  # Model conditions are visible before suggested fixes.
