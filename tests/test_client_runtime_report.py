"""Imported client receipts stay scoped and untrusted in saved HTML reports."""
from copy import deepcopy

import pytest

from app.report.evidence import security_agent_rows
from app.report.html import render_report
from app.scan.client_runtime_chain import attach_client_runtime
from app.scan.client_runtime_record import ARCHIVE_SHA256
from tests.test_client_runtime_record import runtime_evidence


def agent_record():
    return {
        "version": 1, "mode": "deterministic_evidence", "status": "completed",
        "automatic_patch": False, "runtime_verified": False,
        "plan": [], "observations": [], "budget": {},
        "source": {"archive_sha256": ARCHIVE_SHA256, "engine_version": "report-test"},
        "stop_reason": "bounded_review_completed",
    }


def accepted_agent():
    agent = agent_record()
    evidence = runtime_evidence()
    assert attach_client_runtime(agent, evidence, run_id=evidence["run_id"])
    return agent


def html(agent):
    return render_report({"score": {"scan_manifest": {"security_agent": agent}}, "findings": []})


def test_saved_client_evidence_is_scoped_and_does_not_claim_execution():
    agent = accepted_agent()
    before = deepcopy(agent)
    rows = dict(security_agent_rows(agent))
    assert "consistency only" in rows["Client runtime evidence"]
    assert "not independent runtime attestation" in rows["Client runtime evidence"]
    assert "12 reported checks passed" in rows["Client runtime scope"]
    assert "No SQL repair proof" in rows["Client runtime scope"]
    assert rows["Client runtime archive SHA-256"] == ARCHIVE_SHA256
    assert rows["Client runtime run"] == agent["client_runtime"]["run_id"]
    assert "scanner did not execute" in rows["Pattern review limits"]
    rendered = html(agent)
    assert "No runtime tests or automatic patches were run" not in rendered
    assert "Customer project runtime tests not run" not in rendered
    assert "No automatic patch applied" in rendered
    assert "Client runtime evidence SHA-256" in rendered
    assert agent == before


@pytest.mark.parametrize("mutate", [
    lambda a: a["client_runtime"].update(runtime_verified=True),
    lambda a: a["client_runtime"].update(evidence_sha256="0" * 64),
    lambda a: a["source"].update(archive_sha256="0" * 64),
    lambda a: a["client_runtime_chain"]["tasks"][1].update(input_sha256="0" * 64),
    lambda a: a["client_runtime"]["evidence"].update(status="failed"),
    lambda a: a.update(client_runtime_status="<script>private-status</script>"),
    lambda a: a["client_runtime"].update(run_id="<script>private-run</script>"),
])
def test_invalid_saved_client_evidence_is_rejected_without_echoing_metadata(mutate):
    agent = accepted_agent()
    mutate(agent)
    rows = dict(security_agent_rows(agent))
    assert "Client runtime evidence unavailable" in rows
    assert "Client runtime evidence" not in rows
    assert "Client runtime run" not in rows
    rendered = html(agent)
    assert "12 reported checks passed" not in rendered
    assert "private-status" not in rendered
    assert "private-run" not in rendered


def test_untrusted_fixture_strings_are_not_rendered_even_in_consistent_evidence():
    agent = agent_record()
    evidence = runtime_evidence()
    # Fixture descriptions are necessary to validate database observations, not
    # useful display metadata. An arbitrary fixture string must never become HTML.
    old = evidence["fixtures"]["original_description"]
    payload = '<img src=x onerror="alert(1)">'

    def replace(value):
        if isinstance(value, dict):
            return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list):
            return [replace(v) for v in value]
        return payload if value == old else value

    evidence = replace(evidence)
    assert attach_client_runtime(agent, evidence, run_id=evidence["run_id"])
    rendered = html(agent)
    assert "12 reported checks passed" in rendered
    assert "onerror" not in rendered


def test_old_reports_without_imported_receipts_keep_existing_limits():
    rows = dict(security_agent_rows(agent_record()))
    assert "No runtime tests or automatic patches were run." in rows["Pattern review limits"]
    assert not any(label.startswith("Client runtime") for label in rows)
