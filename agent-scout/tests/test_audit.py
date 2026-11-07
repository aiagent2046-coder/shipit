"""Active audit tests: the gate runs first, the shipped pipeline runs for
real (offline), and no inventory leaves for a third party without opt-in.

The real pipeline test is deliberately offline: no LLM providers (the
monkeypatched env guarantees it), no SCA client - exactly the honest
degradation path a contract report must show as its basis.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from scout import audit, guard, paths

FIXTURE = {"requirements.txt": b"langflow==1.2.0\n"}


@pytest.fixture
def auth_dir(tmp_path, monkeypatch):
    path = tmp_path / "authorizations"
    monkeypatch.setattr(guard, "AUTH_DIR", path)
    return path


@pytest.fixture
def contract(auth_dir):
    return guard.activate("c-1", scope=["db.target.example"], hours=24)


@pytest.fixture
def no_llm_providers(monkeypatch):
    """Providers must never leak into tests - an audit run costs money."""
    paths.bootstrap()
    import app.llm.client as llm_client_mod
    monkeypatch.setattr(llm_client_mod, "providers_from_env", list)


def test_run_audit_refuses_without_authorization(auth_dir, no_llm_providers):
    with pytest.raises(guard.ActiveModeUnauthorised):
        audit.run_audit("c-none", FIXTURE)


def test_run_audit_refuses_empty_artifacts(contract, no_llm_providers):
    with pytest.raises(ValueError, match="no artifacts"):
        audit.run_audit("c-1", {})


def test_run_audit_runs_full_pipeline_offline(contract, no_llm_providers):
    report = audit.run_audit("c-1", FIXTURE, target="github.com/o/r")
    result = report["result"]
    assert report["contract_id"] == "c-1"
    assert report["target"] == "github.com/o/r"
    assert isinstance(result["findings"], list)
    assert "score" in result
    # the honesty contract travels: the stage that never ran says so
    assert result["llm"]["skipped_reason"] == "no_providers_configured"
    assert result["llm"]["calls"] == 0
    assert result["sca"]["skipped_reason"] == "no_client"


def test_run_audit_sends_inventory_only_on_opt_in(contract, no_llm_providers,
                                                 monkeypatch):
    paths.bootstrap()
    import app.sca.stage as sca_stage_mod
    import app.scan.pipeline as pipeline_mod
    calls = []

    def fake_sca_client_for(*, paid, opt_out=False, requested=None):
        calls.append((paid, requested))

    def fake_run_scan(data, llm_client, **kwargs):
        return {"findings": [], "score": {}, "llm": {}, "llm_usage": None, "sca": {}}
    monkeypatch.setattr(sca_stage_mod, "sca_client_for", fake_sca_client_for)
    monkeypatch.setattr(pipeline_mod, "run_scan", fake_run_scan)

    audit.run_audit("c-1", FIXTURE)
    assert calls == [(True, False)]  # someone else's repository: send nothing
    calls.clear()
    audit.run_audit("c-1", FIXTURE, osv=True)
    assert calls == [(True, True)]  # explicit opt-in only


def test_run_audit_passes_llm_cost_cap(contract, no_llm_providers, monkeypatch):
    paths.bootstrap()
    import app.scan.pipeline as pipeline_mod
    captured = []

    def fake_run_scan(data, llm_client, **kwargs):
        captured.append(kwargs)
        return {"findings": [], "score": {}, "llm": {}, "llm_usage": None, "sca": {}}
    monkeypatch.setattr(pipeline_mod, "run_scan", fake_run_scan)

    audit.run_audit("c-1", FIXTURE, llm_cost_cap=Decimal("2.50"))
    assert captured[-1]["llm_cost_cap"] == Decimal("2.50")
    audit.run_audit("c-1", FIXTURE)
    assert "llm_cost_cap" not in captured[-1]  # no cap means no cap


def test_run_audit_gates_before_anything(auth_dir, no_llm_providers, monkeypatch):
    paths.bootstrap()
    import app.scan.pipeline as pipeline_mod

    def boom(*args, **kwargs):
        raise AssertionError("the pipeline must not run without authorization")
    monkeypatch.setattr(pipeline_mod, "run_scan", boom)
    with pytest.raises(guard.ActiveModeUnauthorised):
        audit.run_audit("c-none", FIXTURE)


def test_run_audit_missing_pipeline_deps_is_honest(contract, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "app.llm.client", None)  # import halted
    with pytest.raises(RuntimeError, match=r"pip install -e '\.\[active\]'"):
        audit.run_audit("c-1", FIXTURE)
