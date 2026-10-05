"""No paid calls: actual production payload/response handling via MockTransport."""
import json
from decimal import Decimal
import time
import zipfile

import httpx
import pytest

from app.llm.client import LLMError
from scripts import evaluate_luna_repository as trial


def response(*, cost="0.5", text="[]", finish="stop"):
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    if cost is not None:
        usage["cost_rub"] = cost
    return {"model": trial.MODEL, "usage": usage,
            "choices": [{"finish_reason": finish, "message": {"content": text}}]}


def client(tmp_path, handler, budget=50):
    result = {"requests": [], "known_spend_rub": "0", "unknown_charge_count": 0}
    path = tmp_path / "result.json"
    obj = trial.TrialClient("private-key", result, path, Decimal(budget), time.monotonic() + 1200,
                            transport=httpx.MockTransport(handler))
    return obj, result, path


def test_one_call_production_payload_and_private_checkpoint(tmp_path):
    def handler(request):
        saved = json.loads(path.read_text())
        assert saved["requests"][0]["state"] == "in_flight"
        payload = json.loads(request.content)
        assert payload["model"] == trial.MODEL
        assert payload["max_completion_tokens"] == 8192
        assert payload["reasoning_effort"] == "medium"
        assert "temperature" not in payload and "max_tokens" not in payload
        return httpx.Response(200, json=response())
    obj, result, path = client(tmp_path, handler)
    answer, usage = obj.complete("system", "user", 8192)
    assert answer == "[]" and usage.model == trial.MODEL
    assert len(result["requests"]) == 1
    assert result["known_spend_rub"] == "0.5"
    assert path.stat().st_mode & 0o777 == 0o600
    assert "private-key" not in path.read_text()


@pytest.mark.parametrize("kind", ["timeout", "invalid_json", "length", "unknown_cost", "http500"])
def test_failure_stops_without_retry_or_fallback_retains_charges(tmp_path, kind):
    calls = []
    def handler(request):
        calls.append(request)
        if kind == "timeout":
            raise httpx.ReadTimeout("PRIVATE ERROR BODY")
        if kind == "http500":
            return httpx.Response(500, json={"error": "PRIVATE ERROR BODY", "usage": {"cost_rub": "0.7"}})
        data = response(cost=None if kind == "unknown_cost" else "0.5",
                        text="invalid" if kind == "invalid_json" else "[]",
                        finish="length" if kind == "length" else "stop")
        return httpx.Response(200, json=data)
    obj, result, path = client(tmp_path, handler)
    for _ in range(2):
        with pytest.raises(LLMError):
            obj.complete("system", "user", 8192)
    assert len(calls) == 1
    assert result["unknown_charge_count"] == (1 if kind in {"timeout", "unknown_cost"} else 0)
    assert Decimal(result["known_spend_rub"]) == (
        Decimal("0") if kind in {"timeout", "unknown_cost"} else Decimal("0.7" if kind == "http500" else "0.5"))
    assert "PRIVATE ERROR BODY" not in path.read_text()
    if kind == "length":
        assert result["requests"][0]["attempts"][0]["finish_reason"] == "length"
        assert result["requests"][0]["answer"] == "[]"


def test_admission_and_deadline_before_http(tmp_path):
    def handler(request):
        pytest.fail("No request may be sent")
    obj, result, path = client(tmp_path, handler, budget="0.01")
    with pytest.raises(LLMError, match="admission_budget"):
        obj.complete("system", "user", 8192)
    assert result["requests"] == []
    obj, result, path = client(tmp_path, handler)
    obj.deadline = time.monotonic() - 1
    with pytest.raises(LLMError, match="time_limit"):
        obj.complete("system", "user", 8192)
    assert result["requests"] == []


def arguments(tmp_path):
    archive, output = tmp_path / "repo.zip", tmp_path / "result.json"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("repo-root/main.py", "print('hello')\n")
    return ["--archive", str(archive), "--repo", "owner/repo", "--revision", "a" * 40,
            "--json", str(output)], output


def test_dry_run_never_reads_credentials_or_network_and_refuses_reuse(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Dry-run must never read credentials or send HTTP")
    monkeypatch.setattr(trial, "read_values", forbidden)
    monkeypatch.setattr(trial.TrialClient, "_request", forbidden)
    args, path = arguments(tmp_path)
    assert trial.main(args) == 0
    result = json.loads(path.read_text())
    assert result["state"] == "prepared_no_paid_calls"
    assert result["known_spend_rub"] == "0"
    with pytest.raises(FileExistsError):
        trial.main(args)


def test_digest_mismatch_blocks_even_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(trial, "read_values", lambda *a: pytest.fail("must not read keys"))
    args, path = arguments(tmp_path)
    with pytest.raises(SystemExit):
        trial.main(args + ["--execute", "--expected-content-hash", "b" * 64])
    assert not path.exists()


def test_execute_full_scan_schema_two_passes_and_no_remote_stages(tmp_path, monkeypatch):
    args, path = arguments(tmp_path)
    monkeypatch.setenv("AITUNNEL_API_KEY", "fake-only")
    def scan(data, llm, **kwargs):
        assert kwargs == {"llm_passes": 2, "sca_client": None,
                          "synthetic_sql_executor": None, "llm_cost_cap": Decimal(13)}
        llm.complete("system", "user", 8192)
        return {"llm": {"calls": 1}, "findings": [], "coverage": {"status": "partial"}}
    monkeypatch.setattr(trial, "run_scan", scan)
    monkeypatch.setattr(trial.TrialClient, "_request", lambda *a: response())
    assert trial.main(args + ["--execute"]) == 0
    result = json.loads(path.read_text())
    assert result["scan"]["coverage"] == {"status": "partial"}
    assert result["state"] == "completed_needs_review"
    assert result["passes"] == 2
    assert result["engine_version"] == trial.PIPELINE_ENGINE_VERSION
    assert result["model_policy_identity"].startswith(trial.AUDIT_ENGINE_VERSION + "-luna-")
    assert result["known_spend_rub"] == "0.5"


def test_deadline_interrupts_inflight_and_checkpoints_unknown_charge(tmp_path, monkeypatch):
    import signal
    args, path = arguments(tmp_path)
    monkeypatch.setenv("AITUNNEL_API_KEY", "fake-only")
    original_handler = signal.getsignal(signal.SIGALRM)
    def scan(data, llm, **kwargs):
        llm.complete("system", "user", 8192)
        pytest.fail("Deadline must escape scanner")
    def request(*args):
        trial.deadline_handler(signal.SIGALRM, None)
    monkeypatch.setattr(trial, "run_scan", scan)
    monkeypatch.setattr(trial.TrialClient, "_request", request)
    assert trial.main(args + ["--execute"]) == 1
    result = json.loads(path.read_text())
    assert result["state"] == "stopped_on_timeout"
    assert result["unknown_charge_count"] == 1
    assert result["requests"][0]["state"] == "interrupted_charge_unknown"
    assert signal.getsignal(signal.SIGALRM) == original_handler
    assert signal.getitimer(signal.ITIMER_REAL)[0] == 0


def test_call_limit_and_long_context_reservation(tmp_path):
    obj, result, _ = client(tmp_path, lambda request: pytest.fail("Call limit must stop before network"))
    result["requests"] = [{} for _ in range(trial.MAX_CALLS)]
    with pytest.raises(LLMError, match="call_limit"):
        obj.complete("system", "user", 8192)
    assert trial.reservation("", "a" * (272000 - 1024)) == Decimal("7.6192")
    assert trial.reservation("", "a" * (272001 - 1024)) == Decimal("14.82885")


def test_engine_provenance_matches_actual_scan_manifest(tmp_path, monkeypatch):
    args, path = arguments(tmp_path)
    actual_scan = trial.run_scan
    captured = {}
    def scan(*args, **kwargs):
        result = actual_scan(*args, **kwargs)
        captured["engine"] = result["score"]["scan_manifest"]["engine_version"]
        return result
    monkeypatch.setattr(trial, "run_scan", scan)
    assert trial.main(args) == 0
    result = json.loads(path.read_text())
    assert result["engine_version"] == captured["engine"]
    assert result["model_policy_identity"] == trial.engine_identity()
    assert result["dry_run"]["synthetic_empty_answers_only"] is True
