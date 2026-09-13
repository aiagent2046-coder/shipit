"""A replay rejects different evidence and cannot fall back to a live provider."""
from copy import deepcopy
import hashlib

import httpx
import pytest

from app.llm.client import LLMUsage
from app.scan.pipeline import run_scan
from scripts import replay_saved_trial as r
from tests.test_audit_llm_wiring import FakeLLM, make_zip


@pytest.fixture
def trial():
    data = make_zip({"app/api/auth.ts": b"export function login(req) { return req.user; }"}).getvalue()
    calls = []

    class Recorder(FakeLLM):
        def complete(self, system, user, max_tokens=4096):
            calls.append({
                "slot": 1, "request": {"rubric": "auth", "pass": 1, "max_tokens": max_tokens,
                    "messages_sha256": r.canonical_sha256([
                        {"role": "system", "content": system}, {"role": "user", "content": user}])},
                "response": {"http_status": 200, "reported_model": "fixture-model", "answer_text": "[]",
                    "finish_reason": "stop", "numeric_usage_details": {"prompt_tokens": 4000, "completion_tokens": 2}},
            })
            return "[]", LLMUsage("fixture-model", 4000, 2)

    client = Recorder()
    run_scan(data, client, llm_rubrics=("auth",))
    assert len(calls) == 1
    return {"input": {"archive_sha256": hashlib.sha256(data).hexdigest()}, "passes": 1, "rubrics": ["auth"],
            "models": [{"model": "fixture-model", "effective_input_char_budget": client.input_char_budget(),
                        "calls": calls}]}, data


def test_exact_saved_run_preserves_usage_but_reports_no_new_spend(trial):
    report, data = trial
    snapshot = deepcopy(report)
    result = r.replay(report, data)
    assert report == snapshot
    assert result["new_network_attempts"] == 0 and result["new_cost_rub"] == "0"
    model, = result["models"]
    assert model["reused_responses"] == 1 and model["prompt_checks"][0]["matches_saved_request"]
    assert model["scan"]["llm"]["input_tokens"] == 4000


def test_wrong_archive_is_rejected_before_pipeline(trial, monkeypatch):
    report, data = trial
    monkeypatch.setattr(r, "run_scan", lambda *a, **kw: pytest.fail("pipeline must not run"))
    with pytest.raises(r.ReplayMismatch, match="Archive SHA"):
        r.replay(report, data + b"different")


def test_prompt_drift_escapes_provider_failure_fallback(trial):
    report, data = trial
    report["models"][0]["calls"][0]["request"]["messages_sha256"] = "0" * 64
    with pytest.raises(r.ReplayMismatch, match="Saved request mismatch"):
        r.replay(report, data)


def test_saved_failure_does_not_turn_into_an_empty_success(trial):
    report, data = trial
    report.update(state="COMPARISON_INCOMPLETE", full_comparison_complete=False)
    model = report["models"][0]
    model.update(state="INCOMPLETE", stop_reason="REASONING_LIMIT_WITHOUT_ANSWER",
                 scan={"llm": {"failure": "TRIAL_STOPPED_ValueError"}})
    call = model["calls"][0]
    call["response_issue"] = "REASONING_LIMIT_WITHOUT_ANSWER"
    call["response"].update(answer_text=None, finish_reason="length")
    result = r.replay(report, data)
    model, = result["models"]
    assert model["reused_responses"] == 1
    assert result["saved_trial_state"] == "COMPARISON_INCOMPLETE"
    assert result["saved_full_comparison_complete"] is False
    assert model["saved_state"] == "INCOMPLETE"
    assert model["saved_stop_reason"] == "REASONING_LIMIT_WITHOUT_ANSWER"
    assert model["scan"]["llm"]["failure"] == "TRIAL_STOPPED_ValueError"
    assert model["scan"]["llm"]["calls"] == 0


def test_network_attempt_fails_replay_even_when_product_swallows_exception(trial, monkeypatch):
    report, data = trial

    def bad_pipeline(*args, **kwargs):
        scan = run_scan(*args, **kwargs)
        try:
            httpx.get("https://offline.invalid", trust_env=False)
        except r.ReplayMismatch:
            pass
        return scan

    monkeypatch.setattr(r, "run_scan", bad_pipeline)
    with pytest.raises(r.ReplayMismatch, match="attempted networking"):
        r.replay(report, data)
