"""Offline transport checks for a billable, one-attempt-only comparison pilot."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import json

import httpx
import pytest

from scripts import evaluate_luna_pilot as pilot


@pytest.fixture
def baseline():
    system = "Historical system prompt.\nDo not alter whitespace.\n"
    cases = []
    rows = []
    for index, case_id in enumerate(pilot.CASE_IDS):
        prompt = f"Saved prompt {index}: café\n\n  exact spacing  \n"
        prompt_hash = pilot.digest(system, prompt)
        cases.append({
            "id": case_id, "prompt": prompt, "prompt_sha256": prompt_hash,
            "files": {f"src/{case_id}.ts": f"export const value = {index};\n"},
            "rubric": "security", "expected_findings": index % 2,
        })
        rows.append({
            "case": case_id, "requested_model": pilot.BASELINE_MODEL, "repeat": 1,
            "prompt_sha256": prompt_hash, "answer": "[" if index == 1 else "[]",
            "error": "incomplete_or_invalid_answer" if index == 1 else None,
            "finish_reason": "length" if index == 1 else "stop",
            "cost_rub": index + 1, "usage": {"completion_tokens": 8192 if index == 1 else 10},
        })
        rows.append({"case": case_id, "requested_model": "mimo-v2.6-pro", "repeat": 1})
    return {
        "suite": "bounded-paired-pilot", "requested_max_tokens": 8192,
        "system_prompt": system, "revision": "historical-revision", "cases": cases,
        "results": rows,
    }


def _prepare(baseline):
    return pilot.prepare(baseline, "a" * 64)


def _response(**overrides):
    return {
        "model": pilot.MODEL,
        "usage": {"cost_rub": "0.1", "prompt_tokens": 20, "completion_tokens": 5,
                  "completion_tokens_details": {"reasoning_tokens": 3}},
        "choices": [{"finish_reason": "stop", "message": {"content": "[]"}}],
        **overrides,
    }


def _read(path):
    return json.loads(path.read_text())


def test_prepare_reuses_exact_prompts_and_preserves_invalid_sonnet_attempt(baseline):
    original = deepcopy(baseline)
    report = _prepare(baseline)
    assert baseline == original
    assert report["baseline_sha256"] == "a" * 64
    assert report["baseline_revision"] == "historical-revision"
    assert len(report["cases"]) == 10
    assert report["results"] == []
    for case, saved in zip(report["cases"], baseline["cases"]):
        assert case["prompt"] == saved["prompt"]
        assert case["system_prompt"] == baseline["system_prompt"]
        assert case["prompt_sha256"] == saved["prompt_sha256"]
        assert case["files"] == saved["files"]
        assert case["comparison"] == "identical_historical_prompt"
    assert report["historical_sonnet"] == original["results"][::2]
    invalid = report["historical_sonnet"][1]
    assert invalid["answer"] == "["
    assert invalid["finish_reason"] == "length"
    assert invalid["error"] == "incomplete_or_invalid_answer"
    assert invalid["cost_rub"] == 2
    report["historical_sonnet"][1]["usage"]["completion_tokens"] = 0
    report["cases"][0]["files"].clear()
    assert baseline == original


@pytest.mark.parametrize("damage", [
    "prompt_hash", "prompt_text", "system_text", "duplicate_case", "duplicate_sonnet",
    "missing_sonnet", "sonnet_hash", "repeat", "output_limit",
])
def test_prepare_rejects_nonmatching_historical_evidence(baseline, damage):
    if damage == "prompt_hash":
        baseline["cases"][0]["prompt_sha256"] = "b" * 64
    elif damage == "prompt_text":
        baseline["cases"][0]["prompt"] += " "
    elif damage == "system_text":
        baseline["system_prompt"] += " "
    elif damage == "duplicate_case":
        baseline["cases"][1] = deepcopy(baseline["cases"][0])
    elif damage == "duplicate_sonnet":
        baseline["results"].append(deepcopy(baseline["results"][0]))
    elif damage == "missing_sonnet":
        baseline["results"].pop(0)
    elif damage == "sonnet_hash":
        baseline["results"][0]["prompt_sha256"] = "b" * 64
    elif damage == "repeat":
        baseline["results"][0]["repeat"] = 2
    else:
        baseline["requested_max_tokens"] = 16384
    with pytest.raises(ValueError):
        _prepare(baseline)


def test_default_cli_prepares_privately_without_reading_key_or_network(baseline, tmp_path, monkeypatch):
    source = tmp_path / "baseline.json"
    source.write_text(json.dumps(baseline))
    output = tmp_path / "prepared.json"

    def forbidden(*args, **kwargs):
        pytest.fail("Prepare-only must not load provider credentials or create a network client")

    monkeypatch.setattr(pilot, "read_values", forbidden)
    monkeypatch.setattr(pilot.httpx, "Client", forbidden)
    class NoProviderKeyRead(dict):
        def get(self, name, default=None):
            if name == "AITUNNEL_API_KEY":
                forbidden()
            return super().get(name, default)

    monkeypatch.setattr(pilot.os, "environ", NoProviderKeyRead(pilot.os.environ))
    assert pilot.main(["--baseline", str(source), "--output", str(output),
                       "--env", str(tmp_path / "unreadable.env")]) == 0
    report = _read(output)
    assert report["state"] == "prepared"
    assert report["results"] == []
    assert report["baseline_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert output.stat().st_mode & 0o777 == 0o600


def test_cli_never_overwrites_prior_results(baseline, tmp_path):
    source = tmp_path / "baseline.json"
    source.write_text(json.dumps(baseline))
    output = tmp_path / "results.json"
    output.write_text("existing attempts must survive")
    with pytest.raises(SystemExit, match="2"):
        pilot.main(["--baseline", str(source), "--output", str(output)])
    assert output.read_text() == "existing attempts must survive"


def test_run_calls_only_luna_once_per_case_and_checkpoints_before_transport(baseline, tmp_path):
    report = _prepare(baseline)
    output = tmp_path / "results.json"
    sent = []

    def respond(request):
        current = _read(output)
        assert current["state"] == "running"
        assert len(current["results"]) == len(sent) + 1
        assert current["results"][-1]["status"] == "in_flight"
        assert current["results"][-1]["cost_rub"] is None
        assert request.url == httpx.URL(pilot.ENDPOINT)
        body = json.loads(request.content)
        case = report["cases"][len(sent)]
        assert body == {
            "model": "gpt-6-luna", "stream": False,
            "max_completion_tokens": 8192, "reasoning_effort": "medium",
            "messages": [{"role": "system", "content": case["system_prompt"]},
                         {"role": "user", "content": case["prompt"]}],
        }
        assert "review_expectation" not in request.content.decode()
        assert request.headers["Authorization"] == "Bearer fake-key"
        sent.append(body)
        return httpx.Response(200, json=_response())

    assert pilot.run(report, "fake-key", output, transport=httpx.MockTransport(respond)) == 0
    saved = _read(output)
    assert len(sent) == len(saved["results"]) == 10
    assert saved["state"] == "completed_needs_review"
    assert Decimal(saved["known_spend_rub"]) == Decimal("1.0")
    assert all(row["requested_model"] == "gpt-6-luna" for row in saved["results"])
    assert saved["results"][0]["usage"]["completion_tokens_details"]["reasoning_tokens"] == 3
    assert saved["results"][0]["answer_characters"] == 2
    assert saved["results"][0]["answer_utf8_bytes"] == 2
    assert "fake-key" not in output.read_text()


@pytest.mark.parametrize("failure, expected_state", [
    ("timeout", "stopped_on_error"),
    ("http", "stopped_on_error"),
    ("redirect", "stopped_on_error"),
    ("missing_cost", "stopped_on_unknown_cost"),
    ("served_model", "stopped_on_served_model_mismatch"),
    ("budget", "stopped_on_budget_exceeded"),
])
def test_failure_persists_single_attempt_without_retry_or_fallback(
    baseline, tmp_path, failure, expected_state,
):
    report = _prepare(baseline)
    output = tmp_path / "results.json"
    requests = []

    def respond(request):
        requests.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("secret-key in exception must not be saved", request=request)
        if failure == "http":
            return httpx.Response(429, text="secret-key in error body")
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://elsewhere.invalid/"})
        if failure == "missing_cost":
            return httpx.Response(200, json=_response(usage={"completion_tokens": 10}))
        if failure == "served_model":
            return httpx.Response(200, json=_response(model=pilot.BASELINE_MODEL))
        return httpx.Response(200, json=_response(usage={"cost_rub": "20.01"}))

    assert pilot.run(report, "secret-key", output, transport=httpx.MockTransport(respond)) == 1
    saved = _read(output)
    assert len(requests) == len(saved["results"]) == 1
    assert saved["state"] == expected_state
    assert saved["results"][0]["status"] == "stopped"
    assert saved["results"][0]["requested_model"] == pilot.MODEL
    assert "secret-key" not in output.read_text()
    if failure == "timeout":
        assert saved["results"][0]["error"] == "ReadTimeout"
        assert saved["results"][0]["cost_rub"] is None
    if failure == "http":
        assert saved["results"][0]["http_status"] == 429
    if failure == "missing_cost":
        assert saved["results"][0]["answer"] == "[]"
        assert saved["results"][0]["cost_rub"] is None
    with pytest.raises(ValueError, match="never be retried"):
        pilot.run(saved, "secret-key", output, transport=httpx.MockTransport(respond))
    assert len(requests) == 1


def test_budget_reserves_next_request_before_sending(baseline, tmp_path):
    report = _prepare(baseline)
    output = tmp_path / "results.json"
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json=_response(usage={"cost_rub": "19.5"}))

    assert pilot.run(report, "fake-key", output, transport=httpx.MockTransport(respond)) == 1
    saved = _read(output)
    assert len(requests) == len(saved["results"]) == 1
    assert saved["state"] == "stopped_before_budget"
    assert saved["known_spend_rub"] == "19.5"


@pytest.mark.parametrize("answer, finish_reason", [("[", "length"), ("not JSON", "stop")])
def test_invalid_model_answer_is_retained_without_retry(baseline, tmp_path, answer, finish_reason):
    report = _prepare(baseline)
    report["cases"] = report["cases"][:2]
    output = tmp_path / "results.json"
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json=_response(choices=[{
            "finish_reason": finish_reason, "message": {"content": answer},
        }]))

    assert pilot.run(report, "fake-key", output, transport=httpx.MockTransport(respond)) == 0
    saved = _read(output)
    assert len(requests) == 2
    assert saved["state"] == "completed_with_errors_needs_review"
    assert [r["case"] for r in saved["results"]] == list(pilot.CASE_IDS[:2])
    assert all(r["answer"] == answer for r in saved["results"])
    assert all(r["error"] == "incomplete_or_invalid_answer" for r in saved["results"])


@pytest.mark.parametrize("value", [True, -1, "NaN", "Infinity", "-Infinity", None, {}])
def test_invalid_provider_charge_is_never_treated_as_free(value):
    assert pilot.amount(value) is None
