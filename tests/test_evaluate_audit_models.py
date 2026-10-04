import json

import httpx

from scripts import evaluate_audit_models as trial


def test_prepare_never_calls_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(trial, "run", lambda *a: (_ for _ in ()).throw(AssertionError("paid call")))
    output = tmp_path / "prepared.json"
    assert trial.main(["--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert len(report["cases"]) == 6
    assert report["results"] == []
    assert all("positive/" not in c["prompt"] and "negative/" not in c["prompt"]
               for c in report["cases"])


def test_same_prompts_no_fallback_and_usage_retained_on_invalid_output(tmp_path):
    requests = []

    def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(200, json={
            "model": body["model"], "usage": {"prompt_tokens": 100, "completion_tokens": 40,
                                               "completion_tokens_details": {"reasoning_tokens": 30}},
            "cost_rub": 0.1,
            "choices": [{"finish_reason": "stop", "message": {
                "content": "[]" if len(requests) < 3 else "invalid"}}]})

    output = tmp_path / "trial.json"
    report = trial.prepare()
    assert trial.run(report, "synthetic", output, 4096, httpx.MockTransport(respond)) == 1
    assert len(requests) == 3  # fail closed, no retry, no fallback
    assert requests[0]["messages"] == requests[1]["messages"] == requests[2]["messages"]
    saved = json.loads(output.read_text())
    assert saved["state"] == "stopped_on_error"
    assert len(saved["results"]) == 3
    assert saved["results"][-1]["usage"]["completion_tokens_details"]["reasoning_tokens"] == 30
    assert saved["results"][-1]["cost_rub"] == 0.1
    assert not saved["results"][-1]["strict_json_array"]
    assert all(r["manual_verdict"] is None for r in saved["results"])


def test_quote_validation_does_not_label_truth():
    finding = {"file": "app.py", "line_start": 1, "line_end": 1,
               "evidence": "invented", "severity": "high", "confidence": 0.9,
               "title": "Claim", "explanation": "Claim"}
    result = trial.assess(json.dumps([finding]), {"app.py": "print('hello')"})
    assert result["strict_json_array"]
    assert result["quote_checks"] == ["source_quote_or_location_mismatch"]
    assert not trial.assess('```json\n[]\n```', {})["strict_json_array"]
    assert trial.assess("[]", {}) == {"strict_json_array": True, "quote_checks": []}


def test_context_preserves_baseline_and_shares_callers():
    baseline = trial.prepare()
    extended = trial.prepare("context", 3)
    assert extended["cases"][:6] == baseline["cases"]
    assert len(extended["cases"]) == 10
    cases = {c["id"]: c for c in extended["cases"]}
    for family in ("sql", "yaml"):
        risk = cases[family + "-risk-http"]
        control = cases[family + "-control-http"]
        assert risk["files"]["app/routes.py"] == control["files"]["app/routes.py"]
        assert len(risk["files"]) == 2
        assert risk["prompt_sha256"] != cases[family + "-risk"]["prompt_sha256"]
    assert cases["yaml-control"]["prompt_sha256"] == "2c85017753342a1f0cd7dd5d79b3b0c2e9738cd09daf7f19b1279a6bc09f6c54"


def test_repeats_rotation_and_nested_cost(tmp_path):
    def respond(request):
        body = json.loads(request.content)
        return httpx.Response(200, json={
            "model": body["model"], "usage": {"cost_rub": 0}, "cost_rub": 100,
            "choices": [{"finish_reason": "stop", "message": {"content": "[]"}}]})

    report = trial.prepare("context", 3)
    assert trial.run(report, "synthetic", tmp_path / "results.json", 4096,
                     httpx.MockTransport(respond)) == 0
    rows = report["results"]
    assert len(rows) == 90
    assert len({(r["case"], r["requested_model"], r["repeat"]) for r in rows}) == 90
    assert all(r["cost_rub"] == 0 for r in rows)
    assert all(r["manual_verdict"] is None for r in rows)
    for repeat in range(1, 4):
        first_case = [r["requested_model"] for r in rows if r["repeat"] == repeat][:3]
        assert first_case == list(trial.MODELS[repeat - 1:] + trial.MODELS[:repeat - 1])
