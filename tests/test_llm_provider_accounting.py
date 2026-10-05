"""Provider spend survives failed answers, retry and fallback without live APIs."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import httpx
import pytest

from app.llm.client import LLMClient, LLMError, Provider


PRIMARY = Provider("openai_compat", "https://api.aitunnel.ru/v1", "secret-key",
                   "claude-sonnet-4.6")
FALLBACK = Provider("anthropic", "https://api.anthropic.com", "other-secret",
                    "claude-sonnet-4-6")


def answer(*, usage=None, content="[]", finish="stop"):
    return {
        "model": PRIMARY.model,
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
        "usage": usage,
    }


def client_for(body):
    return LLMClient([PRIMARY], httpx.MockTransport(
        lambda request: httpx.Response(200, json=body)))


def test_reported_zero_cost_and_cache_counters_survive_without_private_fields():
    client = client_for(answer(usage={
        "prompt_tokens": 100, "completion_tokens": 8, "cost_rub": "0.000",
        "prompt_tokens_details": {"cached_tokens": 90, "cache_write_tokens": 0},
        "completion_tokens_details": {"reasoning_tokens": 0},
        "balance": 9000, "private": "customer code",
    }))
    text, usage = client.complete("s", "u")
    assert text == "[]"
    assert (usage.input_tokens, usage.output_tokens) == (100, 8)
    assert len(usage.attempts) == 1
    row = usage.attempts[0]
    assert row == {
        "provider_kind": "openai_compat", "requested_model": PRIMARY.model,
        "model": PRIMARY.model, "input_tokens": 100, "output_tokens": 8,
        "cached_tokens": 90, "cache_write_tokens": 0, "reasoning_tokens": 0,
        "cost_rub": "0", "finish_reason": "stop", "error": None,
        "seconds": row["seconds"],
    }
    assert row["seconds"] >= 0
    encoded = json.dumps(row, allow_nan=False)
    assert "secret" not in encoded and "customer code" not in encoded


def test_absent_usage_is_unknown_in_ledger_and_legacy_counts_stay_zero():
    _, usage = client_for(answer()).complete("s", "u")
    assert usage.input_tokens == usage.output_tokens == 0
    row = usage.attempts[0]
    for key in ("input_tokens", "output_tokens", "cached_tokens",
                "cache_write_tokens", "reasoning_tokens", "cost_rub"):
        assert row[key] is None


@pytest.mark.parametrize("nested", [{}, {"cost_rub": None}, None])
def test_top_level_cost_is_used_when_nested_cost_is_absent_or_null(nested):
    body = answer(usage=nested)
    body["cost_rub"] = "2.3400"
    _, usage = client_for(body).complete("s", "u")
    assert usage.attempts[0]["cost_rub"] == "2.34"


@pytest.mark.parametrize("nested, expected", [(0, "0"), ("NaN", None), (True, None)])
def test_present_nested_cost_is_authoritative_over_top_level(nested, expected):
    body = answer(usage={"cost_rub": nested})
    body["cost_rub"] = "9.87"
    _, usage = client_for(body).complete("s", "u")
    assert usage.attempts[0]["cost_rub"] == expected


@pytest.mark.parametrize("bad", [True, False, "NaN", "Infinity", "-Infinity",
                                    -1, "-0.01", {}, [], "bad", "1e999999"])
def test_malformed_usage_values_are_ignored_without_breaking_completion(bad):
    _, usage = client_for(answer(usage={
        "prompt_tokens": bad, "completion_tokens": bad, "cost_rub": bad,
        "prompt_tokens_details": {"cached_tokens": bad, "cache_write_tokens": bad},
        "completion_tokens_details": {"reasoning_tokens": bad},
    })).complete("s", "u")
    assert usage.input_tokens == usage.output_tokens == 0
    for key in ("input_tokens", "output_tokens", "cached_tokens",
                "cache_write_tokens", "reasoning_tokens", "cost_rub"):
        assert usage.attempts[0][key] is None
    json.dumps(usage.attempts, allow_nan=False)


@pytest.mark.parametrize("bad", [42, True, "usage", [1]])
def test_malformed_usage_object_is_nonfatal(bad):
    _, usage = client_for(answer(usage=bad)).complete("s", "u")
    assert usage.attempts[0]["cost_rub"] is None


def test_empty_billed_answer_remains_in_ledger_after_anthropic_fallback():
    hosts = []

    def handler(request):
        hosts.append(request.url.host)
        if len(hosts) == 1:
            return httpx.Response(200, json=answer(
                content=None, finish="length", usage={
                    "prompt_tokens": 200, "completion_tokens": 8192,
                    "cost_rub": 4.35,
                    "completion_tokens_details": {"reasoning_tokens": 8191},
                }))
        return httpx.Response(200, json={
            "model": FALLBACK.model, "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "[]"}],
            "usage": {"input_tokens": 100, "output_tokens": 2,
                      "cache_read_input_tokens": 80, "cache_creation_input_tokens": 20},
        })

    text, usage = LLMClient([PRIMARY, FALLBACK], httpx.MockTransport(handler)).complete("s", "u")
    assert text == "[]" and len(hosts) == 2  # Empty answer is not retried.
    failed, succeeded = usage.attempts
    assert failed["cost_rub"] == "4.35"
    assert failed["output_tokens"] == 8192
    assert failed["finish_reason"] == "length"
    assert failed["error"] == "ValueError"
    assert succeeded["cached_tokens"] == 80
    assert succeeded["cache_write_tokens"] == 20
    assert succeeded["cost_rub"] is None
    assert usage.model == FALLBACK.model and usage.input_tokens == 100


def test_timeout_unknown_cost_retry_success_records_both_attempts(monkeypatch):
    sleeps, requests = [], []
    monkeypatch.setattr("app.llm.client.time.sleep", sleeps.append)

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ReadTimeout("private body with secret-key", request=request)
        return httpx.Response(200, json=answer(usage={"cost_rub": "1.2300"}))

    _, usage = LLMClient([PRIMARY], httpx.MockTransport(handler)).complete("s", "u")
    assert sleeps == [2.0]
    assert [a["cost_rub"] for a in usage.attempts] == [None, "1.23"]
    assert [a["error"] for a in usage.attempts] == ["ReadTimeout", None]
    assert "secret-key" not in json.dumps(usage.attempts)


def test_final_failure_retains_every_attempt_and_reported_error_response_cost(monkeypatch):
    monkeypatch.setattr("app.llm.client.time.sleep", lambda seconds: None)
    client = LLMClient([PRIMARY], httpx.MockTransport(lambda request: httpx.Response(
        503, json={"usage": {"cost_rub": "0.50"}, "error": "private code"})))
    with pytest.raises(LLMError) as caught:
        client.complete("s", "u")
    assert len(caught.value.attempts) == 3
    assert all(a["cost_rub"] == "0.5" and a["error"] == "http_503"
               for a in caught.value.attempts)
    assert "private code" not in json.dumps(caught.value.attempts)
    assert LLMError("legacy").attempts == ()


def test_malformed_response_shape_preserves_received_usage():
    client = client_for({"choices": None, "usage": {"cost_rub": 2}})
    with pytest.raises(LLMError) as caught:
        client.complete("s", "u")
    assert caught.value.attempts[0]["cost_rub"] == "2"


def test_shared_client_does_not_mix_concurrent_ledgers():
    barrier = Barrier(2)

    def handler(request):
        body = json.loads(request.content)
        cost = body["messages"][1]["content"]
        barrier.wait(timeout=5)
        return httpx.Response(200, json=answer(usage={"cost_rub": cost}))

    client = LLMClient([PRIMARY], httpx.MockTransport(handler))
    with ThreadPoolExecutor(max_workers=2) as pool:
        usages = list(pool.map(lambda cost: client.complete("s", cost)[1], ["1", "2"]))
    assert [[a["cost_rub"] for a in u.attempts] for u in usages] == [["1"], ["2"]]


@pytest.mark.parametrize("enabled", [None, "0", "true", "1"])
def test_cache_is_opt_in_and_preserves_exact_prompt_text(monkeypatch, enabled):
    monkeypatch.delenv("AITUNNEL_PROMPT_CACHE", raising=False)
    if enabled is not None:
        monkeypatch.setenv("AITUNNEL_PROMPT_CACHE", enabled)
    system, user = "system\n\n rules", "source\tcode\n"
    payload = LLMClient._payload_openai(PRIMARY, system, user, 8192)
    for message, text in zip(payload["messages"], [system, user]):
        expected = ([{"type": "text", "text": text,
                      "cache_control": {"type": "ephemeral"}}]
                    if enabled == "1" else text)
        assert message["content"] == expected


@pytest.mark.parametrize("provider", [
    replace(PRIMARY, model="claude-haiku-4.5"),
    replace(PRIMARY, model="mimo-v2.6-pro"),
    replace(PRIMARY, model="claude-sonnet-5"),
    replace(PRIMARY, base_url="https://other.example/v1"),
    replace(PRIMARY, base_url="https://api.aitunnel.ru.example/v1"),
    replace(PRIMARY, base_url="http://api.aitunnel.ru/v1"),
    replace(PRIMARY, kind="anthropic"),
    FALLBACK,
])
def test_cache_does_not_change_unrelated_providers_or_models(monkeypatch, provider):
    monkeypatch.setenv("AITUNNEL_PROMPT_CACHE", "1")
    payload = LLMClient._payload_openai(provider, "s", "u", 8192)
    assert [m["content"] for m in payload["messages"]] == ["s", "u"]
    assert "cache_control" not in json.dumps(LLMClient._payload_anthropic(provider, "s", "u", 8192))


def test_direct_call_keeps_legacy_return_shape():
    text, usage = client_for(answer(usage={"prompt_tokens": "12"}))._call(PRIMARY, "s", "u", 4096)
    assert text == "[]" and usage.input_tokens == 12
    assert len(usage.attempts) == 1
