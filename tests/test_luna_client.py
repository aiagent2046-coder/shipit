"""Opt-in Luna uses its own wire contract without changing Sonnet or billing."""

import json
from dataclasses import replace

import httpx
import pytest

from app.llm.client import (
    LLMClient,
    LLMError,
    Provider,
    input_char_budget,
    providers_from_env,
    supports_sampling_params,
)


LUNA = Provider("openai_compat", "https://api.aitunnel.ru/v1", "test-key",
                "gpt-6-luna")
SONNET = Provider("anthropic", "https://api.anthropic.com", "test-fallback",
                  "claude-sonnet-4-6")
ALIASES = ("gpt-6-luna", "openai/gpt-6-luna")


def response(*, model="gpt-6-luna", content="[]", finish="stop", usage=None):
    return {
        "model": model,
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
        "usage": usage,
    }


@pytest.mark.parametrize("model", ALIASES)
@pytest.mark.parametrize("cache", ["0", "1"])
def test_luna_request_preserves_prompts_and_bounds_reasoning_and_answer(model, cache,
                                                                       monkeypatch):
    monkeypatch.setenv("AITUNNEL_PROMPT_CACHE", cache)
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(200, json=response(model=model))

    client = LLMClient([replace(LUNA, model=model)], httpx.MockTransport(handler))
    assert client.complete("system\nточно", "user\ncode", max_tokens=8192)[0] == "[]"
    assert requests == [{
        "model": model,
        "max_completion_tokens": 8192,
        "reasoning_effort": "medium",
        "messages": [
            {"role": "system", "content": "system\nточно"},
            {"role": "user", "content": "user\ncode"},
        ],
    }]
    assert not supports_sampling_params(model)


@pytest.mark.parametrize("model", ALIASES)
def test_luna_keeps_conservative_window_for_single_and_fallback_chains(model):
    expected = (200_000 - 8192) * 3
    assert input_char_budget(model) == expected
    assert LLMClient([replace(LUNA, model=model), SONNET]).input_char_budget() == expected


def test_opt_in_provider_model_does_not_change_direct_anthropic_or_default(monkeypatch):
    monkeypatch.setenv("AITUNNEL_API_KEY", "test-primary")
    monkeypatch.setenv("AITUNNEL_BASE_URL", "https://api.aitunnel.ru/v1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fallback")
    for name in ("LLM_MODEL", "AITUNNEL_LLM_MODEL", "ANTHROPIC_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    assert [p.model for p in providers_from_env()] == [
        "claude-sonnet-4-6", "claude-sonnet-4-6",
    ]
    monkeypatch.setenv("AITUNNEL_LLM_MODEL", "gpt-6-luna")
    assert [p.model for p in providers_from_env()] == ["gpt-6-luna", SONNET.model]


@pytest.mark.parametrize("model", ALIASES)
def test_luna_is_rejected_on_direct_anthropic_before_any_http(model):
    provider = replace(SONNET, model=model)
    with pytest.raises(ValueError):
        LLMClient._payload_anthropic(provider, "s", "u", 8192)

    def forbidden_http(request):
        pytest.fail("Direct Anthropic must reject Luna before sending HTTP")

    client = LLMClient([provider], httpx.MockTransport(forbidden_http))
    with pytest.raises(LLMError) as caught:
        client.complete("s", "u", 8192)
    assert len(caught.value.attempts) == 1
    assert caught.value.attempts[0]["cost_rub"] is None


def test_luna_retains_reported_cost_and_reasoning_without_double_counting_output():
    body = response(usage={
        "prompt_tokens": 15025,
        "completion_tokens": 3394,
        "prompt_tokens_details": {"cached_tokens": 1461, "cache_write_tokens": 13561},
        "completion_tokens_details": {"reasoning_tokens": 2821},
        "cost_rub": "0.6900",
    })
    client = LLMClient([LUNA], httpx.MockTransport(
        lambda request: httpx.Response(200, json=body)))
    _, usage = client.complete("s", "u")
    assert (usage.model, usage.input_tokens, usage.output_tokens) == (
        "gpt-6-luna", 15025, 3394,
    )
    assert len(usage.attempts) == 1
    row = usage.attempts[0]
    assert {key: row[key] for key in (
        "cached_tokens", "cache_write_tokens", "reasoning_tokens", "output_tokens",
        "cost_rub", "finish_reason", "error",
    )} == {
        "cached_tokens": 1461, "cache_write_tokens": 13561,
        "reasoning_tokens": 2821, "output_tokens": 3394,
        "cost_rub": "0.69", "finish_reason": "stop", "error": None,
    }


def test_luna_failure_falls_back_with_original_prompt_and_provider_specific_parameters():
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        if request.url.host == "api.aitunnel.ru":
            return httpx.Response(400, json={"error": "invalid request"})
        return httpx.Response(200, json={
            "model": SONNET.model,
            "content": [{"type": "text", "text": "[]"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 20, "output_tokens": 2},
        })

    client = LLMClient([LUNA, SONNET], httpx.MockTransport(handler))
    text, usage = client.complete("unchanged system", "unchanged source", 8192)
    assert text == "[]"
    assert requests == [
        {
            "model": LUNA.model, "max_completion_tokens": 8192,
            "reasoning_effort": "medium", "messages": [
                {"role": "system", "content": "unchanged system"},
                {"role": "user", "content": "unchanged source"},
            ],
        },
        {
            "model": SONNET.model, "max_tokens": 8192, "temperature": 0,
            "system": "unchanged system",
            "messages": [{"role": "user", "content": "unchanged source"}],
        },
    ]
    assert usage.model == SONNET.model
    assert len(usage.attempts) == 2
    assert usage.attempts[0]["error"] == "http_400"
    assert usage.attempts[0]["cost_rub"] is None
    assert usage.attempts[1]["error"] is None


def test_sonnet_prompt_cache_and_generation_contract_stay_unchanged(monkeypatch):
    monkeypatch.setenv("AITUNNEL_PROMPT_CACHE", "1")
    provider = replace(LUNA, model="claude-sonnet-4.6")
    assert LLMClient._payload_openai(provider, "system", "user", 4096) == {
        "model": provider.model, "max_tokens": 4096, "temperature": 0,
        "messages": [
            {"role": role, "content": [{
                "type": "text", "text": content,
                "cache_control": {"type": "ephemeral"},
            }]}
            for role, content in (("system", "system"), ("user", "user"))
        ],
    }


@pytest.mark.parametrize("bad_response", [
    response(content="[]", finish="length"),
    response(content="[]", finish="content_filter"),
    response(content="[]", finish=None),
    response(model="unexpected-provider-model"),
    response(model=None),
    response(model=""),
    {"model": "gpt-6-luna", "choices": [{"finish_reason": "stop", "message": {
        "content": "[]", "refusal": "Cannot complete this request",
    }}]},
])
def test_luna_incomplete_refused_or_wrong_model_answers_fail_with_billing_retained(
        bad_response):
    body = {**bad_response, "usage": {
        "prompt_tokens": 100, "completion_tokens": 8192,
        "completion_tokens_details": {"reasoning_tokens": 8100},
        "cost_rub": "0.82",
    }}
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=body)

    with pytest.raises(LLMError) as caught:
        LLMClient([LUNA], httpx.MockTransport(handler)).complete("s", "u", 8192)
    assert len(calls) == 1  # Invalid successful responses are not transient retries.
    assert len(caught.value.attempts) == 1
    row = caught.value.attempts[0]
    assert row["error"] == "ValueError"
    assert row["cost_rub"] == "0.82"
    assert row["output_tokens"] == 8192
    assert row["reasoning_tokens"] == 8100


@pytest.mark.parametrize("served_model", ALIASES)
def test_luna_response_accepts_either_known_provider_alias(served_model):
    body = response(model=served_model)
    body["choices"][0]["message"]["refusal"] = None
    client = LLMClient([LUNA], httpx.MockTransport(
        lambda request: httpx.Response(200, json=body)))
    text, usage = client.complete("s", "u")
    assert text == "[]"
    assert usage.model == served_model


def test_luna_truncation_uses_fallback_and_keeps_failed_generation_cost():
    calls = []

    def handler(request):
        calls.append(request.url.host)
        if request.url.host == "api.aitunnel.ru":
            return httpx.Response(200, json=response(finish="length", usage={
                "prompt_tokens": 100, "completion_tokens": 8192, "cost_rub": "0.82",
            }))
        return httpx.Response(200, json={
            "model": SONNET.model, "content": [{"type": "text", "text": "[]"}],
            "stop_reason": "end_turn", "usage": {"input_tokens": 100, "output_tokens": 2},
        })

    text, usage = LLMClient([LUNA, SONNET], httpx.MockTransport(handler)).complete("s", "u")
    assert text == "[]"
    assert calls == ["api.aitunnel.ru", "api.anthropic.com"]
    assert usage.model == SONNET.model
    assert [row["cost_rub"] for row in usage.attempts] == ["0.82", None]
    assert [row["error"] for row in usage.attempts] == ["ValueError", None]
