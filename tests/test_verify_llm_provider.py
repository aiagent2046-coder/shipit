"""Provider diagnostics exercise real HTTP payloads/parsers with an offline transport."""
from __future__ import annotations

import json
import os
from urllib.parse import quote

import httpx
import pytest

from scripts import verify_llm_provider as verify

SECRET = "fixture-key-$-not-a-credential"
PAID = "grok-4.20-multi-agent"
PREVIEW = "claude-haiku-4.5"
BASE = "https://provider.example/v1"


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / "provider.env"
    path.write_text(f'AITUNNEL_API_KEY="{SECRET}"\nAITUNNEL_BASE_URL="{BASE}"\n'
                    f"AITUNNEL_LLM_MODEL={PAID}\nFREE_TIER_LLM_MODEL_AITUNNEL={PREVIEW}\n",
                    encoding="utf-8")
    return path


def catalog(*models, **extra):
    return httpx.Response(200, json={"data": [{"id": model} for model in models], **extra})


def answer(model, content="OK", tokens=1):
    return httpx.Response(200, json={
        "model": model, "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": tokens},
    })


def run(path, handler, *, probe=False):
    code, lines = verify.check(path, probe=probe, transport=httpx.MockTransport(handler))
    report = "\n".join(lines)
    assert SECRET not in report
    assert quote(SECRET, safe="") not in report
    return code, report


def test_file_is_authoritative_parses_quotes_and_restores_shell(env_file, monkeypatch):
    monkeypatch.setenv("AITUNNEL_API_KEY", "ambient-key")
    monkeypatch.setenv("AITUNNEL_BASE_URL", "https://wrong.example/v1")
    monkeypatch.setenv("AITUNNEL_LLM_MODEL", "wrong-paid")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-anthropic")
    monkeypatch.setenv("FREE_TIER_LLM_MODEL_AITUNNEL", "wrong-preview")
    before = dict(os.environ)
    requests = []

    def handle(request):
        requests.append(request)
        assert str(request.url) == BASE + "/models"
        assert request.headers["Authorization"] == "Bearer " + SECRET
        return catalog(PAID, PREVIEW)

    code, report = run(env_file, handle)
    assert code == 0
    assert "провайдеров в цепочке: 1" in report
    assert f"paid (openai_compat) -> {PAID}" in report
    assert f"free preview (openai_compat) -> {PREVIEW}" in report
    assert [r.method for r in requests] == ["GET"]
    assert dict(os.environ) == before


def test_preview_mutation_is_seen_without_reloading_pipeline(env_file, monkeypatch):
    from app.scan import pipeline

    monkeypatch.setattr(pipeline, "FREE_TIER_MODEL", "stale-shared")
    monkeypatch.setattr(pipeline, "FREE_TIER_MODEL_BY_KIND", {"openai_compat": "stale-preview"})
    original = env_file.read_text()
    env_file.write_text(original.replace(f"FREE_TIER_LLM_MODEL_AITUNNEL={PREVIEW}\n", ""))
    code, report = run(env_file, lambda request: catalog(PAID, PREVIEW))
    assert code == 1
    assert "НЕТ claude-haiku-4-5" in report
    assert "stale" not in report
    env_file.write_text(original)
    assert run(env_file, lambda request: catalog(PAID, PREVIEW))[0] == 0
    assert pipeline.FREE_TIER_MODEL == "stale-shared"
    assert pipeline.FREE_TIER_MODEL_BY_KIND == {"openai_compat": "stale-preview"}


def test_blank_provider_override_uses_shared_preview(env_file):
    text = env_file.read_text().replace(f"FREE_TIER_LLM_MODEL_AITUNNEL={PREVIEW}",
                                      'FREE_TIER_LLM_MODEL_AITUNNEL="   "')
    env_file.write_text(text + f"FREE_TIER_LLM_MODEL={PREVIEW}\n")
    assert run(env_file, lambda request: catalog(PAID, PREVIEW))[0] == 0


@pytest.mark.parametrize("contents", [None, "", "# no settings\n", "LLM_MODEL=example\n"])
def test_missing_or_unconfigured_file_cannot_use_shell(tmp_path, monkeypatch, contents):
    monkeypatch.setenv("AITUNNEL_API_KEY", SECRET)
    monkeypatch.setenv("AITUNNEL_BASE_URL", BASE)
    path = tmp_path / "absent.env"
    if contents is not None:
        path.write_text(contents)

    def unexpected(request):
        pytest.fail("an invalid file must not make network requests")

    assert run(path, unexpected)[0] == 1


def test_process_environment_is_an_explicit_alternative(monkeypatch):
    for name in verify.CONFIG_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AITUNNEL_API_KEY", SECRET)
    monkeypatch.setenv("AITUNNEL_BASE_URL", BASE)
    monkeypatch.setenv("LLM_MODEL", PAID)
    monkeypatch.setenv("FREE_TIER_LLM_MODEL", PREVIEW)
    code, report = run(None, lambda request: catalog(PAID, PREVIEW))
    assert code == 0
    assert "окружение процесса" in report


@pytest.mark.parametrize("broken", ["key-only", "blank-model", "url-credentials", "url-query"])
def test_invalid_configuration_fails_before_network(env_file, broken):
    text = env_file.read_text()
    if broken == "key-only":
        text = text.replace(f'AITUNNEL_BASE_URL="{BASE}"\n', "")
    elif broken == "blank-model":
        text = text.replace(f"FREE_TIER_LLM_MODEL_AITUNNEL={PREVIEW}", "FREE_TIER_LLM_MODEL=")
    elif broken == "url-credentials":
        text = text.replace(BASE, f"https://operator:{SECRET}@provider.example/v1")
    else:
        text = text.replace(BASE, f"{BASE}?key={SECRET}")
    env_file.write_text(text)

    def unexpected(request):
        pytest.fail("invalid configuration must not make network requests")

    assert run(env_file, unexpected)[0] == 1


@pytest.mark.parametrize("failure", ["network", "auth", "redirect", "shape", "id", "partial"])
def test_unverifiable_catalog_returns_two_without_leaking_errors(env_file, failure):
    requests = []

    def handle(request):
        requests.append(request)
        if failure == "network":
            raise httpx.ConnectError(f"failed with key {SECRET}", request=request)
        if failure == "auth":
            return httpx.Response(401, text=f"invalid key {SECRET}")
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://other.example/" + SECRET})
        if failure == "shape":
            return httpx.Response(200, json={"error": SECRET})
        if failure == "id":
            return httpx.Response(200, json={"data": [{"id": {"key": SECRET}}]})
        return catalog(PAID, has_more=True, last_id=PAID)

    code, report = run(env_file, handle)
    assert code == 2
    assert "НЕ ПРОВЕРЕНО" in report
    assert len(requests) == 1


def test_anthropic_catalog_pagination_and_product_probe(env_file):
    env_file.write_text(f"ANTHROPIC_API_KEY={SECRET}\nANTHROPIC_LLM_MODEL=claude-sonnet-4-6\n")
    requests = []

    def handle(request):
        requests.append(request)
        assert request.url.host == "api.anthropic.com"
        assert request.headers["x-api-key"] == SECRET
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert "Authorization" not in request.headers
        if request.method == "GET":
            assert request.url.path == "/v1/models"
            if "after_id" not in request.url.params:
                return catalog("claude-sonnet-4-6", has_more=True, last_id="claude-sonnet-4-6")
            assert request.url.params["after_id"] == "claude-sonnet-4-6"
            return catalog("claude-haiku-4-5", has_more=False)
        assert request.url.path == "/v1/messages"
        payload = json.loads(request.content)
        assert payload["system"]
        assert payload["max_tokens"] == 8
        assert payload["temperature"] == 0
        return httpx.Response(200, json={"model": payload["model"],
            "content": [{"type": "text", "text": "OK"}],
            "usage": {"input_tokens": 10, "output_tokens": 1}})

    code, report = run(env_file, handle, probe=True)
    assert code == 0
    assert [r.method for r in requests] == ["GET", "GET", "POST", "POST"]
    assert "claude-haiku-4-5" in report


def test_repeated_anthropic_cursor_is_incomplete(env_file):
    env_file.write_text(f"ANTHROPIC_API_KEY={SECRET}\n")
    calls = []

    def handle(request):
        calls.append(request)
        return catalog("same", has_more=True, last_id="same")

    assert run(env_file, handle)[0] == 2
    assert len(calls) == 2


def test_probe_uses_product_sampling_and_validates_actual_usage(env_file):
    env_file.write_text(env_file.read_text().replace(PREVIEW, PAID))
    requests = []

    def handle(request):
        requests.append(request)
        if request.method == "GET":
            return catalog(PAID)
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer " + SECRET
        payload = json.loads(request.content)
        assert payload["model"] == PAID
        assert payload["max_tokens"] == 8
        assert payload["temperature"] == 0
        assert [m["role"] for m in payload["messages"]] == ["system", "user"]
        return answer(PAID, tokens=3710)

    code, report = run(env_file, handle, probe=True)
    assert code == 0
    assert [r.method for r in requests] == ["GET", "POST"]
    assert "completion=3710" in report
    assert "не гарантирует" in report


@pytest.mark.parametrize("content", [None, "", "   "])
def test_http_200_without_answer_is_not_a_successful_probe(env_file, content):
    def handle(request):
        if request.method == "GET":
            return catalog(PAID, PREVIEW)
        return answer(json.loads(request.content)["model"], content=content)

    code, report = run(env_file, handle, probe=True)
    assert code == 1
    assert "некорректный ответ" in report


@pytest.mark.parametrize("failure", ["network", "http"])
def test_probe_does_not_retry_or_report_unreachable_as_success(env_file, failure):
    env_file.write_text(env_file.read_text().replace(PREVIEW, PAID))
    posts = []

    def handle(request):
        if request.method == "GET":
            return catalog(PAID)
        posts.append(request)
        if failure == "network":
            raise httpx.ReadTimeout(f"timeout with {SECRET}", request=request)
        return httpx.Response(503, text=f"temporary error {SECRET}")

    code, report = run(env_file, handle, probe=True)
    assert code == 2
    assert "НЕ ПРОВЕРЕНО" in report
    assert len(posts) == 1


def test_provider_echo_in_served_model_is_redacted(env_file):
    def handle(request):
        if request.method == "GET":
            return catalog(PAID, PREVIEW)
        return answer(SECRET + " " + quote(SECRET, safe=""))

    code, report = run(env_file, handle, probe=True)
    assert code == 0
    assert "served_as=[REDACTED] [REDACTED]" in report


def test_missing_model_and_unreachable_fallback_report_both_with_exit_two(env_file):
    env_file.write_text(env_file.read_text() + f"ANTHROPIC_API_KEY={SECRET}\n")

    def handle(request):
        if request.url.host == "api.anthropic.com":
            return httpx.Response(401, text=SECRET)
        return catalog(PAID)

    code, report = run(env_file, handle)
    assert code == 2
    assert f"НЕТ {PREVIEW}" in report
    assert "HTTP 401" in report


def test_cli_defaults_to_catalog_only_and_file_only(env_file, monkeypatch, capsys):
    calls = []

    def fake_check(path, probe=False):
        calls.append((path, probe))
        return 2, ["НЕ ПРОВЕРЕНО"]

    monkeypatch.setattr(verify, "check", fake_check)
    assert verify.main(["--env", str(env_file)]) == 2
    assert calls == [(env_file, False)]
    assert "НЕ ПРОВЕРЕНО" in capsys.readouterr().out
    assert verify.main(["--process-env", "--probe"]) == 2
    assert calls[-1] == (None, True)
    with pytest.raises(SystemExit):
        verify.main(["--process-env", "--env", str(env_file)])


@pytest.mark.parametrize("result,expected", [("resolved", 0), ("missing", 1), ("unreachable", 2), ("invalid", 2)])
def test_anthropic_aliases_are_resolved_without_guessing(env_file, result, expected):
    alias = "claude-haiku-4-5"
    canonical = "claude-haiku-4-5-20251001"
    env_file.write_text(f"ANTHROPIC_API_KEY={SECRET}\nANTHROPIC_LLM_MODEL={alias}\n")
    requests = []

    def handle(request):
        requests.append(request)
        assert request.headers["x-api-key"] == SECRET
        assert request.headers["anthropic-version"] == "2023-06-01"
        if request.url.path == "/v1/models":
            return catalog(canonical, has_more=False)
        if request.method == "POST":
            payload = json.loads(request.content)
            assert payload["model"] == alias  # probe the configured name, not its replacement
            return httpx.Response(200, json={"model": canonical,
                "content": [{"type": "text", "text": "OK"}],
                "usage": {"input_tokens": 10, "output_tokens": 1}})
        assert request.url.path == "/v1/models/" + alias
        if result == "missing":
            return httpx.Response(404, text=SECRET)
        if result == "unreachable":
            return httpx.Response(401, text=SECRET)
        if result == "invalid":
            return httpx.Response(200, json={"error": SECRET})
        return httpx.Response(200, json={"id": canonical})

    code, report = run(env_file, handle, probe=True)
    assert code == expected
    assert [r.method for r in requests] == (["GET", "GET", "POST"] if expected == 0 else ["GET", "GET"])
    if expected == 0:
        assert f"ALIAS {alias} -> {canonical}" in report
