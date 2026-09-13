"""The provider check must catch the failure that costs an incident.

The class it exists for, MEASURED 2026-09-13: a model name that the code defaults
to but the configured provider does not list (`claude-haiku-4-5` with dashes
against AITunnel, which lists `claude-haiku-4.5`). Every request would answer 400,
and nothing in the project said so at startup.

The check talks to the network, so these tests drive it with a stubbed listing and
assert the verdict, including that no key material reaches the report.
"""
from __future__ import annotations

import pathlib

import pytest

from scripts import verify_llm_provider

SECRET = "sk-aitunnel-TESTKEYDOESNOTEXIST"


@pytest.fixture
def env_file(tmp_path: pathlib.Path, monkeypatch) -> pathlib.Path:
    for name in ("AITUNNEL_API_KEY", "AITUNNEL_BASE_URL", "AITUNNEL_LLM_MODEL",
                 "LLM_MODEL", "FREE_TIER_LLM_MODEL_AITUNNEL", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".env"
    path.write_text(
        f"AITUNNEL_API_KEY={SECRET}\n"
        "AITUNNEL_BASE_URL=https://api.aitunnel.ru/v1\n"
        "AITUNNEL_LLM_MODEL=grok-4.20-multi-agent\n",
        encoding="utf-8")
    return path


def stub_listing(monkeypatch, ids: set[str]) -> None:
    monkeypatch.setattr(verify_llm_provider, "fetch_model_ids", lambda *_a, **_k: ids)


def test_a_model_the_provider_does_not_list_fails_the_check(env_file, monkeypatch):
    """The exact production trap: the code default for the preview is dashed, the
    provider lists the dotted spelling."""
    stub_listing(monkeypatch, {"grok-4.20-multi-agent", "claude-haiku-4.5"})

    code, lines = verify_llm_provider.check(env_file)
    text = "\n".join(lines)

    assert code == 1
    assert "claude-haiku-4-5" in text          # named, so an operator can fix it
    assert "400" in text                       # and told what it would cost
    assert SECRET not in text                  # never the key itself


def test_the_same_environment_passes_when_every_name_is_listed(env_file, monkeypatch):
    """The mutation: one configuration value changes -- the preview model is set to
    the provider's own dotted spelling -- and nothing else.

    The free-tier model is read from a module constant, computed when
    app.scan.pipeline is imported, so the value has to be in the environment BEFORE
    the process starts. That is how production works; here the module is reloaded
    to model a process that started with this setting.
    """
    import importlib

    (env_file.parent / ".env").write_text(
        env_file.read_text(encoding="utf-8") + "FREE_TIER_LLM_MODEL_AITUNNEL=claude-haiku-4.5\n",
        encoding="utf-8")
    monkeypatch.setenv("FREE_TIER_LLM_MODEL_AITUNNEL", "claude-haiku-4.5")
    from app.scan import pipeline
    importlib.reload(pipeline)
    monkeypatch.setattr(pipeline, "FREE_TIER_MODEL_BY_KIND", {"openai_compat": "claude-haiku-4.5"})
    stub_listing(monkeypatch, {"grok-4.20-multi-agent", "claude-haiku-4.5"})

    code, lines = verify_llm_provider.check(env_file)
    text = "\n".join(lines)

    assert code == 0
    assert "claude-haiku-4.5" in text
    assert SECRET not in text


def test_no_provider_configured_is_a_failure_not_a_silent_static_audit(tmp_path, monkeypatch):
    for name in ("AITUNNEL_API_KEY", "AITUNNEL_BASE_URL", "AITUNNEL_LLM_MODEL",
                 "LLM_MODEL", "ANTHROPIC_API_KEY", "FREE_TIER_LLM_MODEL_AITUNNEL"):
        monkeypatch.delenv(name, raising=False)

    code, lines = verify_llm_provider.check(tmp_path / "absent.env")

    assert code == 1
    assert "static-only" in "\n".join(lines)


def test_an_unreachable_provider_is_not_reported_as_success(env_file, monkeypatch):
    def explode(*_a, **_k):
        raise OSError("network down")

    monkeypatch.setattr(verify_llm_provider, "fetch_model_ids", explode)

    code, lines = verify_llm_provider.check(env_file)

    assert code == 2                       # distinct from 0 and from 1
    assert "НЕ ПРОВЕРЕНО" in "\n".join(lines)


def test_the_report_names_which_model_each_stage_requests(env_file, monkeypatch):
    """Paid and preview resolve through different variables, so the report has to
    show both -- that is the whole reason the dashed default was invisible."""
    stub_listing(monkeypatch, {"grok-4.20-multi-agent", "claude-haiku-4-5"})

    _code, lines = verify_llm_provider.check(env_file)
    text = "\n".join(lines)

    assert "paid (openai_compat)" in text
    assert "free preview (openai_compat)" in text
    assert "grok-4.20-multi-agent" in text
