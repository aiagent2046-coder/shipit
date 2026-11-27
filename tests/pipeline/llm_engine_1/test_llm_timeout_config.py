"""Reject unusable completion timeouts before accepting audit work."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.foundation.llm import client as client_mod
from app.foundation.llm.client import LLMClient, Provider
from app.pipeline import scan_pipeline as pipeline_mod


def _import_client(timeout: str | None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("LLM_READ_TIMEOUT", None)
    if timeout is not None:
        env["LLM_READ_TIMEOUT"] = timeout
    # A fresh process exercises the actual import-time configuration without
    # replacing LLMError/Provider classes used by other tests in this process.
    return subprocess.run(
        [
            sys.executable, "-c",
            "import json; from app.foundation.llm.client import TIMEOUT; "
            "print(json.dumps({'read': TIMEOUT.read, 'connect': TIMEOUT.connect}))",
        ],
        cwd=Path(__file__).resolve().parents[3],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "1e309", "", "bad"])
def test_invalid_timeout_fails_at_startup(value):
    result = _import_client(value)
    assert result.returncode != 0
    assert "LLM_READ_TIMEOUT must be a finite positive number" in result.stderr


@pytest.mark.parametrize("value, expected", [(None, 120.0), ("300.5", 300.5)])
def test_valid_timeout_preserves_connect_deadline(value, expected):
    result = _import_client(value)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"read": expected, "connect": 10.0}


# --- one model name per PROVIDER, not one per chain (#29) --------------------
#
# The same model is spelled differently by each provider: AITunnel wants
# claude-sonnet-4.6 (dot), the direct Anthropic API wants claude-sonnet-4-6
# (dash), and the wrong one is a 400 on every request. One LLM_MODEL for the
# whole chain cannot be right for both -- it configures the primary and
# mis-configures the fallback, which then fails for a reason unrelated to the
# outage it exists to survive. A spare tyre that only fits the car you are not
# driving.
#
# This project has already paid for that spelling once: FREE_TIER_LLM_MODEL
# shipped as the dashed name against an AITunnel-only deployment, and every
# preview would have 400ed and degraded to static-only in silence.


def _chain(monkeypatch, **env):
    for k in ("LLM_MODEL", "AITUNNEL_LLM_MODEL", "ANTHROPIC_LLM_MODEL",
              "AITUNNEL_API_KEY", "AITUNNEL_BASE_URL", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AITUNNEL_API_KEY", "k1")
    monkeypatch.setenv("AITUNNEL_BASE_URL", "https://aitunnel.example/v1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k2")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return {p.kind: p.model for p in client_mod.providers_from_env()}


def test_each_provider_can_be_told_its_own_spelling(monkeypatch):
    models = _chain(monkeypatch,
                    LLM_MODEL="claude-sonnet-4.6",
                    ANTHROPIC_LLM_MODEL="claude-sonnet-4-6")

    assert models == {"openai_compat": "claude-sonnet-4.6",
                      "anthropic": "claude-sonnet-4-6"}


def test_one_name_still_serves_a_one_provider_chain(monkeypatch):
    """Every deployment today runs a single provider. The per-kind variables
    exist so that adding a second one is a configuration change rather than a
    silent downgrade -- not so that anyone has to learn them first."""
    models = _chain(monkeypatch, LLM_MODEL="claude-sonnet-4.6")

    assert set(models.values()) == {"claude-sonnet-4.6"}


def test_an_unset_override_does_not_blank_the_model(monkeypatch):
    """An empty string is what an operator leaves behind after commenting a
    value out, and it must read as "not set" rather than as a model named ""."""
    models = _chain(monkeypatch, LLM_MODEL="claude-sonnet-4.6",
                    ANTHROPIC_LLM_MODEL="")

    assert models["anthropic"] == "claude-sonnet-4.6"


def test_with_model_can_respell_per_provider():
    """The free tier's path. It runs a different model from the paid one, and
    a preview that 400s on the fallback turns every free scan static-only on
    the day the primary is down -- the thinner report a visitor cannot tell
    apart from a real one."""
    chain = LLMClient(providers=[
        Provider("openai_compat", "https://a", "k", "claude-sonnet-4.6"),
        Provider("anthropic", "https://b", "k", "claude-sonnet-4-6"),
    ])

    swapped = chain.with_model("claude-haiku-4.5",
                               by_kind={"anthropic": "claude-haiku-4-5"})

    assert [p.model for p in swapped.providers] == [
        "claude-haiku-4.5", "claude-haiku-4-5"]


def test_with_model_without_a_mapping_is_unchanged():
    chain = LLMClient(providers=[
        Provider("openai_compat", "https://a", "k", "x"),
        Provider("anthropic", "https://b", "k", "y"),
    ])

    assert [p.model for p in chain.with_model("z").providers] == ["z", "z"]


def test_the_free_tier_mapping_is_read_from_the_environment(monkeypatch):
    """The producer behind FREE_TIER_MODEL_BY_KIND.

    The constant is built at import, so without a function to call, the only
    way to test the reading is to reload the module -- which leaves every
    other importer holding the value from before.
    """
    monkeypatch.setenv("FREE_TIER_LLM_MODEL_ANTHROPIC", "claude-haiku-4-5")
    monkeypatch.delenv("FREE_TIER_LLM_MODEL_AITUNNEL", raising=False)

    assert pipeline_mod.free_tier_models_by_kind() == {
        "anthropic": "claude-haiku-4-5"}


def test_a_blanked_free_tier_override_is_not_a_model_named_nothing(monkeypatch):
    monkeypatch.setenv("FREE_TIER_LLM_MODEL_ANTHROPIC", "  ")
    monkeypatch.delenv("FREE_TIER_LLM_MODEL_AITUNNEL", raising=False)

    assert pipeline_mod.free_tier_models_by_kind() == {}
