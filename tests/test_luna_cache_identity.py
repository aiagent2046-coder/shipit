"""An opt-in Luna run must not reuse an audit cached under Sonnet."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from app.scan.model_identity import configured_model_engine_version
from app.scan.version import AUDIT_ENGINE_VERSION


PROVIDER_ENV = (
    "AITUNNEL_API_KEY", "AITUNNEL_BASE_URL", "AITUNNEL_LLM_MODEL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_LLM_MODEL", "LLM_MODEL",
)


@pytest.fixture
def configured_primary(monkeypatch):
    for name in PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AITUNNEL_API_KEY", "test-key")
    monkeypatch.setenv("AITUNNEL_BASE_URL", "https://api.aitunnel.ru/v1")
    monkeypatch.setenv("AITUNNEL_LLM_MODEL", "gpt-6-luna")
    return monkeypatch


def test_luna_partitions_cache_and_both_aliases_share_identity(configured_primary):
    version = configured_model_engine_version(AUDIT_ENGINE_VERSION)
    assert re.fullmatch(re.escape(AUDIT_ENGINE_VERSION) + r"-luna-[0-9a-f]{12}", version)
    configured_primary.setenv("AITUNNEL_LLM_MODEL", "openai/gpt-6-luna")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == version
    configured_primary.setenv("AITUNNEL_LLM_MODEL", "claude-sonnet-4.6")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == AUDIT_ENGINE_VERSION


def test_unconfigured_luna_name_does_not_partition_cache(configured_primary):
    configured_primary.delenv("AITUNNEL_API_KEY")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == AUDIT_ENGINE_VERSION


def test_fallback_model_changes_partition_but_secret_rotation_does_not(configured_primary):
    luna_only = configured_model_engine_version(AUDIT_ENGINE_VERSION)
    configured_primary.setenv("ANTHROPIC_API_KEY", "test-fallback-key")
    configured_primary.setenv("ANTHROPIC_LLM_MODEL", "claude-sonnet-4-6")
    with_fallback = configured_model_engine_version(AUDIT_ENGINE_VERSION)
    assert with_fallback != luna_only
    configured_primary.setenv("AITUNNEL_API_KEY", "rotated-key")
    configured_primary.setenv("ANTHROPIC_API_KEY", "rotated-fallback-key")
    configured_primary.setenv("AITUNNEL_BASE_URL", "https://other-compatible.invalid/v1")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == with_fallback
    configured_primary.setenv("ANTHROPIC_LLM_MODEL", "claude-haiku-4-5")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) not in (luna_only, with_fallback)


def test_shared_model_override_and_provider_override_resolve_actual_chain(configured_primary):
    explicit = configured_model_engine_version(AUDIT_ENGINE_VERSION)
    configured_primary.delenv("AITUNNEL_LLM_MODEL")
    configured_primary.setenv("LLM_MODEL", "gpt-6-luna")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == explicit
    configured_primary.setenv("AITUNNEL_LLM_MODEL", "claude-sonnet-4.6")
    assert configured_model_engine_version(AUDIT_ENGINE_VERSION) == AUDIT_ENGINE_VERSION


def test_api_and_worker_share_startup_identity_without_changing_offline_version(configured_primary):
    expected = configured_model_engine_version(AUDIT_ENGINE_VERSION)
    # A fresh interpreter exercises real import-time configuration without
    # reloading shared pipeline globals in the parent test process.
    environment = os.environ.copy()
    environment.pop("DATABASE_URL", None)
    result = subprocess.run(
        [sys.executable, "-c", """
import json
import os
from app import main
from app.scan import pipeline, version
from app.worker import main as worker
initial = [main.AUDIT_ENGINE_VERSION, worker.AUDIT_ENGINE_VERSION,
           pipeline.AUDIT_ENGINE_VERSION, version.AUDIT_ENGINE_VERSION]
os.environ['AITUNNEL_LLM_MODEL'] = 'claude-sonnet-4.6'
assert pipeline.AUDIT_ENGINE_VERSION == initial[2]
print(json.dumps(initial))
"""],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        text=True, capture_output=True, check=True, timeout=30,
    )
    assert json.loads(result.stdout) == [expected, expected, expected, AUDIT_ENGINE_VERSION]
