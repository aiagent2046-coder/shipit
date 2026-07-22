"""Shared test fixtures.

Autouse: give every test a fresh, generous rate limiter so tests in
different files that each hit /v1/audits a few times never trip each
other's daily budget (they'd otherwise all share the same TestClient
key). Tests that want to exercise real limiting override
`get_rate_limiter` themselves inside the test body — see
test_ratelimit.py — which simply shadows this default for the
duration of that test.

Autouse: keep DATABASE_URL out of the default suite regardless of what
the shell happens to have exported. Without this, a DATABASE_URL left
over from running scripts/verify_db_locally.py by hand makes
unrelated tests (test_fixpack_api.py, test_ingest_api.py, ...) open
real connections to Supabase through app/db.py's module-global pool --
slow, and the pool ends up bound to one test's asyncio event loop
while a later test runs on a different (already-closed) one, which is
what the `Event loop is closed` / `another operation is in progress`
cascade actually was. tests/test_db.py sets DATABASE_URL back
explicitly, per test, where it wants the configured-path behavior.
"""

from __future__ import annotations

import pytest

import app.db as db_mod
from app.main import app, get_rate_limiter
from app.ratelimit import RateLimiter


@pytest.fixture(autouse=True)
def _generous_rate_limit_by_default():
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=10_000)
    yield
    app.dependency_overrides.pop(get_rate_limiter, None)


@pytest.fixture(autouse=True)
def _no_ambient_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_mod._pool = None
    yield
    db_mod._pool = None


@pytest.fixture(autouse=True)
def _no_ambient_llm_providers(monkeypatch):
    """Same isolation principle as DATABASE_URL above, third instance
    of the class: a shell with AITUNNEL_*/ANTHROPIC_* exported (e.g.
    after `set -a; . ./.env` for a manual script run) made the default
    suite construct a real provider chain and spend real money on real
    LLM calls — one visible assertion failure, several silent paid
    calls, 4-minute suite. Tests that want an LLM pass explicit fake
    providers or monkeypatch get_llm_client; nothing may inherit them
    from the ambient environment."""
    for var in ("AITUNNEL_API_KEY", "AITUNNEL_BASE_URL",
                "ANTHROPIC_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _no_ambient_production_integrations(monkeypatch):
    """Never let the default test suite use production integrations.

    The production VPS exports real GitHub App and sandbox-runner settings.
    Tests that need these values must set or monkeypatch them explicitly.
    """
    variables = (
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_PRIVATE_KEY_B64",
        "GITHUB_APP_SLUG",
        "GITHUB_PR_TOKEN",
        "SANDBOX_RUNNER_URL",
        "SANDBOX_RUNNER_UDS",
        "SANDBOX_RUNNER_TOKEN",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET",
        "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "USDT_POLL_TOKEN",
    )

    for variable in variables:
        monkeypatch.delenv(variable, raising=False)

    # sandbox_client reads these values at import time, before pytest
    # fixtures execute. Override the module-level values as well so a test
    # can never contact the real production runner accidentally.
    import app.sandbox_client as sandbox_client_mod

    monkeypatch.setattr(sandbox_client_mod, "SANDBOX_RUNNER_URL", "")
    monkeypatch.setattr(
        sandbox_client_mod,
        "SANDBOX_RUNNER_UDS",
        "/tmp/shipit-pytest-no-sandbox-runner.sock",
    )
    monkeypatch.setattr(sandbox_client_mod, "SANDBOX_RUNNER_TOKEN", "")
