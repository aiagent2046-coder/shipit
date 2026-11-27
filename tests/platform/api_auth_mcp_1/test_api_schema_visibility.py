"""The interactive API schema must not be served from a deployed environment.

The source repository is public, so an attacker reading the code learns
nothing new from /docs. A live machine-readable inventory of every route on
the running host is a different thing: it is reconnaissance handed over
pre-formatted, and it describes the deployment rather than the repository.

These tests build a fresh app per environment value rather than importing the
module-level `app`, because the docs decision is made once at import time and
cannot be observed for two environments from a single import.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

SCHEMA_PATHS = ("/docs", "/redoc", "/openapi.json")


def app_for(monkeypatch: pytest.MonkeyPatch, environment: str | None):
    """Re-import app.main with ENVIRONMENT set, returning the fresh app."""
    if environment is None:
        monkeypatch.delenv("ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("ENVIRONMENT", environment)

    import app.main

    return importlib.reload(app.main).app


@pytest.fixture(autouse=True)
def restore_module():
    """Leave app.main as the rest of the suite expects to find it.

    Without this, reloading here would leave every later test importing an app
    built under whichever ENVIRONMENT ran last -- and `app.dependency_overrides`
    keys on object identity, so 29 test modules would be overriding
    dependencies on an app object that is no longer the one under test.
    """
    yield
    import app.main

    importlib.reload(app.main)


@pytest.mark.parametrize("environment", ["production", "staging", "preview"])
@pytest.mark.parametrize("path", SCHEMA_PATHS)
def test_schema_is_not_served_outside_development(
    monkeypatch: pytest.MonkeyPatch, environment: str, path: str
) -> None:
    client = TestClient(app_for(monkeypatch, environment))

    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", SCHEMA_PATHS)
def test_schema_is_served_in_development(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """Turning the docs off everywhere would be a worse trade: they are how
    the API is explored while it is being built."""
    client = TestClient(app_for(monkeypatch, "development"))

    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", SCHEMA_PATHS)
def test_an_unset_environment_keeps_the_docs(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """ENVIRONMENT defaults to "development", so a plain local checkout keeps
    the docs and only a deliberately configured deployment loses them."""
    client = TestClient(app_for(monkeypatch, None))

    assert client.get(path).status_code == 200


def test_the_api_still_works_without_the_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disabling the docs must not disable the app."""
    client = TestClient(app_for(monkeypatch, "production"))

    assert client.get("/healthz").status_code == 200
    assert client.get("/version").status_code == 200
