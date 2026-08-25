"""Tests for GET /v1/github/installation-status — the check the audit
results page uses before offering a Fix Pack.

The GitHub API call the endpoint makes (via installation_state_for_repo)
is faked: installation_state_for_repo itself is unit-tested against a
mocked GitHub API with httpx.MockTransport in test_github_app.py, so here
we stub that boundary function to drive the endpoint's own branching
(configured/not, active/suspended/absent, upstream failure) without a
network call.
"""

import pytest
from fastapi.testclient import TestClient

from app.deploypack import github_app
from app.deploypack.github_app import GitHubAppError
from app.main import app

client = TestClient(app)


@pytest.fixture
def app_configured(monkeypatch):
    """Make app_credentials_from_env() return creds. The private key is a
    placeholder string, never parsed here — installation_state_for_repo is
    stubbed per-test, so no real signing happens."""
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_B64", raising=False)
    monkeypatch.delenv("GITHUB_APP_SLUG", raising=False)


def test_not_configured_returns_app_configured_false(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_B64", raising=False)

    resp = client.get("/v1/github/installation-status",
                      params={"owner": "acme", "repo": "app"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"owner": "acme", "repo": "app", "app_configured": False,
                    "installed": None, "suspended": None, "install_url": None}


def test_installed_true_has_no_install_url(app_configured, monkeypatch):
    def fake_state(owner, repo, *, app_id, private_key):
        assert (owner, repo) == ("acme", "app")
        return github_app.INSTALLATION_ACTIVE

    monkeypatch.setattr(github_app, "installation_state_for_repo", fake_state)
    resp = client.get("/v1/github/installation-status",
                      params={"owner": "acme", "repo": "app"})
    assert resp.status_code == 200
    assert resp.json() == {"owner": "acme", "repo": "app",
                           "app_configured": True, "installed": True,
                           "suspended": False, "install_url": None}


def test_not_installed_returns_install_url_with_state(app_configured, monkeypatch):
    monkeypatch.setattr(github_app, "installation_state_for_repo",
        lambda owner, repo, *, app_id, private_key: github_app.INSTALLATION_ABSENT,
    )
    resp = client.get("/v1/github/installation-status",
                      params={"owner": "acme", "repo": "app"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["app_configured"] is True
    assert body["installed"] is False
    assert body["suspended"] is False
    assert body["install_url"] == (
        "https://github.com/apps/aiagent2046-coder-shipit/installations/new"
        "?state=acme%2Fapp"
    )


def test_suspended_blocks_the_sale_and_offers_no_install_link(
    app_configured, monkeypatch,
):
    """A suspended installation cannot open a pull request, so the Fix Pack
    must not be offered — `installed` is false. But `install_url` stays null
    and `suspended` says why: the person already installed the App, and
    sending them to the install page would be telling them to redo the thing
    they have done instead of the thing that would help.

    Found the hard way on 2026-08-25: the old check answered "installed" for a
    suspended installation one second before delivery got a 403."""
    monkeypatch.setattr(github_app, "installation_state_for_repo",
        lambda owner, repo, *, app_id, private_key:
            github_app.INSTALLATION_SUSPENDED,
    )
    resp = client.get("/v1/github/installation-status",
                      params={"owner": "acme", "repo": "app"})
    assert resp.status_code == 200
    assert resp.json() == {"owner": "acme", "repo": "app",
                           "app_configured": True, "installed": False,
                           "suspended": True, "install_url": None}


def test_upstream_failure_is_502(app_configured, monkeypatch):
    def boom(owner, repo, *, app_id, private_key):
        raise GitHubAppError("resolve installation failed: 401 bad jwt")

    monkeypatch.setattr(github_app, "installation_state_for_repo", boom)
    resp = client.get("/v1/github/installation-status",
                      params={"owner": "acme", "repo": "app"})
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "installation_check_failed"


@pytest.mark.parametrize("owner,repo", [
    ("../etc", "app"),
    ("acme", "a/b"),
    ("acme", "app;rm"),
])
def test_bad_owner_repo_is_422(app_configured, owner, repo):
    resp = client.get("/v1/github/installation-status",
                      params={"owner": owner, "repo": repo})
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "bad_owner_repo"
