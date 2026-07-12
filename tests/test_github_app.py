"""Tests for GitHub App JWT minting + installation token resolution.

Uses a real RSA keypair generated at test time (not a hardcoded fake)
so mint_app_jwt exercises real RS256 signing via the cryptography
backend, and a real jwt.decode with the matching public key proves the
signature actually verifies — not just "didn't raise".

The HTTP calls to api.github.com are faked with httpx.MockTransport
(no real network) — this sandbox has no GitHub App to test against
yet; see app/deploypack/github_app.py's module docstring for why that
manual step can't be automated from here.
"""

import time

import jwt
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.deploypack.github_app import (
    GitHubAppError,
    app_credentials_from_env,
    installation_token_for_repo,
    mint_app_jwt,
)


@pytest.fixture(scope="module")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def test_app_credentials_from_env_none_when_unset(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    assert app_credentials_from_env() is None


def test_app_credentials_from_env_returns_both(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")
    assert app_credentials_from_env() == ("12345", "fake-pem")


def test_mint_app_jwt_is_really_signed_and_verifiable(keypair):
    private_pem, public_pem = keypair
    now = time.time()
    token = mint_app_jwt("999", private_pem, now=now)

    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["iss"] == "999"
    assert decoded["iat"] == int(now) - 60
    assert decoded["exp"] == int(now) + 9 * 60

    # A tampered token must fail verification against the real public key.
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token[:-4] + "abcd", public_pem, algorithms=["RS256"])


def test_installation_token_for_repo_happy_path(keypair):
    private_pem, _ = keypair
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/repos/acme/app/installation":
            assert request.headers["authorization"].startswith("Bearer ")
            return httpx.Response(200, json={"id": 4242})
        if request.url.path == "/app/installations/4242/access_tokens":
            return httpx.Response(201, json={"token": "ghs_fake123"})
        raise AssertionError(f"unexpected path {request.url.path}")

    token = installation_token_for_repo(
        "acme", "app", app_id="999", private_key=private_pem,
        transport=httpx.MockTransport(handler),
    )
    assert token == "ghs_fake123"
    assert calls == ["/repos/acme/app/installation",
                      "/app/installations/4242/access_tokens"]


def test_installation_token_for_repo_not_installed_gives_specific_error(keypair):
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    with pytest.raises(GitHubAppError, match="not installed on acme/app"):
        installation_token_for_repo(
            "acme", "app", app_id="999", private_key=private_pem,
            transport=httpx.MockTransport(handler),
        )


def test_installation_token_for_repo_other_api_error(keypair):
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    with pytest.raises(GitHubAppError, match="resolve installation failed: 500"):
        installation_token_for_repo(
            "acme", "app", app_id="999", private_key=private_pem,
            transport=httpx.MockTransport(handler),
        )


def test_installation_token_mint_error(keypair):
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/app/installation":
            return httpx.Response(200, json={"id": 4242})
        return httpx.Response(403, text="forbidden")

    with pytest.raises(GitHubAppError, match="mint installation token failed: 403"):
        installation_token_for_repo(
            "acme", "app", app_id="999", private_key=private_pem,
            transport=httpx.MockTransport(handler),
        )
