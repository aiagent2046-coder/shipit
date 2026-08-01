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

import logging
import time

import jwt
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import app.deploypack.github_app as github_app
from app.deploypack.github_app import (
    GITHUB_APP_SLUG_DEFAULT,
    GitHubAppError,
    _public_key_fingerprint,
    app_credentials_from_env,
    app_slug_from_env,
    build_install_url,
    installation_exists_for_repo,
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


def test_mint_app_jwt_valid_real_newline_key_unchanged(keypair):
    private_pem, public_pem = keypair
    assert "\n" in private_pem  # sanity: real multi-line PEM
    now = time.time()
    token = mint_app_jwt("999", private_pem, now=now)
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["iss"] == "999"


def test_mint_app_jwt_normalizes_literal_backslash_n(keypair):
    """A PEM stored the only way a flat systemd EnvironmentFile can hold
    it — real newlines replaced by literal two-char \\n escapes — must be
    normalized and produce the same valid, verifiable JWT."""
    private_pem, public_pem = keypair
    escaped = private_pem.replace("\n", "\\n")
    assert "\n" not in escaped and "\\n" in escaped

    now = time.time()
    token_escaped = mint_app_jwt("999", escaped, now=now)
    token_real = mint_app_jwt("999", private_pem, now=now)
    assert token_escaped == token_real

    decoded = jwt.decode(token_escaped, public_pem, algorithms=["RS256"])
    assert decoded["iss"] == "999"


def test_mint_app_jwt_escaped_pem_with_trailing_real_newline(keypair):
    """The production failure: the env value is the literal-\\n single-line
    PEM (byte-confirmed correct: header, 27 literal \\n, footer) but the
    loader kept a stray trailing real newline. The old normalize gate saw
    that real newline and skipped unescaping, leaving 27 literal \\n so the
    key was rejected. Must now normalize and mint a verifiable JWT."""
    private_pem, public_pem = keypair
    escaped = private_pem.replace("\n", "\\n")
    value = escaped + "\n"                      # stray trailing real newline
    assert "\\n" in value and "\n" in value     # both kinds present

    now = time.time()
    token = mint_app_jwt("999", value, now=now)
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["iss"] == "999"


def test_mint_app_jwt_escaped_pem_with_stray_interior_newline(keypair):
    """Same class of defect, real newline in the middle rather than the end:
    literal \\n escapes must still be unescaped so the key parses."""
    private_pem, public_pem = keypair
    escaped = private_pem.replace("\n", "\\n")
    value = escaped[:40] + "\n" + escaped[40:]
    now = time.time()
    token = mint_app_jwt("999", value, now=now)
    assert jwt.decode(token, public_pem, algorithms=["RS256"])["iss"] == "999"


def test_app_credentials_from_env_normalizes_escaped_pem(monkeypatch, keypair):
    private_pem, _ = keypair
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", private_pem.replace("\n", "\\n"))
    app_id, key = app_credentials_from_env()
    assert app_id == "12345"
    assert key == private_pem  # real newlines restored


def test_app_credentials_from_env_uses_b64_path(monkeypatch, keypair):
    """base64 path decodes a valid PEM and takes precedence over the
    escaping path — the systemd-safe route."""
    private_pem, public_pem = keypair
    import base64
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv(
        "GITHUB_APP_PRIVATE_KEY_B64",
        base64.b64encode(private_pem.encode()).decode(),
    )
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    app_id, key = app_credentials_from_env()
    assert app_id == "12345"
    assert key == private_pem
    # And the decoded key really works end to end.
    token = mint_app_jwt(app_id, key)
    assert jwt.decode(token, public_pem, algorithms=["RS256"])["iss"] == "12345"


def test_app_credentials_b64_takes_precedence_over_plain(monkeypatch, keypair):
    private_pem, _ = keypair
    import base64
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv(
        "GITHUB_APP_PRIVATE_KEY_B64",
        base64.b64encode(private_pem.encode()).decode(),
    )
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "some-other-ignored-value")
    _, key = app_credentials_from_env()
    assert key == private_pem


def test_app_credentials_invalid_b64_falls_back_to_plain(monkeypatch, keypair):
    """Undecodable base64 must not break auth — fall back to the existing
    literal-\\n escaping path."""
    private_pem, _ = keypair
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_B64", "!!!not-valid-base64!!!")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", private_pem.replace("\n", "\\n"))
    app_id, key = app_credentials_from_env()
    assert app_id == "12345"
    assert key == private_pem  # real newlines restored via the fallback


def test_app_credentials_empty_b64_does_not_block_plain(monkeypatch, keypair):
    private_pem, _ = keypair
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_B64", "")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", private_pem.replace("\n", "\\n"))
    _, key = app_credentials_from_env()
    assert key == private_pem


def test_app_credentials_b64_non_utf8_falls_back(monkeypatch, keypair):
    """Valid base64 that decodes to non-UTF-8 bytes falls back cleanly."""
    private_pem, _ = keypair
    import base64
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv(
        "GITHUB_APP_PRIVATE_KEY_B64", base64.b64encode(b"\xff\xfe\xff").decode()
    )
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", private_pem.replace("\n", "\\n"))
    _, key = app_credentials_from_env()
    assert key == private_pem


def test_mint_app_jwt_iss_is_string_and_stripped(keypair):
    """PyJWT (>=2, issue #1039) forbids a non-string iss, so iss is always
    a string. A stray whitespace/newline around the App ID (e.g. from a
    sloppy env value) is stripped so GitHub sees a clean digit string."""
    private_pem, public_pem = keypair
    token = mint_app_jwt("  4278482\n", private_pem)
    iss = jwt.decode(token, public_pem, algorithms=["RS256"])["iss"]
    assert iss == "4278482"
    assert isinstance(iss, str)


def test_public_key_fingerprint_matches_independent_computation(keypair):
    import hashlib
    from cryptography.hazmat.primitives import serialization

    private_pem, _ = keypair
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = "sha256:" + hashlib.sha256(der).hexdigest()[:16]
    assert _public_key_fingerprint(private_pem) == expected
    # Same fingerprint whether the key is real-newline or literal-\n form.
    assert _public_key_fingerprint(private_pem.replace("\n", "\\n")) == expected


def test_public_key_fingerprint_unavailable_on_garbage_key():
    assert _public_key_fingerprint("not-a-pem").startswith("unavailable")


def test_installation_token_401_logs_keypair_fingerprint(keypair, caplog):
    """A 401 on the App JWT (GitHub's "could not be decoded") must emit a
    structural, secret-free diagnostic including the keypair fingerprint so
    an operator can tell a wrong-key from a clock-skew cause."""
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="A JSON web token could not be decoded")

    with caplog.at_level("WARNING"):
        with pytest.raises(GitHubAppError, match="resolve installation failed: 401"):
            installation_token_for_repo(
                "acme", "app", app_id="4278482", private_key=private_pem,
                transport=httpx.MockTransport(handler),
            )
    msg = caplog.text
    assert "App JWT rejected (401)" in msg
    assert "app_id(iss)='4278482'" in msg
    assert "public key sha256:" in msg
    assert private_pem not in msg  # never logs the secret


def test_mint_app_jwt_garbage_key_raises_githubapperror():
    with pytest.raises(GitHubAppError, match="not a valid PEM private key"):
        mint_app_jwt("999", "this-is-not-a-pem-key")


def test_pem_parse_failure_log_leaks_no_key_material(caplog, keypair):
    """The PEM-parse diagnostic fires precisely when the key is malformed, so
    a slice of the value is NOT reliably the header/footer -- on a truncated
    key the tail is base64 key material. Nothing but shape may be logged."""
    private_pem, _ = keypair
    truncated = private_pem[:len(private_pem) // 2]     # cut mid-base64

    with caplog.at_level(logging.WARNING):
        with pytest.raises(GitHubAppError):
            mint_app_jwt("999", truncated)

    msg = caplog.text
    # Not one 12-char window of the base64 body may appear anywhere in the
    # line. The window is deliberately shorter than the 15-char head/tail
    # slices this replaced, so this test fails against the old code rather
    # than passing vacuously.
    body = "".join(truncated.splitlines()[1:])
    assert len(body) > 12
    for offset in range(len(body) - 12):
        assert body[offset:offset + 12] not in msg
    # ...and the shape survives: truncation reads as a begin with no end.
    assert "has_begin=True" in msg
    assert "has_end=False" in msg


def test_pem_parse_failure_log_reports_shape_of_flattened_value(caplog, keypair):
    """The other real cause, the one _private_key_from_b64 exists for: systemd
    ate the backslashes, so no escape ever reached us and the newlines became
    bare letter "n". Distinguishable from truncation without seeing content --
    no escapes, no real newlines, so the whole key is a single line."""
    private_pem, _ = keypair
    flattened = private_pem.strip().replace("\n", "n")

    with caplog.at_level(logging.WARNING):
        with pytest.raises(GitHubAppError):
            mint_app_jwt("999", flattened)

    msg = caplog.text
    assert "escapes before normalize=False" in msg
    assert "newlines after normalize=0" in msg
    assert "lines=1" in msg
    body = "".join(private_pem.splitlines()[1:-1])
    for offset in range(len(body) - 12):
        assert body[offset:offset + 12] not in msg


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


def test_installation_exists_true_on_200(keypair):
    private_pem, _ = keypair
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers["authorization"].startswith("Bearer ")
        return httpx.Response(200, json={"id": 4242})

    assert installation_exists_for_repo(
        "acme", "app", app_id="999", private_key=private_pem,
        transport=httpx.MockTransport(handler),
    ) is True
    # Status check only: it must NOT go on to mint an installation token.
    assert calls == ["/repos/acme/app/installation"]


def test_installation_exists_false_on_404(keypair):
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    assert installation_exists_for_repo(
        "acme", "app", app_id="999", private_key=private_pem,
        transport=httpx.MockTransport(handler),
    ) is False


def test_installation_exists_raises_on_other_error(keypair):
    """A non-404 error (bad App JWT, GitHub down) must raise rather than be
    silently reported as "not installed" — the caller can't tell those apart
    otherwise."""
    private_pem, _ = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    with pytest.raises(GitHubAppError, match="resolve installation failed: 500"):
        installation_exists_for_repo(
            "acme", "app", app_id="999", private_key=private_pem,
            transport=httpx.MockTransport(handler),
        )


def test_app_slug_default_and_env_override(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_SLUG", raising=False)
    assert app_slug_from_env() == GITHUB_APP_SLUG_DEFAULT == "aiagent2046-coder-shipit"
    monkeypatch.setenv("GITHUB_APP_SLUG", "some-other-app")
    assert app_slug_from_env() == "some-other-app"


def test_build_install_url_encodes_state(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_SLUG", raising=False)
    url = build_install_url("acme/app")
    assert url == (
        "https://github.com/apps/aiagent2046-coder-shipit/installations/new"
        "?state=acme%2Fapp"
    )


# --- the health probe, and telling our failure from the caller's ---


def _key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _configure(monkeypatch, pem: str | None = None) -> None:
    monkeypatch.setenv("GITHUB_APP_ID", "Iv23test")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", pem if pem else _key_pem())
    github_app.reset_app_auth_cache()


def _transport(status: int, body: dict | None = None):
    return httpx.MockTransport(
        lambda request: httpx.Response(status, json=body or {})
    )


def test_auth_probe_is_none_when_app_is_not_configured(monkeypatch):
    """Not every deployment uses the App -- the PAT path is legitimate, and
    reporting it as a fault would make /health permanently red for it."""
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    github_app.reset_app_auth_cache()
    assert github_app.app_auth_ok() is None


def test_auth_probe_true_when_github_accepts_the_jwt(monkeypatch):
    _configure(monkeypatch)
    assert github_app.app_auth_ok(
        transport=_transport(200, {"slug": "drydock"})
    ) is True


def test_auth_probe_false_on_401(monkeypatch):
    _configure(monkeypatch)
    assert github_app.app_auth_ok(
        transport=_transport(401, {"message": "A JSON web token could not be decoded"})
    ) is False


def test_auth_probe_false_on_an_unparseable_key_without_any_network(monkeypatch):
    """A PEM that will not parse is a verdict on its own -- and the one cause
    that must be caught even when GitHub is unreachable."""
    _configure(monkeypatch, pem="not a pem at all")

    def explode(request):
        raise AssertionError("the probe must not call GitHub for a broken PEM")

    assert github_app.app_auth_ok(
        transport=httpx.MockTransport(explode)
    ) is False


def test_a_definite_verdict_is_cached(monkeypatch):
    """/health is public and unauthenticated: without this, a pinger turns
    every probe into a GitHub call and rate-limits the App."""
    _configure(monkeypatch)
    calls = []

    def counting(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(counting)
    assert github_app.app_auth_ok(transport=transport, now=1000.0) is True
    assert github_app.app_auth_ok(transport=transport, now=1200.0) is True
    assert calls == ["/app"]

    # Past the TTL it asks again.
    github_app.app_auth_ok(
        transport=transport, now=1000.0 + github_app.AUTH_CACHE_SECONDS + 1)
    assert len(calls) == 2


def test_an_unreachable_github_is_reported_but_not_remembered(monkeypatch):
    """A network blip says nothing about the key. Reporting False is honest
    -- we cannot open a PR right now -- but caching it would keep the probe
    red for five minutes after GitHub came back."""
    _configure(monkeypatch)

    def failing(request):
        raise httpx.ConnectError("no route to host")

    assert github_app.app_auth_ok(transport=httpx.MockTransport(failing)) is False
    assert github_app.app_auth_ok(transport=_transport(200)) is True


def test_401_raises_the_auth_subclass_not_the_generic_error(monkeypatch):
    """The processor tells 'our credentials are broken' from 'this repo has a
    problem' by exception type, so the type is the contract."""
    pem = _key_pem()
    with pytest.raises(github_app.GitHubAppAuthError):
        github_app.installation_token_for_repo(
            "owner", "repo", app_id="Iv23test", private_key=pem,
            transport=_transport(401, {"message": "could not be decoded"}),
        )


def test_404_stays_the_plain_error(monkeypatch):
    """'Not installed on this repo' is the caller's problem and must NOT be
    the auth subclass, or a repo that will never work would be retried."""
    pem = _key_pem()
    with pytest.raises(github_app.GitHubAppError) as caught:
        github_app.installation_token_for_repo(
            "owner", "repo", app_id="Iv23test", private_key=pem,
            transport=_transport(404, {"message": "Not Found"}),
        )
    assert not isinstance(caught.value, github_app.GitHubAppAuthError)
    assert "not installed" in str(caught.value)
