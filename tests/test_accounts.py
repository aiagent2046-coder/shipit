"""Tests for the paywall foundation (Stage 1): account resolution from
an API key, tier-aware rate limiting, and GET /v1/account. No real
Postgres — a FakeAccountRepo stands in for AccountRepository, same idea
as tests/test_db.py's FakePool. The outbound-fetch and LLM paths are not
exercised here; audits use valid Next.js zips so they reach the quota
check without needing either.
"""

import io
import json
import zipfile

from fastapi.testclient import TestClient

import pytest

from app.accounts import (
    API_KEY_COOKIE,
    API_KEY_PEPPER_ENV,
    CSRF_HEADER,
    PRO_DAILY_AUDIT_LIMIT,
    Entitlements,
    api_key_from_request,
    api_key_prefix,
    entitlements_for_tier,
    generate_api_key,
    hash_api_key,
    require_pepper,
    resolve_account,
    validate_api_key_pepper_configured,
)
from app.main import app, get_account_repo, get_rate_limiter
from app.ratelimit import RateLimiter

client = TestClient(app)

# A made-up pepper for tests only — never a real production value.
TEST_PEPPER = "test-pepper-not-a-real-secret"


@pytest.fixture(autouse=True)
def _pepper_set(monkeypatch):
    """Accounts are only usable with a pepper configured (post-0009 keys are
    matched purely by HMAC hash). Default every test to a configured pepper;
    the few tests that assert the unset/wrong-pepper behavior override this
    with their own monkeypatch.delenv/setenv, which wins."""
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)


class FakeAccountRepo:
    """In-memory AccountRepository stand-in. Indexes accounts by their HMAC
    key_hash only — the plaintext api_key column no longer exists (migration
    0019), so a key is resolvable solely by hashing it. Unknown hash -> None,
    like the real repo's miss / not-configured contract."""

    def __init__(self, accounts: list | None = None):
        self._by_hash: dict = {}
        for acct in accounts or []:
            if acct.get("key_hash"):
                self._by_hash[acct["key_hash"]] = acct

    async def get_by_key_hash(self, key_hash: str):
        return self._by_hash.get(key_hash)

    async def rotate_key(self, account_id: str):
        acct = next(
            (a for a in self._by_hash.values() if a["id"] == account_id), None
        )
        if acct is None:
            return None
        old_hash = acct["key_hash"]
        new_key = generate_api_key()
        acct["key_prefix"] = api_key_prefix(new_key)
        acct["key_hash"] = hash_api_key(new_key)
        acct["api_key"] = new_key
        self._by_hash.pop(old_hash, None)
        self._by_hash[acct["key_hash"]] = acct
        return acct


def _account_for(key: str, *, account_id: str = "acct-1", tier: str = "pro"):
    return {
        "id": account_id,
        "key_prefix": api_key_prefix(key),
        "key_hash": hash_api_key(key),
        "tier": tier,
    }


def _pro_repo(key: str = "sk_live_prokey"):
    return FakeAccountRepo([_account_for(key)])


def _override_account_repo(repo):
    app.dependency_overrides[get_account_repo] = lambda: repo


def _clear_account_repo():
    app.dependency_overrides.pop(get_account_repo, None)


def make_valid_zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode(),
        )
    buf.seek(0)
    return buf


# --- entitlement resolution (pure) ---

def test_free_entitlements_use_the_passed_limit():
    ent = entitlements_for_tier("free", free_daily_limit=5)
    assert ent == Entitlements(daily_audit_limit=5)


def test_pro_entitlements_grant_a_higher_limit():
    ent = entitlements_for_tier("pro", free_daily_limit=5)
    assert ent.daily_audit_limit == PRO_DAILY_AUDIT_LIMIT


def test_unknown_tier_falls_back_to_free_not_an_error():
    ent = entitlements_for_tier("enterprise", free_daily_limit=7)
    assert ent == entitlements_for_tier("free", free_daily_limit=7)


def test_generated_api_key_shape():
    key = generate_api_key()
    assert key.startswith("sk_live_")
    assert len(key) > len("sk_live_")
    assert generate_api_key() != generate_api_key()  # random


# --- key hashing + pepper (server-side HMAC) ---

def test_hash_is_deterministic_and_key_specific(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
    h1 = hash_api_key("sk_live_aaa")
    # same key + same pepper -> same hash (so lookup is possible)
    assert hash_api_key("sk_live_aaa") == h1
    # different keys -> different hashes
    assert hash_api_key("sk_live_bbb") != h1
    # it's a hash, not the key, and hex sha256 length
    assert "sk_live_aaa" not in h1
    assert len(h1) == 64


def test_hash_depends_on_pepper(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, "pepper-one")
    a = hash_api_key("sk_live_same")
    monkeypatch.setenv(API_KEY_PEPPER_ENV, "pepper-two")
    b = hash_api_key("sk_live_same")
    assert a != b  # a DB leak without the pepper can't reproduce the hash


def test_require_pepper_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv(API_KEY_PEPPER_ENV, raising=False)
    with pytest.raises(RuntimeError) as exc:
        require_pepper()
    assert API_KEY_PEPPER_ENV in str(exc.value)


def test_hash_refuses_empty_default_when_pepper_unset(monkeypatch):
    # No silent fallback to an empty/default pepper.
    monkeypatch.delenv(API_KEY_PEPPER_ENV, raising=False)
    with pytest.raises(RuntimeError):
        hash_api_key("sk_live_x")


def test_startup_guard_raises_when_db_set_but_pepper_missing(monkeypatch):
    monkeypatch.delenv(API_KEY_PEPPER_ENV, raising=False)
    with pytest.raises(RuntimeError) as exc:
        validate_api_key_pepper_configured(database_configured=True)
    assert API_KEY_PEPPER_ENV in str(exc.value)


def test_startup_guard_ok_when_pepper_present(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
    validate_api_key_pepper_configured(database_configured=True)  # no raise


def test_startup_guard_ok_when_db_not_configured(monkeypatch):
    # DB-less deployment: accounts unusable anyway, pepper not required.
    monkeypatch.delenv(API_KEY_PEPPER_ENV, raising=False)
    validate_api_key_pepper_configured(database_configured=False)  # no raise


def test_api_key_prefix_is_short_and_nonrevealing():
    key = "sk_live_abcdefghijklmnop"
    assert api_key_prefix(key) == "sk_live_abcd"  # KEY_PREFIX_LEN=12
    assert len(api_key_prefix(key)) < len(key)


# --- resolve_account: hashed lookup only ---

class _Request:
    def __init__(self, key: str | None):
        self.headers = {"authorization": f"Bearer {key}"} if key else {}


async def test_resolve_account_finds_by_hash():
    key = "sk_live_realkey"
    acct = _account_for(key)
    repo = FakeAccountRepo([acct])  # indexed by key_hash

    found = await resolve_account(_Request(key), repo)
    assert found is acct


async def test_resolve_account_wrong_key_not_found():
    acct = _account_for("sk_live_realkey")
    repo = FakeAccountRepo([acct])

    assert await resolve_account(_Request("sk_live_wrongkey"), repo) is None


async def test_resolve_account_without_pepper_is_anonymous(monkeypatch):
    # No pepper -> can't hash the presented key, so fall back to free rather
    # than raise. (A real DB deployment is guaranteed a pepper by the startup
    # guard; this is the degrade-to-free safety net.)
    key = "sk_live_realkey"
    acct = _account_for(key)
    repo = FakeAccountRepo([acct])
    monkeypatch.delenv(API_KEY_PEPPER_ENV, raising=False)

    assert await resolve_account(_Request(key), repo) is None


async def test_resolve_account_no_key_is_anonymous():
    repo = _pro_repo()
    assert await resolve_account(_Request(None), repo) is None


# --- api_key extraction from the header ---

class _Req:
    def __init__(self, headers):
        self.headers = headers


def test_api_key_extracted_from_bearer_header():
    assert api_key_from_request(_Req({"authorization": "Bearer sk_live_x"})) == "sk_live_x"


def test_api_key_absent_or_wrong_scheme_is_none():
    assert api_key_from_request(_Req({})) is None
    assert api_key_from_request(_Req({"authorization": "Basic abc"})) is None
    assert api_key_from_request(_Req({"authorization": "Bearer "})) is None


# --- GET /v1/account: both cases ---

def test_account_endpoint_anonymous_returns_free_entitlements():
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=5)
    try:
        resp = client.get("/v1/account")  # no Authorization header
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == "free"
    assert body["authenticated"] is False
    assert body["entitlements"] == {"daily_audit_limit": 5}


def test_account_endpoint_unknown_key_is_free_not_401():
    _override_account_repo(FakeAccountRepo())  # knows no keys
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=5)
    try:
        resp = client.get(
            "/v1/account", headers={"Authorization": "Bearer sk_live_nope"}
        )
    finally:
        _clear_account_repo()
        app.dependency_overrides.pop(get_rate_limiter, None)
    assert resp.status_code == 200
    assert resp.json()["tier"] == "free"
    assert resp.json()["authenticated"] is False


def test_account_endpoint_valid_key_returns_pro_entitlements():
    _override_account_repo(_pro_repo("sk_live_prokey"))
    try:
        resp = client.get(
            "/v1/account", headers={"Authorization": "Bearer sk_live_prokey"}
        )
    finally:
        _clear_account_repo()
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == "pro"
    assert body["authenticated"] is True
    assert body["entitlements"] == {"daily_audit_limit": PRO_DAILY_AUDIT_LIMIT}
    # the endpoint never echoes the secret back
    assert "api_key" not in json.dumps(body)


# --- key rotation: repo + POST /v1/account/rotate-key ---

async def test_rotate_key_invalidates_old_and_resolves_new():
    key = "sk_live_prokey"
    repo = _pro_repo(key)

    rotated = await repo.rotate_key("acct-1")
    new_key = rotated["api_key"]
    assert new_key != key
    assert rotated["tier"] == "pro"  # tier preserved across rotation

    # old key no longer resolves; new key does
    assert await resolve_account(_Request(key), repo) is None
    found = await resolve_account(_Request(new_key), repo)
    assert found["id"] == "acct-1"


async def test_rotate_key_unknown_account_returns_none():
    repo = _pro_repo("sk_live_prokey")
    assert await repo.rotate_key("acct-does-not-exist") is None


def test_rotate_endpoint_requires_recognized_key():
    _override_account_repo(FakeAccountRepo())  # knows no keys
    try:
        resp = client.post(
            "/v1/account/rotate-key",
            headers={"Authorization": "Bearer sk_live_nope"},
        )
    finally:
        _clear_account_repo()
    assert resp.status_code == 401


def test_rotate_endpoint_anonymous_is_401():
    _override_account_repo(_pro_repo("sk_live_prokey"))
    try:
        resp = client.post("/v1/account/rotate-key")  # no Authorization
    finally:
        _clear_account_repo()
    assert resp.status_code == 401


def test_rotate_endpoint_mints_new_key_and_invalidates_old():
    repo = _pro_repo("sk_live_prokey")
    _override_account_repo(repo)
    try:
        resp = client.post(
            "/v1/account/rotate-key",
            headers={"Authorization": "Bearer sk_live_prokey"},
        )
        assert resp.status_code == 200
        body = resp.json()
        new_key = body["api_key"]
        assert new_key.startswith("sk_live_")
        assert new_key != "sk_live_prokey"
        assert body["tier"] == "pro"
        assert body["key_prefix"] == api_key_prefix(new_key)

        # old key is now rejected, new key is accepted by GET /v1/account
        old = client.get(
            "/v1/account", headers={"Authorization": "Bearer sk_live_prokey"}
        )
        assert old.json()["tier"] == "free"
        new = client.get(
            "/v1/account", headers={"Authorization": f"Bearer {new_key}"}
        )
        assert new.json()["tier"] == "pro"
    finally:
        _clear_account_repo()


# --- tier-aware rate limiting on /v1/audits ---

def test_pro_account_gets_higher_audit_limit():
    # A tiny shared limiter (free budget = 2). A pro caller passes the pro
    # limit (100) per call, so a 3rd audit that would 429 an anonymous
    # caller still succeeds.
    tiny = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny
    _override_account_repo(_pro_repo("sk_live_prokey"))
    try:
        for _ in range(3):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
                headers={"Authorization": "Bearer sk_live_prokey"},
            )
            assert resp.status_code == 202
    finally:
        _clear_account_repo()
        app.dependency_overrides.pop(get_rate_limiter, None)


def test_anonymous_caller_free_limit_is_unchanged_regression():
    # CRITICAL regression: an anonymous caller (no key) must be limited
    # exactly as before — free budget of 2, the 3rd request is 429. Same
    # limiter as the pro test above; the difference is purely the tier.
    tiny = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny
    try:
        for _ in range(2):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
            )
            assert resp.status_code == 202
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
        )
        assert resp.status_code == 429
        assert resp.json()["detail"]["reason"] == "rate_limited"
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)


def test_unknown_key_audit_is_limited_as_free():
    # An unrecognized key must not smuggle a pro budget: it resolves to
    # None -> free, so it hits the free limit like any anonymous caller.
    tiny = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny
    _override_account_repo(FakeAccountRepo())  # knows no keys
    try:
        for _ in range(2):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
                headers={"Authorization": "Bearer sk_live_unknown"},
            )
            assert resp.status_code == 202
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
            headers={"Authorization": "Bearer sk_live_unknown"},
        )
        assert resp.status_code == 429
    finally:
        _clear_account_repo()
        app.dependency_overrides.pop(get_rate_limiter, None)


# --- session cookie and its CSRF gate ---
#
# The key used to sit in sessionStorage, readable by any script on the page.
# It now travels in an HttpOnly cookie. SameSite=Lax is the CSRF defence and
# is only possible because the API shares a registrable domain with the
# frontend (#172); CSRF_HEADER is the second lock, for same-site callers Lax
# cannot distinguish -- a Deploy Pack preview on a drydock.co subdomain
# running a customer's code.

PRO_KEY = "sk_live_prokey"


class _Req:
    """Minimal duck-typed request: api_key_from_request only reads .headers
    and .cookies."""

    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.cookies = cookies or {}


def test_cookie_without_the_csrf_header_is_not_a_key():
    """SameSite=Lax already keeps this cookie off a cross-site request. This
    check is for the same-site one it cannot see: ten POST endpoints here
    parse no body, so a bare cookie would be a CSRF primitive on each."""
    req = _Req(cookies={API_KEY_COOKIE: PRO_KEY})
    assert api_key_from_request(req) is None


def test_cookie_with_the_csrf_header_is_a_key():
    req = _Req(headers={CSRF_HEADER: "1"}, cookies={API_KEY_COOKIE: PRO_KEY})
    assert api_key_from_request(req) == PRO_KEY


def test_the_csrf_header_value_is_never_checked():
    """Presence is the mechanism -- it forces a preflight the attacker's
    origin cannot pass. A value would be a secret to leak for no gain."""
    for value in ("1", "anything", "0", "false"):
        req = _Req(headers={CSRF_HEADER: value}, cookies={API_KEY_COOKIE: PRO_KEY})
        assert api_key_from_request(req) == PRO_KEY


def test_authorization_header_needs_no_csrf_header():
    """A caller that sets Authorization already holds the key, and cannot be
    made to by a third party's page. curl and scripts keep working."""
    req = _Req(headers={"authorization": f"Bearer {PRO_KEY}"})
    assert api_key_from_request(req) == PRO_KEY


def test_authorization_header_wins_over_a_cookie():
    req = _Req(headers={"authorization": "Bearer sk_live_fromheader",
                        CSRF_HEADER: "1"},
               cookies={API_KEY_COOKIE: "sk_live_fromcookie"})
    assert api_key_from_request(req) == "sk_live_fromheader"


def test_login_sets_an_httponly_session_cookie():
    _override_account_repo(_pro_repo(PRO_KEY))
    try:
        r = client.post("/v1/auth/login", json={"api_key": PRO_KEY})
        assert r.status_code == 200
        assert r.json()["authenticated"] is True
        assert r.json()["tier"] == "pro"

        raw = r.headers["set-cookie"]
        assert API_KEY_COOKIE in raw
        assert "HttpOnly" in raw            # unreadable from JavaScript
        assert "Secure" in raw
        assert "samesite=lax" in raw.lower()   # not None: see #172
        assert "max-age" not in raw.lower() # dies with the browser session,
        assert "expires" not in raw.lower() # exactly like sessionStorage did
    finally:
        _clear_account_repo()


def test_login_rejects_an_unknown_key_instead_of_downgrading_it():
    """The caller asserted they hold a key. Answering 200-free would look
    like a login that worked and bought nothing."""
    _override_account_repo(FakeAccountRepo([]))
    try:
        r = client.post("/v1/auth/login", json={"api_key": "sk_live_nope"})
        assert r.status_code == 401
        assert "set-cookie" not in r.headers
    finally:
        _clear_account_repo()


def test_login_without_a_key_is_422_not_500():
    _override_account_repo(_pro_repo(PRO_KEY))
    try:
        assert client.post("/v1/auth/login", json={}).status_code == 422
        assert client.post("/v1/auth/login", json={"api_key": "  "}).status_code == 422
    finally:
        _clear_account_repo()


def test_logout_clears_the_cookie_and_needs_no_session():
    """Parity with the old sessionStorage removal, which the page could do
    itself. Unauthenticated on purpose: a stale session must be clearable."""
    r = client.post("/v1/auth/logout")
    assert r.status_code == 200
    raw = r.headers["set-cookie"]
    assert API_KEY_COOKIE in raw
    assert 'max-age=0' in raw.lower() or "1970" in raw


def test_the_cookie_authenticates_a_real_request_end_to_end():
    # An https base URL, because the cookie is Secure and no client will send
    # a Secure cookie over http. That refusal is the flag working, not a test
    # inconvenience -- over http this session would simply not exist.
    secure = TestClient(app, base_url="https://testserver")
    _override_account_repo(_pro_repo(PRO_KEY))
    try:
        assert secure.post("/v1/auth/login", json={"api_key": PRO_KEY}).status_code == 200

        # The cookie jar now holds it, so this is the browser's next call.
        r = secure.get("/v1/account", headers={CSRF_HEADER: "1"})
        assert r.json()["authenticated"] is True

        # Same cookie, no CSRF header: what a third party's page could send.
        r = secure.get("/v1/account")
        assert r.json()["authenticated"] is False
        assert r.json()["tier"] == "free"

        # And after logout the cookie stops working even with the header.
        assert secure.post("/v1/auth/logout").status_code == 200
        r = secure.get("/v1/account", headers={CSRF_HEADER: "1"})
        assert r.json()["authenticated"] is False
    finally:
        secure.cookies.clear()
        _clear_account_repo()


def test_the_account_payload_advertises_nothing_that_gates_nothing():
    """The guard against the flags creeping back.

    `private_repos_allowed` and `priority_queue` shipped in this payload for
    months, described in app/accounts.py as "honest placeholders". They were
    honest in that file and dishonest on the wire: a caller reading
    `priority_queue: false` on free and `true` on pro concludes that paying
    buys a faster queue, and it does not. A comment the caller never sees is
    not a disclaimer.

    So the assertion is on the payload's exact shape, not on the two names.
    A new field that gates nothing fails this test the same way, which is the
    point -- the rule is about the class of mistake, not about these two.
    """
    fields = set(Entitlements.__dataclass_fields__)
    assert fields == {"daily_audit_limit"}, (
        f"entitlements gained {fields - {'daily_audit_limit'}}. Every field "
        "here is reported by GET /v1/account and reads as a promise. Add one "
        "only together with the code that enforces it."
    )
