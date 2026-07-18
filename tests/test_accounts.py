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
    API_KEY_PEPPER_ENV,
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


class FakeAccountRepo:
    """In-memory AccountRepository stand-in. Indexes accounts by both the
    HMAC key_hash (primary lookup) and the plaintext api_key (transitional
    fallback), so it exercises whichever path resolve_account takes.
    Unknown key -> None, like the real repo's miss / not-configured
    contract."""

    def __init__(self, by_key: dict | None = None):
        self._by_key = by_key or {}
        self._by_hash: dict = {}
        for acct in self._by_key.values():
            if acct.get("key_hash"):
                self._by_hash[acct["key_hash"]] = acct

    async def get_by_key_hash(self, key_hash: str):
        return self._by_hash.get(key_hash)

    async def get_by_api_key(self, api_key: str):
        return self._by_key.get(api_key)


def _pro_repo(key: str = "sk_live_prokey"):
    return FakeAccountRepo({key: {"id": "acct-1", "api_key": key, "tier": "pro"}})


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

def test_free_entitlements_use_the_passed_limit_and_deny_paid_flags():
    ent = entitlements_for_tier("free", free_daily_limit=5)
    assert ent == Entitlements(
        daily_audit_limit=5, private_repos_allowed=False, priority_queue=False
    )


def test_pro_entitlements_grant_higher_limit_and_paid_flags():
    ent = entitlements_for_tier("pro", free_daily_limit=5)
    assert ent.daily_audit_limit == PRO_DAILY_AUDIT_LIMIT
    assert ent.private_repos_allowed is True
    assert ent.priority_queue is True


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


# --- resolve_account: hashed lookup + backward-compat fallback ---

class _Request:
    def __init__(self, key: str | None):
        self.headers = {"authorization": f"Bearer {key}"} if key else {}


async def test_resolve_account_finds_by_hash(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
    key = "sk_live_realkey"
    acct = {"id": "acct-1", "api_key": None,
            "key_hash": hash_api_key(key), "tier": "pro"}
    repo = FakeAccountRepo({"ignored": acct})  # indexed by key_hash

    found = await resolve_account(_Request(key), repo)
    assert found is acct


async def test_resolve_account_wrong_key_not_found(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
    good = "sk_live_realkey"
    acct = {"id": "acct-1", "api_key": None,
            "key_hash": hash_api_key(good), "tier": "pro"}
    repo = FakeAccountRepo({"ignored": acct})

    assert await resolve_account(_Request("sk_live_wrongkey"), repo) is None


async def test_resolve_account_falls_back_to_plaintext_for_prebackfill_key(monkeypatch):
    # Account issued before migration 0009: key_hash is NULL, only plaintext
    # api_key exists. The hashed lookup misses; the fallback finds it.
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
    key = "sk_live_legacykey"
    acct = {"id": "acct-legacy", "api_key": key, "key_hash": None, "tier": "pro"}
    repo = FakeAccountRepo({key: acct})  # only plaintext-indexed (no key_hash)

    found = await resolve_account(_Request(key), repo)
    assert found is acct


async def test_resolve_account_no_key_is_anonymous(monkeypatch):
    monkeypatch.setenv(API_KEY_PEPPER_ENV, TEST_PEPPER)
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
    assert body["entitlements"] == {
        "daily_audit_limit": 5,
        "private_repos_allowed": False,
        "priority_queue": False,
    }


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
    assert body["entitlements"] == {
        "daily_audit_limit": PRO_DAILY_AUDIT_LIMIT,
        "private_repos_allowed": True,
        "priority_queue": True,
    }
    # the endpoint never echoes the secret back
    assert "api_key" not in json.dumps(body)


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
