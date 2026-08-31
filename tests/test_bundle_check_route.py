"""POST /v1/audits/{id}/bundle-check — the first endpoint that fetches an
arbitrary customer-supplied URL.

app/proof/served_bundle.py is tested thoroughly on its own. What CANNOT be
inferred from those tests is whether the route in front of it actually applies
the guard, the consent phrase, the token check and the rate limit — a route
that forgot any one of them would leave every module-level test green while the
deployed endpoint was an open fetch proxy. So these drive the HTTP surface and
assert on what the transport was asked to do, not only on the response body.

THE FETCH IS ALWAYS INJECTED. `get_bundle_fetch` is overridden in every test
here, and `_RecordingFetch` fails the test if it is asked for a URL the guard
should have refused. A test that merely asserted `status == "skipped"` would
pass even if the request had already gone out.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app.main import app
from app.routes.dependencies import (
    get_audit_repo,
    get_bundle_fetch,
    get_rate_limiter,
    get_served_bundle_check_repo,
)
from app.routes.rls_check import CONSENT_PHRASE

client = TestClient(app)

AUDIT_ID = "11111111-2222-3333-4444-555555555555"
TOKEN = "audit-access-token"  # noqa: S105 - test fixture, not a credential

# A real-shaped service_role JWT signed with a secret that is NOT the published
# demo one, so the production oracle grades it critical rather than carving it
# out as scaffolding.
SERVICE_ROLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnMiLCJyb2xlIjoi"
    "c2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9"
    ".b3VyLXRlc3Qtc2lnbmF0dXJlLW5vdC10aGUtcHVibGlzaGVkLWRlbW8tb25l"
)

INDEX_HTML = '<html><script src="/assets/app.js"></script></html>'
BUNDLE_JS = f'const k="{SERVICE_ROLE_JWT}";export default k;'


class _FakeAuditRepo:
    def __init__(self, audit: dict | None):
        self._audit = audit

    async def get_authorized(self, audit_id, token):
        if self._audit is None:
            return None
        if audit_id != AUDIT_ID or token != TOKEN:
            return None
        return self._audit


class _FakeLedger:
    """Records the ledger calls so the before-the-request ordering is testable."""

    def __init__(self, configured: bool = True):
        self.configured = configured
        self.started: list[dict] = []
        self.completed: list[dict] = []

    async def start(self, *, audit_id, client_key, consent_phrase):
        self.started.append({"audit_id": audit_id, "client_key": client_key,
                             "consent_phrase": consent_phrase})
        if not self.configured:
            return None
        return {"id": uuid.uuid4()}

    async def complete(self, check_id, *, deployment_url, outcome,
                       assets_read, result):
        self.completed.append({"deployment_url": deployment_url,
                               "outcome": outcome, "assets_read": assets_read,
                               "result": result})
        return {"id": check_id}


class _RecordingFetch:
    """Serves a two-file deployment and REFUSES to be asked for anything else.

    The refusal is the point: if the route ever let a request through that the
    guard should have stopped, this raises inside the request and the test
    fails loudly, instead of the assertion passing on a response body that
    happens to look right.
    """

    def __init__(self, pages: dict[str, str]):
        self.pages = pages
        self.requested: list[str] = []

    def __call__(self, url, host, port, max_bytes):
        self.requested.append(url)
        if url not in self.pages:
            raise AssertionError(f"fetched a URL the test never allowed: {url}")
        return 200, self.pages[url]


def _override(*, audit, ledger, fetch, limiter=None):
    app.dependency_overrides[get_audit_repo] = lambda: _FakeAuditRepo(audit)
    app.dependency_overrides[get_served_bundle_check_repo] = lambda: ledger
    app.dependency_overrides[get_bundle_fetch] = lambda: fetch
    if limiter is not None:
        app.dependency_overrides[get_rate_limiter] = lambda: limiter


def _clear():
    app.dependency_overrides.clear()


def _post(**form):
    body = {"deployment_url": "https://app.example/", "consent": CONSENT_PHRASE,
            "token": TOKEN}
    body.update(form)
    return client.post(f"/v1/audits/{AUDIT_ID}/bundle-check", data=body)


@pytest.fixture
def leaking_deployment():
    return _RecordingFetch({
        "https://app.example/": INDEX_HTML,
        "https://app.example:443/assets/app.js": BUNDLE_JS,
    })


def test_a_leaked_service_role_key_is_found_and_never_returned(
        monkeypatch, leaking_deployment):
    """The whole point of the endpoint, and the one thing it must never do.

    The raw token is what makes the key usable and is abused within minutes of
    exposure. It stays in-process so a probe could consume it; nothing in the
    response may carry it.
    """
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=leaking_deployment)
    try:
        response = _post()
    finally:
        _clear()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "checked"
    assert body["leaked"] is True
    assert body["findings"][0]["pattern"] == "supabase_service_role"
    assert SERVICE_ROLE_JWT not in response.text, "the raw token left the process"


def test_a_secret_always_carries_a_disclosure(monkeypatch, leaking_deployment):
    """The invariant from app/proof/disclosure.py, asserted at the edge: there
    is no path from "found a secret" to a response that does not say so."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=leaking_deployment)
    try:
        body = _post().json()
    finally:
        _clear()

    assert len(body["disclosures"]) == len(body["findings"]) == 1
    disclosure = body["disclosures"][0]
    assert disclosure["ownership"] == "consented"
    assert disclosure["channel"] == "report"
    assert disclosure["may_probe"] is True


def test_consent_must_be_the_phrase_and_nothing_is_fetched_without_it():
    """`consent=true` is what a client library sets by default. The refusal has
    to happen before any request leaves, so the fetch is booby-trapped."""
    def _never(*a, **kw):
        raise AssertionError("fetched despite consent not being given")

    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=_never)
    try:
        response = _post(consent="true")
    finally:
        _clear()

    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "consent_not_given"
    assert ledger.started == [], "a ledger row was opened for a refused consent"


def test_a_wrong_token_is_404_and_fetches_nothing():
    """Same rule as GET /v1/audits/{id}: never confirm an id exists to somebody
    who does not hold its token."""
    def _never(*a, **kw):
        raise AssertionError("fetched for an unauthorized caller")

    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=_never)
    try:
        response = _post(token="wrong-token")
    finally:
        _clear()

    assert response.status_code == 404
    assert ledger.started == []


@pytest.mark.parametrize("addresses", [
    ["169.254.169.254"],             # cloud metadata
    ["10.0.0.5"],                    # RFC-1918
    ["127.0.0.1"],                   # loopback
    ["93.184.216.34", "10.0.0.5"],   # dual-record rebind
])
def test_the_guard_applies_through_the_route(monkeypatch, addresses):
    """The module refuses these; this proves the ROUTE does not route around
    it. `_RecordingFetch` raises if asked for anything, so a guard that failed
    to run fails the test rather than quietly returning a body."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: (_ for _ in ()).throw(
                            __import__("app.proof.served_bundle", fromlist=["x"])
                            .UnsafeDeploymentUrl("refused")))
    fetch = _RecordingFetch({})
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post(deployment_url="https://metadata.evil/").json()
    finally:
        _clear()

    assert body["status"] == "skipped"
    assert body["evidence"]["reason"] == "unsafe_url"
    assert fetch.requested == [], "the route fetched a refused address"


def test_the_ledger_row_opens_before_the_request_and_closes_after(
        monkeypatch, leaking_deployment):
    """A row written only on success cannot show the check that crashed
    halfway, which is the case somebody would actually ask about."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=leaking_deployment)
    try:
        body = _post().json()
    finally:
        _clear()

    assert len(ledger.started) == 1
    assert ledger.started[0]["consent_phrase"] == CONSENT_PHRASE
    assert len(ledger.completed) == 1
    assert ledger.completed[0]["outcome"] == "checked"
    assert body["persisted"] is True

    # The stored result must be the same redacted shape the caller got.
    stored = ledger.completed[0]["result"]
    assert SERVICE_ROLE_JWT not in str(stored), "the raw token reached the ledger"


def test_no_database_still_answers(monkeypatch, leaking_deployment):
    """The ledger is accounting, not a precondition. A deployment without
    DATABASE_URL must still get the finding -- and must be told it was not
    recorded rather than left to assume it was."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger(configured=False)
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=leaking_deployment)
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["leaked"] is True
    assert body["persisted"] is False
    assert ledger.completed == []


def test_the_anon_key_is_reported_as_publishable_not_a_leak(monkeypatch):
    """The anti-false-alarm half of the registry, at the edge. A Supabase anon
    key is DESIGNED to ship in the browser; a tool that calls it a leak is the
    tool nobody trusts the second time."""
    anon = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnMiLCJyb2xl"
        "IjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ"
        ".b3VyLXRlc3Qtc2lnbmF0dXJlLW5vdC10aGUtcHVibGlzaGVkLWRlbW8tb25l"
    )
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    fetch = _RecordingFetch({
        "https://app.example/": INDEX_HTML,
        "https://app.example:443/assets/app.js": f'const k="{anon}";',
    })
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["leaked"] is False
    assert body["findings"] == []
    assert [p["pattern"] for p in body["publishable"]] == ["supabase_anon_key"]
    assert body["disclosures"] == []


def test_the_route_is_registered_exactly_once():
    """A double `include_router` would serve the path twice, and the second
    copy would be dead code that a reader reasonably assumes is live.

    Counted through `original_router` rather than `app.routes`: this FastAPI
    wraps each included router in an `_IncludedRouter` that exposes no `.routes`
    of its own, so a walk over `app.routes` finds the path zero times and an
    assertion built on it would fail while the endpoint works — which is
    exactly what the first version of this test did.
    """
    path = "/v1/audits/{audit_id}/bundle-check"
    found = 0
    for entry in main_mod.app.routes:
        if getattr(entry, "path", None) == path:
            found += 1
        inner = getattr(entry, "original_router", None)
        if inner is not None:
            found += sum(1 for r in inner.routes
                         if getattr(r, "path", None) == path)
    assert found == 1, f"expected one registration of {path}, found {found}"
