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


def test_a_clean_bundle_still_reports_what_was_read(monkeypatch):
    """THE DEFECT THE FIRST REAL RUN FOUND, and the reason it mattered.

    Against our own deployment on 2026-08-31 the endpoint answered
    `status: checked`, `leaked: false` — and `assets_read: []`. The list was
    only appended to when a scan found a secret, so a clean bundle produced the
    same empty list as a bundle nobody fetched, and the stored ledger row could
    not say what had been read.

    That is the disjoint-population failure this project keeps guarding
    against, in the one place where the answer is "we found nothing": absence
    of evidence rendered identical to evidence of absence. A row that cannot
    show its scope is not accounting.
    """
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    clean = _RecordingFetch({
        "https://app.example/": INDEX_HTML,
        "https://app.example:443/assets/app.js": "export const answer = 42;",
    })
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=clean)
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["leaked"] is False and body["findings"] == []
    assert body["assets_read"] == [
        "(served html)", "https://app.example:443/assets/app.js"], (
        "a clean bundle must still report the scope of the fetch")
    # And the ledger carries it, which is the half a support question reads.
    assert ledger.completed[0]["assets_read"] == body["assets_read"]


def test_a_capped_asset_list_says_so(monkeypatch):
    """20 entries must not read as "the page had 20 scripts".

    A Next.js build splits into far more chunks than MAX_ASSETS, so a clean
    result on a large page covers the part we looked at and nothing more. The
    caller has to be able to tell which of the two they got.
    """
    from app.proof.served_bundle import MAX_ASSETS

    many = MAX_ASSETS + 5
    html = "<html>" + "".join(
        f'<script src="/assets/c{i}.js"></script>' for i in range(many)
    ) + "</html>"
    pages = {"https://app.example/": html}
    for i in range(many):
        pages[f"https://app.example:443/assets/c{i}.js"] = "const x = 1;"

    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=_RecordingFetch(pages))
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["evidence"]["assets_found"] == many
    assert body["evidence"]["assets_truncated"] is True
    # html + the capped assets, and not one more.
    assert len(body["assets_read"]) == MAX_ASSETS + 1


def test_an_uncapped_page_is_not_reported_as_truncated(monkeypatch):
    """The other side of the same boundary: without it, always-true would pass."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger,
              fetch=_RecordingFetch({
                  "https://app.example/": INDEX_HTML,
                  "https://app.example:443/assets/app.js": "const x = 1;"}))
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["evidence"]["assets_found"] == 1
    assert body["evidence"]["assets_truncated"] is False


def test_a_chunk_named_twice_is_fetched_once(monkeypatch):
    """Observed on our own deployment (2026-08-31): Next.js names the same
    chunk as a `<script src>` AND a preload `href`, both match the pattern, and
    it was fetched twice.

    `_RecordingFetch.requested` is the assertion: a second request for the
    same URL is what this test is about, so it is counted directly rather than
    inferred from the response body.
    """
    html = (
        '<html>'
        '<link rel="modulepreload" href="/_next/chunks/a.js">'
        '<script src="/_next/chunks/a.js"></script>'
        '<script src="/_next/chunks/b.js"></script>'
        '</html>'
    )
    fetch = _RecordingFetch({
        "https://app.example/": html,
        "https://app.example:443/_next/chunks/a.js": "const a = 1;",
        "https://app.example:443/_next/chunks/b.js": "const b = 2;",
    })
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post().json()
    finally:
        _clear()

    assert fetch.requested.count(
        "https://app.example:443/_next/chunks/a.js") == 1, (
        "the same chunk was fetched more than once")
    assert body["evidence"]["assets_found"] == 2, (
        "the duplicate must not be counted as a second asset")
    assert body["assets_read"] == [
        "(served html)",
        "https://app.example:443/_next/chunks/a.js",
        "https://app.example:443/_next/chunks/b.js"]


def test_duplicates_do_not_spend_the_asset_budget(monkeypatch):
    """The cost that matters. A page naming a handful of chunks many times
    would otherwise exhaust MAX_ASSETS on repeats, read only the handful, and
    still report `assets_truncated: false` -- the cap spent invisibly while the
    evidence claims full coverage."""
    from app.proof.served_bundle import MAX_ASSETS

    distinct = 3
    html = "<html>" + "".join(
        f'<script src="/c{i % distinct}.js"></script>'
        for i in range(MAX_ASSETS * 2)
    ) + "</html>"
    pages = {"https://app.example/": html}
    for i in range(distinct):
        pages[f"https://app.example:443/c{i}.js"] = "const x = 1;"

    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger,
              fetch=_RecordingFetch(pages))
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["evidence"]["assets_found"] == distinct
    assert body["evidence"]["assets_truncated"] is False, (
        "40 references to 3 files is not a truncated page")
    assert len(body["assets_read"]) == distinct + 1  # + the html


def test_a_route_chunk_named_only_inside_js_is_found(monkeypatch):
    """THE REASON THE WALK IS TRANSITIVE.

    A bundler names route chunks inside JavaScript, never in the served HTML.
    A one-pass walk over `<script src>` reads the shell and calls the
    application clean — fine for a statement about our own landing page, not
    fine for one about somebody else's app, which is the claim this endpoint
    exists to support.

    Here the key is in a chunk the HTML never mentions. Before the queue, this
    returned `leaked: false`.
    """
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    fetch = _RecordingFetch({
        "https://app.example/": '<html><script src="/main.js"></script></html>',
        # The manifest: a quoted filename, which is all a chunk map is.
        "https://app.example:443/main.js":
            'const chunks={"page":"/chunks/route-9f2.js"};export default chunks;',
        "https://app.example:443/chunks/route-9f2.js": BUNDLE_JS,
    })
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["leaked"] is True, (
        "a key in a dynamically-imported chunk was missed")
    assert body["findings"][0]["location"] == \
        "https://app.example:443/chunks/route-9f2.js"
    assert body["evidence"]["assets_found"] == 2  # main.js + the discovered one


def test_discovery_widens_urls_but_never_addresses(monkeypatch):
    """The guard must hold for what a fetched file names, not only for what the
    customer typed. A chunk that references a script on another host — or one
    whose host resolves somewhere private — is refused at the same two gates as
    the seed URL.

    `_RecordingFetch` raises on anything it was not given, so a leak here fails
    the test rather than quietly widening the blast radius.
    """
    def _vet(host, port, **kw):
        if host != "app.example":
            raise __import__("app.proof.served_bundle", fromlist=["x"]) \
                .UnsafeDeploymentUrl(f"refused {host}")
        return ["93.184.216.34"]

    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet", _vet)
    fetch = _RecordingFetch({
        "https://app.example/": '<html><script src="/main.js"></script></html>',
        "https://app.example:443/main.js": (
            'a="https://evil.other/x.js";'          # off-origin, dropped early
            'b="https://internal.corp/y.js";'       # off-origin too
            'c="/ok.js";'
        ),
        "https://app.example:443/ok.js": "const ok = 1;",
    })
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["assets_read"] == [
        "(served html)",
        "https://app.example:443/main.js",
        "https://app.example:443/ok.js"]
    assert all("app.example" in u for u in fetch.requested)


def test_a_reference_cycle_terminates(monkeypatch):
    """Two chunks naming each other must not loop. The queue de-duplicates on
    the URL, so the cycle closes after one visit each — without that this hangs
    until MAX_ASSETS, wasting a customer's bandwidth on the same two files."""
    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    fetch = _RecordingFetch({
        "https://app.example/": '<html><script src="/a.js"></script></html>',
        "https://app.example:443/a.js": 'import "/b.js";',
        "https://app.example:443/b.js": 'import "/a.js";',
    })
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=fetch)
    try:
        body = _post().json()
    finally:
        _clear()

    assert fetch.requested.count("https://app.example:443/a.js") == 1
    assert fetch.requested.count("https://app.example:443/b.js") == 1
    assert body["evidence"]["assets_truncated"] is False


def test_a_transitive_walk_that_hits_the_cap_says_truncated(monkeypatch):
    """Discovery makes the cap reachable on a real app, so the honest signal
    matters more than it did. Whatever is still queued was never looked at."""
    from app.proof.served_bundle import MAX_ASSETS

    total = MAX_ASSETS + 10
    pages = {"https://app.example/":
             '<html><script src="/c0.js"></script></html>'}
    for i in range(total):
        # Each chunk names the next: a chain longer than the budget.
        pages[f"https://app.example:443/c{i}.js"] = f'import "/c{i + 1}.js";'
    pages[f"https://app.example:443/c{total}.js"] = "const end = 1;"

    monkeypatch.setattr("app.proof.served_bundle.resolve_and_vet",
                        lambda host, port, **kw: ["93.184.216.34"])
    ledger = _FakeLedger()
    _override(audit={"id": AUDIT_ID}, ledger=ledger, fetch=_RecordingFetch(pages))
    try:
        body = _post().json()
    finally:
        _clear()

    assert body["evidence"]["assets_truncated"] is True
    assert len(body["assets_read"]) == MAX_ASSETS + 1  # + the html
