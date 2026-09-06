"""The SSRF guard, consent, and extraction for the served-bundle fetch.

This is the first primitive in the codebase that fetches an ARBITRARY,
customer-supplied URL — every other outbound request is locked to a shape
(github.com, `<ref>.supabase.co`). So the rules here are not comments in a
plan; they are branches with tests, the same posture test_proof_rls_probe.py
takes, because a plan cannot stop a caller and a default can.

The test that matters most is the guard: a host that resolves to an internal
address must be refused, on every resolved record, before a byte is fetched.
The whole class hinges on never fetching an internal address.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from app.proof.served_bundle import (
    UnsafeDeploymentUrl,
    extract_service_role,
    fetch_served_bundle,
    resolve_and_vet,
    validate_deployment_url,
)
from app.scan.secrets import _SUPABASE_DEMO_JWT_SECRETS

# A non-public secret: a service_role JWT signed with it is a real credential,
# so app.scan.secrets._jwt_severity grades it `critical`.
_REAL_SECRET = "a-real-private-secret-not-the-public-demo-one-xxxx"  # noqa: S105
_DEMO_SECRET = _SUPABASE_DEMO_JWT_SECRETS[0]
_REF = "egoprezwkjaqacxtjwfl"


def _mint(role: str, secret: str = _REAL_SECRET) -> str:
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"},
                       separators=(",", ":")).encode())
    p = b64(json.dumps({"iss": "supabase", "ref": _REF, "role": role},
                       separators=(",", ":")).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(),
                       hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


SERVICE_KEY = _mint("service_role")
ANON_KEY = _mint("anon")
DEMO_SERVICE_KEY = _mint("service_role", _DEMO_SECRET)

HOST = "app.example.test"
URL = f"https://{HOST}/"


def _resolver(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int):
        if host not in mapping:
            raise OSError(f"NXDOMAIN {host}")
        return [(0, 0, 0, "", (ip, port)) for ip in mapping[host]]
    return resolve


_PUBLIC = _resolver({HOST: ["93.184.216.34"]})


def _fetch(html: str, js: str = "", *, calls: list | None = None):
    """Root URL -> html; any `.js`/`/assets/` URL -> js. Records calls so a
    test can assert an off-origin or private URL was never requested."""
    def _fn(url: str, host: str, port: int, max_bytes: int):
        if calls is not None:
            calls.append(url)
        if url.endswith((".js", ".mjs")) or "/assets/" in url:
            return 200, js
        return 200, html
    return _fn


# --- the guard: URL shape ---------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://app.example.test/",                       # http without loopback
    "ftp://app.example.test/",                        # non-http scheme
    "file:///etc/passwd",                             # file scheme
    "https://user:pass@app.example.test/",            # credential smuggling
    "https:///just-a-path",                           # no host
    "",                                               # empty
])
def test_a_bad_url_shape_is_refused(url) -> None:
    with pytest.raises(UnsafeDeploymentUrl):
        validate_deployment_url(url)


def test_a_plain_https_url_is_accepted_and_normalised() -> None:
    target = validate_deployment_url("https://app.example.test")
    assert target.host == "app.example.test"
    assert target.scheme == "https"
    assert target.port == 443
    assert target.url == "https://app.example.test/"


def test_loopback_is_refused_unless_explicitly_allowed() -> None:
    """The e2e serves a bundle on loopback and needs this; production must not
    have it, or the fetch becomes an SSRF into our own host."""
    with pytest.raises(UnsafeDeploymentUrl):
        validate_deployment_url("http://127.0.0.1:8080/")
    ok = validate_deployment_url("http://127.0.0.1:8080/", allow_loopback=True)
    assert ok.host == "127.0.0.1"


# --- the guard: the address behind the name --------------------------------

@pytest.mark.parametrize("addrs", [
    ["169.254.169.254"],            # cloud metadata (link-local)
    ["10.0.0.5"],                   # RFC-1918
    ["192.168.1.10"],              # RFC-1918
    ["172.16.0.1"],                # RFC-1918
    ["127.0.0.1"],                 # loopback
    ["0.0.0.0"],                   # unspecified
    ["fd00::1"],                   # IPv6 unique-local
    ["fe80::1"],                   # IPv6 link-local
    ["::1"],                       # IPv6 loopback
    ["93.184.216.34", "10.0.0.5"],  # dual-record rebind: one public, one private
])
def test_a_host_resolving_to_a_non_public_address_is_refused(addrs) -> None:
    """The host string is innocent; the address behind it is not. Every
    resolved record is checked, so a dual-record rebind is refused because any
    one private address rejects the whole host — the safe direction."""
    with pytest.raises(UnsafeDeploymentUrl):
        resolve_and_vet(HOST, 443, resolver=_resolver({HOST: addrs}))


def test_a_public_address_passes() -> None:
    assert resolve_and_vet(HOST, 443, resolver=_PUBLIC) == ["93.184.216.34"]


def test_a_host_that_resolves_to_nothing_is_refused() -> None:
    with pytest.raises(UnsafeDeploymentUrl):
        resolve_and_vet("nx.example.test", 443, resolver=_resolver({}))


def test_loopback_address_passes_only_under_the_flag() -> None:
    lb = _resolver({"127.0.0.1": ["127.0.0.1"]})
    with pytest.raises(UnsafeDeploymentUrl):
        resolve_and_vet("127.0.0.1", 80, resolver=lb)
    assert resolve_and_vet("127.0.0.1", 80, allow_loopback=True,
                           resolver=lb) == ["127.0.0.1"]


# --- consent ----------------------------------------------------------------

def test_without_consent_nothing_is_fetched() -> None:
    """`consent` has no default, so a caller that has not thought about it
    cannot accidentally fetch a stranger's deployment."""
    calls: list = []
    res = fetch_served_bundle(url=URL, consent=False, resolver=_PUBLIC,
                              fetch=_fetch("<html></html>", calls=calls))
    assert calls == []
    assert res.status == "skipped"
    assert res.evidence["reason"] == "no_consent"


def test_consent_is_a_required_keyword() -> None:
    with pytest.raises(TypeError):
        fetch_served_bundle(url=URL)  # type: ignore[call-arg]


# --- the guard, at the live entry point -------------------------------------

def test_an_unsafe_url_stops_the_fetch_rather_than_reporting_safety() -> None:
    calls: list = []
    res = fetch_served_bundle(
        url="http://169.254.169.254/", consent=True,
        resolver=_resolver({"169.254.169.254": ["169.254.169.254"]}),
        fetch=_fetch("<html></html>", calls=calls))
    assert calls == []
    assert res.status == "skipped"
    assert res.evidence["reason"] == "unsafe_url"


def test_a_host_resolving_private_stops_the_fetch() -> None:
    calls: list = []
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_resolver({HOST: ["10.0.0.5"]}),
        fetch=_fetch("<html></html>", calls=calls))
    assert calls == []
    assert res.status == "skipped"
    assert res.evidence["reason"] == "unsafe_url"


# --- extraction: production's oracle, demo carve-out ------------------------

def test_a_real_service_role_token_is_extracted() -> None:
    assert extract_service_role(f"const k='{SERVICE_KEY}'") == [SERVICE_KEY]


def test_a_demo_signed_service_role_token_is_not_a_credential() -> None:
    """Every local Supabase stack ships a service_role JWT signed with the
    public demo secret. Treating it as a credential is the inverse of the CORS
    `*`-credentials error — the carve-out is production's, reused here."""
    assert extract_service_role(f"x='{DEMO_SERVICE_KEY}'") == []


def test_an_anon_key_is_not_a_finding() -> None:
    assert extract_service_role(f"x='{ANON_KEY}'") == []


# --- fetch_served_bundle: reading the served bundle -------------------------

def test_a_key_inlined_in_the_html_is_found() -> None:
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_PUBLIC,
        fetch=_fetch(f"<script>var k='{SERVICE_KEY}'</script>"))
    assert res.status == "checked"
    assert res.leaked is True
    assert res.service_role_keys == [SERVICE_KEY]


def test_a_key_in_a_same_origin_asset_is_followed_and_found() -> None:
    html = '<script type="module" src="/assets/index-abc.js"></script>'
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_PUBLIC,
        fetch=_fetch(html, js=f"const k='{SERVICE_KEY}'"))
    assert res.leaked is True
    assert any("/assets/index-abc.js" in a for a in res.assets_read)


def test_an_off_origin_script_is_never_followed() -> None:
    """A page pointing its `<script src>` at another host is a second SSRF
    surface and is not where the app's own key lives. It is dropped, so its
    URL is never fetched."""
    calls: list = []
    html = '<script src="https://cdn.other.test/app.js"></script>'
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_PUBLIC,
        fetch=_fetch(html, js=f"const k='{SERVICE_KEY}'", calls=calls))
    assert res.leaked is False
    assert all("cdn.other.test" not in c for c in calls)


def test_a_patched_deployment_shipping_only_anon_leaks_nothing() -> None:
    html = '<script src="/assets/index-xyz.js"></script>'
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_PUBLIC,
        fetch=_fetch(html, js=f"const k='{ANON_KEY}'"))
    assert res.status == "checked"
    assert res.leaked is False
    # `no_secret`, not `no_service_role`: the module scans the whole secret
    # registry, so a clean bundle is "no secret of any class", and the anon key
    # it did ship is recognised as publishable rather than alarmed on. The
    # older `no_service_role` string predates the registry generalisation.
    assert res.evidence["reason"] == "no_secret"
    assert "supabase_anon_key" in res.evidence["publishable"]


# --- error is not "checked, safe" -------------------------------------------

def test_a_non_200_root_is_an_error_not_a_clean_check() -> None:
    def _fn(*_a, **_k):
        return 503, ""
    res = fetch_served_bundle(url=URL, consent=True, resolver=_PUBLIC, fetch=_fn)
    assert res.status == "error"
    assert res.leaked is False


def test_a_fetch_that_raises_is_an_error() -> None:
    def _boom(*_a, **_k):
        raise TimeoutError("read timeout")
    res = fetch_served_bundle(url=URL, consent=True, resolver=_PUBLIC,
                              fetch=_boom)
    assert res.status == "error"
    assert res.evidence["reason"] == "request_failed"


# --- nothing sensitive leaves ------------------------------------------------

def test_the_raw_token_never_reaches_the_evidence() -> None:
    """service_role_keys carries the token for the probe to use, but the
    stored/rendered evidence must carry only the ref and a reason — the same
    wall the RLS probe puts up around row values."""
    res = fetch_served_bundle(
        url=URL, consent=True, resolver=_PUBLIC,
        fetch=_fetch(f"<script>var k='{SERVICE_KEY}'</script>"))
    blob = repr(res.evidence)
    assert SERVICE_KEY not in blob
    assert res.evidence["refs"] == [_REF]
