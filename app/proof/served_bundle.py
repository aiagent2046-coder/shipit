"""Fetch a deployment's SERVED JavaScript and read the key it shipped.

Part C of SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md, and the single most dangerous
primitive in this codebase: the first time the product fetches an ARBITRARY,
customer-supplied web URL. Every other outbound request is shape-constrained —
`fetch_repo_zip` only ever hits github.com with an owner/repo (its SSRF guard
is that it cannot be pointed anywhere else), and `rls_probe` only accepts
`https://<ref>.supabase.co`. A deployment lives on any domain — vercel.app,
netlify.app, a custom domain — so it CANNOT be constrained to a shape, and the
guard has to be the real thing: resolve the host and refuse every private,
loopback, link-local, or reserved address behind it.

WHY THIS EXISTS AT ALL. Part A proved static analysis is blind to this class
(93% of the market commits no bundle). The key reaches the browser at RUNTIME,
inlined from a `VITE_`/`NEXT_PUBLIC_` var whether or not the build is committed.
The only place it can be seen is the served bundle — which means fetching it,
which means this guard.

WHAT IT MAY AND MAY NOT DO, and the wall is the point:

  * READ-ONLY GET of a public asset. Nothing here writes, and the only thing it
    returns from a response body is the SHAPE of a service_role JWT it found —
    never the body itself, never row data, never an arbitrary fetched document.
    So even in the worst case the guard somehow lets slip, what leaves this
    module is "a service_role-shaped token was present", which a metadata
    endpoint or an internal service does not carry.
  * CONSENT has no default. A caller that has not thought about it cannot
    accidentally fetch a stranger's deployment — the result is `skipped`, the
    same posture rls_probe takes.
  * SAME-ORIGIN assets only, and the walk is TRANSITIVE: a fetched chunk's own
    `.js` references join the queue, because a bundler names route chunks
    inside JavaScript and never in the HTML. Following only the page's script
    tags reads the shell and calls the application clean, which is fine for a
    statement about our own landing page and not fine for one about somebody
    else's app. Every discovered URL is re-vetted when it is popped, so
    discovery widens the set of URLs and never the set of ADDRESSES.
  * NO auto-redirects. Each hop would be a fresh URL to re-vet, and a 302 to
    `http://169.254.169.254/` is the classic bypass. Redirects are not
    followed; a deployment that 301s its asset is handled explicitly when one
    appears, not by opening the hole.

THE RESIDUAL RISK, NAMED. Resolve-then-connect has a TOCTOU window: the name
could re-resolve to a private address between the check and the socket. The
default fetch closes it by PINNING to a vetted IP — it connects to the address
this module verified, carrying the original Host (and SNI for TLS) — so the
bytes come from the address that passed, not from whatever the name says a
millisecond later. A caller injecting its own `fetch` inherits the duty to do
the same; the injection exists for tests, not to route around the guard.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.proof.disclosure import Disclosure, Ownership, plan_disclosure
from app.proof.secret_registry import Finding, ProbeResult, scan_text
from app.scan.secrets import _is_demo_jwt, _jwt_severity

FETCH_TIMEOUT_S = 15
MAX_HTML_BYTES = 2 * 1024 * 1024        # an index.html naming its bundles
MAX_ASSET_BYTES = 12 * 1024 * 1024      # one JS chunk; larger is not a hand-built app
# TOTAL scripts fetched per check, not per level. The walk is transitive
# now (a chunk's own references join the queue), so this is the whole
# budget -- and it bounds requests made to somebody else's server as much
# as it bounds our work. Raising it costs them load; `assets_truncated`
# is what keeps a capped answer from reading as a complete one.
MAX_ASSETS = 40

# The same JWT shape the shipped secrets scanner matches.
_JWT = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

# <script ... src="...js"> / module preload / plain asset refs. Deliberately
# permissive on the tag and strict on the extension: we only ever fetch `.js`.
_SCRIPT_SRC = re.compile(
    r"""(?:src|href)\s*=\s*["']([^"']+?\.m?js)(?:\?[^"']*)?["']""",
    re.IGNORECASE)

# A quoted string inside JavaScript that looks like a path to a script. This is
# what a bundler's chunk manifest is made of, and it is how route chunks that
# the HTML never names are found. Bounded to 300 characters so a minified blob
# cannot turn one line into an enormous candidate; `..` is refused outright
# rather than normalised, because a traversal in a fetched file is not a thing
# we want to follow even same-origin.
_JS_ASSET_REF = re.compile(
    r"""["'`](?!\.\.)([A-Za-z0-9_\-./]{1,300}?\.m?js)(?:\?[^"'`]*)?["'`]""")


class UnsafeDeploymentUrl(ValueError):
    """The URL, or an address behind it, is one we will not fetch."""


def _addr_is_public(ip: str) -> bool:
    """A routable public address, and nothing else. Every non-public category
    is refused by name rather than by a private-only check, because the harm is
    not only RFC-1918: link-local carries 169.254.169.254 (cloud metadata),
    reserved and unspecified reach odd corners of the stack, multicast is not a
    fetch target."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_reserved or a.is_multicast or a.is_unspecified
    )


def _is_loopback_host(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


@dataclass(frozen=True)
class _Target:
    url: str
    host: str
    port: int
    scheme: str


def validate_deployment_url(url: str, *, allow_loopback: bool = False) -> _Target:
    """Scheme/host/userinfo checks. IP vetting is separate (resolve_and_vet),
    because a name can pass the string checks and still resolve to a private
    address — the two guards are different failures and both must run."""
    parsed = urlsplit((url or "").strip())
    scheme = parsed.scheme.lower()

    if parsed.username or parsed.password:
        # user:pass@host is a classic way to smuggle a different authority past
        # a naive host check.
        raise UnsafeDeploymentUrl("credentials in URL are not accepted")

    host = parsed.hostname
    if not host:
        raise UnsafeDeploymentUrl(f"no host in URL: {url[:80]!r}")

    if scheme == "https":
        port = parsed.port or 443
    elif scheme == "http" and allow_loopback and _is_loopback_host(host):
        # The only http we accept, and only for the local stand. Production
        # never sets allow_loopback, exactly as rls_probe does not.
        port = parsed.port or 80
    else:
        raise UnsafeDeploymentUrl(
            f"scheme not allowed: {scheme!r} (https only)")

    normalized = urlunsplit((scheme, parsed.netloc, parsed.path or "/", "", ""))
    return _Target(url=normalized, host=host, port=port, scheme=scheme)


Resolver = Callable[[str, int], Iterable[tuple]]


def _default_resolver(host: str, port: int) -> Iterable[tuple]:
    return socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)


def resolve_and_vet(
    host: str, port: int, *, allow_loopback: bool = False,
    resolver: Resolver | None = None,
) -> list[str]:
    """Every address the host resolves to must pass, not just the first.

    A name with one public A record and one private one is not half-safe: the
    stack may connect to either. So the whole set is vetted and any single
    private address rejects the host — the safe direction, and the one a DNS-
    rebind attacker's dual-record setup depends on our getting wrong.
    """
    resolver = resolver or _default_resolver
    try:
        infos = list(resolver(host, port))
    except OSError as exc:
        raise UnsafeDeploymentUrl(f"cannot resolve host: {host!r}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeDeploymentUrl(f"host resolved to nothing: {host!r}")

    for ip in ips:
        if allow_loopback and ipaddress.ip_address(ip).is_loopback:
            continue
        if not _addr_is_public(ip):
            raise UnsafeDeploymentUrl(
                f"host {host!r} resolves to a non-public address ({ip})")
    return ips


@dataclass(frozen=True)
class BundleFinding:
    """One credential found in the served bundle, with where it was seen.

    Wraps a registry `Finding` (which carries the redacted mask and, in-process
    only, the raw token) plus the asset it came from. `evidence()` is the
    storable/renderable form — mask + location, never the token.
    """
    finding: Finding
    location: str

    def evidence(self) -> dict[str, Any]:
        return {**self.finding.evidence(), "location": self.location}


@dataclass(frozen=True)
class ProbePlanItem:
    """A finding that MAY be probed given ownership, and how. Present only for
    Tier A findings on an owned/consented target — the ownership gate is applied
    when this list is built, so a third-party finding never appears here."""
    finding_id: str
    name: str
    redacted: str
    location: str
    probe_family: str            # "key" (a read-only API call) | "endpoint" (rls_probe)
    probe: ProbeResult | None    # declared read-only stub for key-probe classes


@dataclass
class ServedBundleResult:
    status: str                          # "checked" | "skipped" | "error"
    detail: str
    findings: list[BundleFinding] = field(default_factory=list)     # secret only
    publishable: list[BundleFinding] = field(default_factory=list)  # designed to ship
    disclosures: list[Disclosure] = field(default_factory=list)     # one per secret — ALWAYS
    probe_plan: list[ProbePlanItem] = field(default_factory=list)   # ownership-gated
    assets_read: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def leaked(self) -> bool:
        return bool(self.findings)

    @property
    def service_role_keys(self) -> list[str]:
        """Back-compat: raw service_role tokens (in-process) for the RLS probe
        chain. Derived from findings so there is one source of truth."""
        return [bf.finding.secret for bf in self.findings
                if bf.finding.pattern_id == "supabase_service_role"]


def extract_service_role(text: str) -> list[str]:
    """Real (non-demo) service_role JWTs in a blob of JS, classified by the
    PRODUCTION oracle — a demo-signed token is a fixture, not a credential.

    Kept for callers that only want the service_role class; the full scan now
    goes through the registry (scan_text) inside fetch_served_bundle."""
    out: list[str] = []
    for token in _JWT.findall(text):
        try:
            sev, _c, _m = _jwt_severity(token)
        except Exception:  # noqa: BLE001
            continue
        if sev == "critical" and not _is_demo_jwt(token):
            out.append(token)
    return out


# The fetch signature is (url, host, port, max_bytes) -> (status_code, text).
# Injectable for tests exactly as rls_probe's is; the default pins to a vetted
# IP so the bytes come from the address that passed the guard.
FetchText = Callable[[str, str, int, int], tuple[int, str]]


def fetch_served_bundle(
    *,
    url: str,
    consent: bool,
    ownership: Ownership = "unknown",
    allow_loopback: bool = False,
    resolver: Resolver | None = None,
    fetch: FetchText | None = None,
) -> ServedBundleResult:
    """Fetch the deployment's HTML, follow its same-origin `.js`, and return
    every credential the served bundle carries as a set of disclosures plus a
    consent-gated probe plan. Read-only, consent-gated, SSRF-vetted at every hop.

    `ownership` (own / consented / third_party / unknown) drives two things and
    is never inferred from the target: a secret finding ALWAYS produces a
    disclosure (there is no silent path), while the probe plan is populated only
    for own/consented — a third-party or unknown target is disclosed to its
    owner and never probed. The default is the safe one: `unknown` discloses,
    never probes.
    """
    started = time.monotonic()

    def done(status: str, detail: str, **kw: Any) -> ServedBundleResult:
        return ServedBundleResult(
            status=status, detail=detail,
            duration_ms=int((time.monotonic() - started) * 1000), **kw)

    if not consent:
        return done("skipped",
                    "не запускалось: нет подтверждённого согласия владельца "
                    "деплоя", evidence={"reason": "no_consent"})

    try:
        target = validate_deployment_url(url, allow_loopback=allow_loopback)
        resolve_and_vet(target.host, target.port,
                        allow_loopback=allow_loopback, resolver=resolver)
    except UnsafeDeploymentUrl as exc:
        return done("skipped", str(exc), evidence={"reason": "unsafe_url"})

    fetch = fetch or _default_fetch_text
    try:
        status_code, html = fetch(target.url, target.host, target.port,
                                  MAX_HTML_BYTES)
    except Exception as exc:  # noqa: BLE001 — infrastructure, not a verdict
        return done("error",
                    f"запрос к деплою не выполнился: {type(exc).__name__}",
                    evidence={"reason": "request_failed"})

    if status_code != 200:
        return done("error", f"деплой ответил {status_code} на корень",
                    evidence={"reason": "bad_status", "status": status_code})

    # Scan the HTML, then follow same-origin `.js`. The registry classifies
    # every credential class — secret vs publishable — in one pass.
    secret_found: list[BundleFinding] = []
    publishable_found: list[BundleFinding] = []
    assets_read: list[str] = []
    seen: set[tuple[str, str]] = set()

    def ingest(text: str, location: str) -> None:
        """Classify one blob, and record that we read it.

        `assets_read` is appended HERE, unconditionally, and that is the whole
        point of the field. It used to be appended by the callers only when a
        scan turned up a secret, which made "we read twenty chunks and they
        were clean" indistinguishable from "we read nothing" — both an empty
        list. Found on the first real run, against our own deployment
        (2026-08-31): `checked`, no findings, `assets_read: []`, and the stored
        ledger row could not say what had been fetched.

        Where a secret was FOUND is already carried by BundleFinding.location.
        This answers the different question of what was LOOKED AT, and a row
        that cannot answer it is not accounting.
        """
        assets_read.append(location)
        secrets, publ = scan_text(text)
        for f in secrets:
            key = (f.pattern_id, f.secret)
            if key in seen:
                continue
            seen.add(key)
            secret_found.append(BundleFinding(f, location))
        for f in publ:
            key = (f.pattern_id, f.secret)
            if key in seen:
                continue
            seen.add(key)
            publishable_found.append(BundleFinding(f, location))

    ingest(html, "(served html)")

    # A WORKLIST, NOT A SINGLE PASS OVER THE HTML.
    #
    # The page's own `<script src>` tags are only the entry point. A Next.js or
    # Vite build loads route-level chunks by dynamic import, named inside
    # already-loaded JavaScript and never mentioned in the served HTML — so a
    # one-pass walk reads the shell and calls the application clean. Measured
    # on our own deployment (2026-08-31): 8 chunks named in the HTML, which is
    # the entry point and not the app.
    #
    # That is fine for a statement about our own landing page and NOT fine for
    # a statement about somebody else's application, which is the claim this
    # endpoint exists to support. So each fetched chunk is scanned for further
    # same-origin `.js` references and they join the queue.
    #
    # WHAT THIS IS NOT: executing the page. No browser, no build, no container
    # — the three blockers that ended the runtime-CORS detector at 0 of 26 and
    # that this whole class was chosen to avoid. It follows references that are
    # written down, which is a heuristic and is described as one below.
    queue: list[str] = _same_origin_assets(html, target)
    queued: set[str] = set(queue)
    discovered = len(queue)
    truncated = False
    fetched = 0

    while queue:
        if fetched >= MAX_ASSETS:
            # Stopped early: whatever is still queued was never looked at, and
            # the caller has to be told that rather than shown a clean answer.
            truncated = True
            break
        asset_url = queue.pop(0)
        try:
            a_target = validate_deployment_url(asset_url,
                                               allow_loopback=allow_loopback)
            resolve_and_vet(a_target.host, a_target.port,
                            allow_loopback=allow_loopback, resolver=resolver)
        except UnsafeDeploymentUrl:
            continue  # a script pointing off-origin or at a private address
        try:
            a_status, a_text = fetch(a_target.url, a_target.host,
                                     a_target.port, MAX_ASSET_BYTES)
        except Exception:  # noqa: BLE001
            continue
        fetched += 1
        if a_status != 200:
            continue
        ingest(a_text, a_target.url)

        # Every reference is re-vetted when it is popped, so discovery widens
        # the set of URLs but never the set of ADDRESSES: same-origin only,
        # then the same IP check as the seed.
        for ref in _asset_refs_in_js(a_text, a_target.url, target):
            if ref in queued:
                continue
            queued.add(ref)
            discovered += 1
            queue.append(ref)

    # Disclosure is unconditional: one per secret finding, whatever ownership is.
    disclosures: list[Disclosure] = []
    for bf in secret_found:
        d = plan_disclosure(bf.finding, ownership=ownership, location=bf.location)
        if d is not None:  # always, for a secret — the invariant
            disclosures.append(d)

    # The probe plan is consent-gated: only own/consented, only Tier A. The gate
    # is `disclosure.may_probe`, the same field assert_probe_allowed enforces —
    # a third-party finding is disclosed above but never planned for a probe.
    probe_plan: list[ProbePlanItem] = []
    for bf, disc in zip(secret_found, disclosures):
        if not disc.may_probe or bf.finding.tier != "A":
            continue
        result = bf.finding.probe()   # None for service_role (endpoint family)
        probe_plan.append(ProbePlanItem(
            finding_id=bf.finding.pattern_id, name=bf.finding.name,
            redacted=bf.finding.redacted, location=bf.location,
            probe_family="key" if result is not None else "endpoint",
            probe=result))

    if secret_found:
        classes = sorted({bf.finding.pattern_id for bf in secret_found})
        reason = ("service_role_in_bundle"
                  if "supabase_service_role" in classes else "secret_in_bundle")
        # The project refs behind the service_role tokens. This is the ONLY
        # thing about the token that may be stored: `ref` is the project
        # subdomain, already public in every request the app makes, and it is
        # what lets a human confirm which project was read. The token itself
        # stays in-process for the probe (see ServedBundleResult.service_role_keys).
        refs = sorted({r for r in (_ref_of(bf.finding.secret)
                                   for bf in secret_found
                                   if bf.finding.pattern_id
                                   == "supabase_service_role") if r})
        return done(
            "checked",
            f"в отданном бандле найдены секреты ({len(secret_found)}): "
            f"{', '.join(classes)}",
            findings=secret_found, publishable=publishable_found,
            disclosures=disclosures, probe_plan=probe_plan,
            assets_read=assets_read,
            evidence={"reason": reason, "classes": classes, "refs": refs,
                      "ownership": ownership, "assets": assets_read,
                      "assets_found": discovered,
                      "assets_truncated": truncated,
                      "disclosures": [d.evidence() for d in disclosures]})

    return done(
        "checked", "секретов в отданном бандле не найдено",
        publishable=publishable_found, assets_read=assets_read,
        evidence={"reason": "no_secret", "ownership": ownership,
                  # The scope of a CLEAN answer is the half that matters: this
                  # is the result a reader is most likely to hear as "nothing
                  # here", so it has to say how much was looked at.
                  "assets_found": discovered,
                  "assets_truncated": truncated,
                  "publishable": sorted({bf.finding.pattern_id
                                         for bf in publishable_found})})


def _same_origin_assets(html: str, target: _Target) -> list[str]:
    """Absolute-ise the `<script src>` refs and keep only same-origin ones.

    A relative `/assets/x.js` becomes the deployment's own URL; an absolute
    `https://cdn.other/x.js` is dropped — following it would be a second SSRF
    surface and is not where the app's own key would be.

    DE-DUPLICATED, IN FIRST-SEEN ORDER, and that is not tidiness. Observed on
    our own deployment (2026-08-31): Next.js names the same chunk twice, once
    as `<script src>` and once as a preload `href`, and both match the pattern,
    so the file was fetched twice. Two costs, and the second is the real one:

      * a second request to somebody else's server, when the whole posture of
        this module is that it reads the minimum;
      * duplicates spend the MAX_ASSETS budget. A page naming five distinct
        chunks twenty times would read five, report twenty, and say
        `assets_truncated: false` — the cap silently exhausted on repeats while
        the evidence claims full coverage. That is the same gap between "what
        we looked at" and "what we said" that the empty `assets_read` was, one
        step along.

    Order is preserved rather than sorted: the first script a page names is the
    entry point, and a reader following `assets_read` should see them in the
    order the page does.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url in seen:
            return
        seen.add(url)
        out.append(url)

    for raw in _SCRIPT_SRC.findall(html):
        if raw.startswith(("http://", "https://")):
            try:
                other = urlsplit(raw)
            except ValueError:
                continue
            if (other.hostname or "").lower() != target.host.lower():
                continue
            add(raw)
        else:
            path = raw if raw.startswith("/") else "/" + raw
            add(f"{target.scheme}://{target.host}:{target.port}{path}")
    return out


def _asset_refs_in_js(text: str, base_url: str, target: _Target) -> list[str]:
    """Same-origin `.js` URLs named inside a fetched chunk.

    A HEURISTIC, and worth saying so plainly: it reads quoted string literals
    that look like a path to a script and resolves them against the chunk that
    named them, the way a relative import resolves. A bundler's chunk manifest
    is exactly that — a table of quoted filenames — which is why this reaches
    route chunks the HTML never mentions.

    What it therefore does NOT reach: a URL the code assembles at runtime from
    pieces (`base + hash + ".js"`), which is a real pattern and the honest
    boundary of a crawl that does not execute anything. `assets_truncated` says
    when the CAP stopped us; nothing can say when a computed name did, so the
    claim this supports is "every script we could find from what is written
    down", never "every script the app can load".

    Same-origin is enforced here and the address is vetted again at fetch time.
    Discovery widens the set of URLs, never the set of hosts.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in _JS_ASSET_REF.findall(text):
        if raw.startswith(("//", "data:", "blob:")):
            # A protocol-relative URL is a different origin's problem, and the
            # other two are not fetchable addresses.
            continue
        try:
            candidate = urljoin(base_url, raw)
        except ValueError:
            continue
        parts = urlsplit(candidate)
        if parts.scheme != target.scheme:
            continue
        if (parts.hostname or "").lower() != target.host.lower():
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def _ref_of(token: str) -> str:
    import base64
    import json
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("ref", ""))
    except Exception:  # noqa: BLE001
        return ""


def _default_fetch_text(url: str, host: str, port: int,
                        max_bytes: int) -> tuple[int, str]:
    """GET pinned to a vetted IP, redirects OFF, size-capped.

    Connecting by IP with the original Host (and SNI for TLS) is what closes the
    resolve-then-connect TOCTOU: the bytes come from the address the guard
    checked, not from a name that may have re-resolved. Redirects are not
    followed — each hop is a URL the guard has not seen.
    """
    import httpx

    parsed = urlsplit(url)
    # Re-vet here too: this default must be safe even if called directly.
    ips = resolve_and_vet(host, port)
    ip = ips[0]

    connect_netloc = f"[{ip}]" if ":" in ip else ip
    connect_url = urlunsplit(
        (parsed.scheme, f"{connect_netloc}:{port}", parsed.path or "/", "", ""))

    extensions = {"sni_hostname": host} if parsed.scheme == "https" else {}
    with httpx.Client(follow_redirects=False, timeout=FETCH_TIMEOUT_S,
                      verify=True) as client:
        with client.stream("GET", connect_url,
                           headers={"Host": host, "Accept": "*/*"},
                           extensions=extensions) as response:
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    break
            text = bytes(body[:max_bytes]).decode("utf-8", errors="replace")
            return response.status_code, text
