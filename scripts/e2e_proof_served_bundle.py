"""End-to-end: fetch a SERVED bundle, read its key, and prove the bypass.

Part C of SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md — the piece Part A could never
reach, because the key is in the deployment, not the repo. Three things, all
runnable here (the live-DB half defers to Docker exactly as Part B's does):

  GUARD  — the SSRF vetting in app.proof.served_bundle, exercised against a
           table of hostile hosts through a fake resolver: cloud metadata,
           RFC-1918, loopback, IPv6 ULA, a dual-record rebind. Every one must
           be refused; a public address must pass. This is the most important
           test in the file — the whole class hinges on never fetching an
           internal address.

  FETCH  — a real HTTP server on loopback serving smoke/service_role_bundle/
           dist_vulnerable/. fetch_served_bundle follows the served index.html
           to its `/assets/*.js` and extracts the service_role key. Asserted
           equal to the key the stand baked in, so we know we read the SERVED
           bundle rather than anything on disk. The patched deployment is
           served too and must yield no service_role key.

  CHAIN  — the extracted key feeds the same before/after pair as Part B, so
           the full Part C path is shown end to end: URL -> served JS ->
           service_role key -> live probe -> verified.

CONSENT and the URL guard are checked in the negative directions too: no
consent -> skipped, a metadata URL -> skipped. The guard failing OPEN is the
one outcome this file exists to make impossible.

    python scripts/e2e_proof_served_bundle.py

No Docker, no flags. The CHAIN uses the injected fetch from the Part B logic
path; the live PostgREST confirmation is `e2e_proof_bundle_probe.py` under
Docker.
"""

from __future__ import annotations

import http.server
import socketserver
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.compare import build_proof_report  # noqa: E402
from app.proof.rls_probe import run_rls_probe  # noqa: E402
from app.proof.served_bundle import (  # noqa: E402
    UnsafeDeploymentUrl,
    fetch_served_bundle,
    resolve_and_vet,
    validate_deployment_url,
)

STAND = Path(__file__).resolve().parent.parent / "smoke" / "service_role_bundle"


# --------------------------------------------------------------------------- #
# GUARD
# --------------------------------------------------------------------------- #

def _fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int):
        if host not in mapping:
            raise OSError(f"NXDOMAIN {host}")
        return [(0, 0, 0, "", (ip, port)) for ip in mapping[host]]
    return resolve


def test_guard() -> bool:
    print("GUARD — SSRF vetting")
    ok = True

    # URL-shape refusals (no resolver needed).
    for bad, why in [
        ("http://example.com/", "http scheme without loopback"),
        ("ftp://example.com/", "non-http scheme"),
        ("https://user:pass@example.com/", "credentials in URL"),
        ("https:///path", "no host"),
    ]:
        try:
            validate_deployment_url(bad)
            print(f"  FAIL: accepted {bad!r} ({why})")
            ok = False
        except UnsafeDeploymentUrl:
            pass

    # Address refusals via a fake resolver — the host string is innocent, the
    # address behind it is not.
    hostile = {
        "metadata.evil":   ["169.254.169.254"],   # cloud metadata (link-local)
        "internal.evil":   ["10.0.0.5"],           # RFC-1918
        "loop.evil":       ["127.0.0.1"],          # loopback
        "ula.evil":        ["fd00::1"],            # IPv6 unique-local (private)
        "rebind.evil":     ["93.184.216.34", "10.0.0.5"],  # one public, one private
    }
    for host in hostile:
        try:
            resolve_and_vet(host, 443, resolver=_fake_resolver(hostile))
            print(f"  FAIL: accepted host resolving to {hostile[host]}")
            ok = False
        except UnsafeDeploymentUrl:
            pass

    # A genuinely public address must pass.
    try:
        resolve_and_vet("app.example", 443,
                        resolver=_fake_resolver({"app.example": ["93.184.216.34"]}))
    except UnsafeDeploymentUrl:
        print("  FAIL: refused a public address")
        ok = False

    print(f"  {'OK' if ok else 'FAILED'}: hostile hosts refused, public passes\n")
    return ok


# --------------------------------------------------------------------------- #
# FETCH — a real loopback server
# --------------------------------------------------------------------------- #

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: A003 — silence access logs
        pass


class _Server:
    def __init__(self, directory: Path):
        handler = lambda *a, **k: _QuietHandler(  # noqa: E731
            *a, directory=str(directory), **k)
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _loopback_fetch(url, host, port, max_bytes):
    """Injected for the stand: loopback is already vetted by the caller, and the
    production default re-vets WITHOUT loopback (correctly refusing 127.0.0.1),
    so the stand supplies its own reader rather than loosening the default."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, r.read(max_bytes).decode("utf-8", errors="replace")


def _baked_service_key() -> str:
    for line in (STAND / "keys.env").read_text().splitlines():
        if line.startswith("SERVICE_ROLE_JWT="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("stand keys.env missing SERVICE_ROLE_JWT — build it first")


def test_fetch_vulnerable() -> tuple[bool, str]:
    print("FETCH — served vulnerable deployment")
    with _Server(STAND / "dist_vulnerable") as srv:
        url = f"http://127.0.0.1:{srv.port}/"
        res = fetch_served_bundle(url=url, consent=True, allow_loopback=True,
                                  fetch=_loopback_fetch)
    print(f"  status={res.status} leaked={res.leaked} "
          f"assets_read={res.assets_read}")
    print(f"  evidence={res.evidence}")

    if not res.leaked:
        print("  FAILED: no service_role key found in the served bundle\n")
        return False, ""
    got = res.service_role_keys[0]
    if got != _baked_service_key():
        print("  FAILED: extracted key does not match the baked-in one — we did "
              "not read the served bundle\n")
        return False, ""
    # The raw token must not have leaked into evidence.
    assert got not in repr(res.evidence)
    print("  OK: read the service_role key from the SERVED bundle, raw token "
          "kept out of evidence\n")
    return True, got


def test_fetch_patched() -> bool:
    print("FETCH — served patched deployment (must find nothing)")
    with _Server(STAND / "dist_patched") as srv:
        url = f"http://127.0.0.1:{srv.port}/"
        res = fetch_served_bundle(url=url, consent=True, allow_loopback=True,
                                  fetch=_loopback_fetch)
    ok = res.status == "checked" and not res.leaked
    print(f"  status={res.status} leaked={res.leaked}  "
          f"{'OK' if ok else 'FAILED'}\n")
    return ok


def test_consent_and_metadata() -> bool:
    print("GUARD — consent and metadata in the live entry point")
    ok = True
    no_consent = fetch_served_bundle(url="https://app.example/", consent=False)
    if no_consent.status != "skipped":
        print("  FAIL: ran without consent")
        ok = False
    meta = fetch_served_bundle(
        url="http://169.254.169.254/", consent=True,
        resolver=_fake_resolver({"169.254.169.254": ["169.254.169.254"]}))
    # http scheme without loopback is refused at the URL stage already.
    if meta.status != "skipped":
        print("  FAIL: did not skip a metadata URL")
        ok = False
    print(f"  {'OK' if ok else 'FAILED'}: no-consent and metadata both skipped\n")
    return ok


# --------------------------------------------------------------------------- #
# CHAIN — extracted key -> probe pair
# --------------------------------------------------------------------------- #

def _role_of(token: str) -> str:
    import base64
    import json
    p = token.split(".")[1]
    p += "=" * (-len(p) % 4)
    return str(json.loads(base64.urlsafe_b64decode(p)).get("role", ""))


def _injected_probe_fetch(_base, key, _table, _limit):
    if _role_of(key) == "service_role":
        return 200, [{"id": "1", "email": "ada@example.invalid"}]
    return 200, []


def test_chain(service_key: str, anon_key: str) -> bool:
    print("CHAIN — extracted key -> live probe (injected)")

    def probe(key):
        return run_rls_probe(
            project_url="http://127.0.0.1:54399", anon_key=key,
            table="founders", consent=True, allow_loopback=True,
            fetch=_injected_probe_fetch)

    before = probe(service_key)
    after = probe(anon_key)
    report = build_proof_report(before, after, informational=False)
    ok = (before.status == "success" and after.status == "failure"
          and report.verified)
    print(f"  before={before.status} after={after.status} "
          f"verified={report.verified}  {'OK' if ok else 'FAILED'}\n")
    return ok


def _anon_key() -> str:
    for line in (STAND / "keys.env").read_text().splitlines():
        if line.startswith("ANON_JWT="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("stand keys.env missing ANON_JWT")


def main() -> int:
    if not (STAND / "dist_vulnerable" / "assets").exists():
        print("stand not built — run smoke/service_role_bundle/build_variants.sh "
              "first", file=sys.stderr)
        return 2

    results = [test_guard()]
    leaked_ok, service_key = test_fetch_vulnerable()
    results.append(leaked_ok)
    results.append(test_fetch_patched())
    results.append(test_consent_and_metadata())
    if service_key:
        results.append(test_chain(service_key, _anon_key()))

    if all(results):
        print("ALL OK: served-bundle fetch reads the key, the guard refuses "
              "every internal\naddress, and the extracted key verifies the "
              "bypass end to end.")
        return 0
    print("FAILED — see above.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
