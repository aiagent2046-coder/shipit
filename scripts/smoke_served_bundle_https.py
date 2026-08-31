#!/usr/bin/env python3
"""Does `_default_fetch_text` actually complete TLS? The one thing the unit
tests structurally cannot answer.

    python scripts/smoke_served_bundle_https.py

REQUIRED BEFORE PART C. `tests/test_proof_served_bundle.py` covers the guard
thoroughly — metadata addresses, RFC-1918, loopback, IPv6, dual-record rebind —
but every one of those tests injects a fake `fetch`. Not one of them executes
`app.proof.served_bundle._default_fetch_text`, which is the function that will
carry every real request. So the guard is proven and the transport is not.

THE SPECIFIC DOUBT. `_default_fetch_text` closes the resolve-then-connect
TOCTOU by connecting to a vetted IP literal while carrying the original name in
the `Host` header and the `sni_hostname` extension. Whether httpx then verifies
the certificate against that SNI name or against the IP in the URL is a
property of the installed httpx/httpcore, not of our code. If it verifies
against the IP, every fetch of a real deployment fails certificate
verification, and this whole path is dead in a way no test would show — it
fails CLOSED, as an `error` result, which reads exactly like an unreachable
site.

TWO HALVES, AND THE SECOND IS THE POINT. A fetch that returns 200 proves the
transport works. It does NOT prove verification is still on — an httpx that
ignored the hostname entirely would also return 200, and we would have
swapped a TOCTOU for a silent downgrade to unverified TLS. So this also points
the pinning at a host whose certificate does not match the name, and REQUIRES
the failure. A green that has never been red proves only that it ran; that
lesson is written into the proof layer's negative controls, and it applies to
the transport too.

UNDETERMINED IS NOT PASS. This talks to the public internet, so a refusal can
mean "TLS correctly rejected it" or "the network is blocked". Those are
different answers and the script never collapses them: a connection that never
reached TLS exits 78 (undetermined), the same disjoint-population discipline
the measurement scripts use for an unreachable repository.

Exit codes: 0 both halves passed · 1 a half genuinely failed · 78 undetermined
(no egress) — rerun somewhere with outbound HTTPS.
"""

from __future__ import annotations

import argparse
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.served_bundle import (  # noqa: E402
    UnsafeDeploymentUrl,
    _default_fetch_text,
    resolve_and_vet,
)

# A plain, stable, publicly reachable HTTPS host. Nothing about the content
# matters — only that TLS completes against a real certificate.
DEFAULT_GOOD = "https://example.com/"

# Serves a certificate valid for badssl.com, presented under a name it does not
# cover. The canonical "hostname verification must reject this" target.
DEFAULT_BAD = "https://wrong.host.badssl.com/"

OK, FAIL, UNDETERMINED = 0, 1, 78


def _is_tls_failure(exc: BaseException) -> bool:
    """A certificate/hostname rejection, as opposed to never getting there.

    Walks the cause chain because httpx wraps the ssl error in a ConnectError.
    Matching on the exception type first and the message second: an
    `ssl.SSLCertVerificationError` anywhere in the chain is unambiguous, and the
    string check only catches stacks that flatten it into a plain ConnectError.
    """
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen:
        seen.append(cur)
        if isinstance(cur, ssl.SSLCertVerificationError | ssl.SSLError):
            return True
        cur = cur.__cause__ or cur.__context__
    text = " ".join(str(e) for e in seen).lower()
    return any(m in text for m in (
        "certificate verify failed", "hostname mismatch",
        "certificate is not valid", "sslcertverificationerror",
        "doesn't match", "does not match"))


def _target(url: str) -> tuple[str, str, int]:
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return url, (parts.hostname or ""), (parts.port or 443)


def half_one_transport(url: str) -> int:
    """The pinned fetch must complete TLS and return a real response."""
    print(f"HALF 1 — pinned fetch against a real certificate: {url}")
    _, host, port = _target(url)

    try:
        ips = resolve_and_vet(host, port)
    except UnsafeDeploymentUrl as exc:
        print(f"  UNDETERMINED: cannot resolve/vet {host}: {exc}")
        return UNDETERMINED
    print(f"  vetted addresses : {', '.join(ips)}")
    print(f"  connecting to    : {ips[0]}  (Host + SNI = {host})")

    try:
        status, text = _default_fetch_text(url, host, port, 256 * 1024)
    except Exception as exc:  # noqa: BLE001
        if _is_tls_failure(exc):
            print(f"  FAILED: certificate verification rejected a VALID host — "
                  f"{type(exc).__name__}: {exc}")
            print("  => httpx is verifying against the connected IP, not the "
                  "SNI name. The pinning in _default_fetch_text needs to pass "
                  "the hostname to the verifier explicitly.")
            return FAIL
        print(f"  UNDETERMINED: never reached TLS ({type(exc).__name__}: {exc})")
        print("  => looks like blocked egress, not a code defect. Rerun with "
              "outbound HTTPS available.")
        return UNDETERMINED

    if status != 200 or not text.strip():
        print(f"  FAILED: TLS completed but the response is unusable "
              f"(status={status}, {len(text)} chars)")
        return FAIL

    print(f"  OK: status={status}, {len(text)} chars read over verified TLS\n")
    return OK


def half_two_verification_is_on(url: str) -> int:
    """The same code path MUST reject a certificate that does not cover the
    name. Without this, half 1 passing is compatible with verification being
    off entirely."""
    print(f"HALF 2 — the negative control: {url}")
    _, host, port = _target(url)

    try:
        resolve_and_vet(host, port)
    except UnsafeDeploymentUrl as exc:
        print(f"  UNDETERMINED: cannot resolve/vet {host}: {exc}\n")
        return UNDETERMINED

    try:
        status, _text = _default_fetch_text(url, host, port, 64 * 1024)
    except Exception as exc:  # noqa: BLE001
        if _is_tls_failure(exc):
            print(f"  OK: rejected by certificate verification "
                  f"({type(exc).__name__})\n")
            return OK
        print(f"  UNDETERMINED: never reached TLS ({type(exc).__name__}: {exc})")
        print("  => cannot tell a correct rejection from a blocked network.\n")
        return UNDETERMINED

    print(f"  FAILED: a mismatched certificate was ACCEPTED (status={status}).")
    print("  => TLS hostname verification is not in force on the pinned "
          "connection. Every fetch is open to an impersonating host; do NOT "
          "run Part C until this rejects.\n")
    return FAIL


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--good-url", default=DEFAULT_GOOD)
    ap.add_argument("--bad-url", default=DEFAULT_BAD)
    args = ap.parse_args(argv)

    print("served-bundle HTTPS transport smoke — required before Part C\n")
    one = half_one_transport(args.good_url)
    two = half_two_verification_is_on(args.bad_url)

    if FAIL in (one, two):
        print("RESULT: FAILED — the served-bundle fetch must not be pointed at "
              "a customer deployment until this passes.")
        return FAIL
    if UNDETERMINED in (one, two):
        print("RESULT: UNDETERMINED — no verdict was reached. This is NOT a "
              "pass; Part C stays blocked until both halves are green "
              "somewhere with outbound HTTPS.")
        return UNDETERMINED

    print("RESULT: PASSED — pinned TLS completes against a valid certificate "
          "and is rejected by an invalid one. Part C's transport precondition "
          "is met.")
    return OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
