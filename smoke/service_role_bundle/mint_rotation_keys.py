#!/usr/bin/env python3
"""Mint the synthetic credentials the rotation stand ships, and prove they work.

WHY SYNTHETIC, AND WHY THAT IS NOT A COMPROMISE. The plan for proving the four
live rotation verdicts originally called for a real Supabase project whose
service_role key would sit in a public bundle until it could be revoked. Reading
the classifier made that unnecessary:

  * app/scan/secrets._is_demo_jwt verifies the SIGNATURE against a short list of
    published development secrets. A token signed with a secret generated here
    matches none of them.
  * _jwt_severity then reads the `role` claim, and `service_role` is critical at
    0.95 — the same verdict a real key gets, because the classifier grades the
    SHAPE of a credential, not whether a provider ever issued it.
  * app/proof/secret_registry.Finding.probe() is a declared stub: "Intentionally
    does not execute". No code path fires this token at anything.

So a token with a random project ref, signed with a random secret, travels the
whole chain indistinguishably from a live credential and grants access to
nothing. There is no project to burn and nothing to revoke, and a stand that
would otherwise have published a working RLS bypass publishes an inert string.

THE SIGNING SECRET IS DISCARDED. It exists for the length of one HMAC. Keeping
it would let somebody mint further tokens that verify together, which is a
capability this stand has no use for.

WHAT THIS REFUSES TO PRODUCE. The script verifies its own output through the
production registry before writing anything: both service_role tokens must
classify as `critical`, must NOT be damped as demo keys, and must have DIFFERENT
fingerprints — `replaced_still_shipped` is exactly the verdict that a pair of
accidentally identical keys would silently turn into `unchanged`. A stand built
on an unverified fixture proves whatever the fixture happens to be.

    python smoke/service_role_bundle/mint_rotation_keys.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.proof.secret_registry import classify, fingerprint  # noqa: E402
from app.scan.secrets import _is_demo_jwt, _jwt_severity  # noqa: E402

OUT = Path(__file__).resolve().parent / "keys.rotation.env"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _mint(role: str) -> str:
    """A Supabase-shaped JWT for `role`, signed with a secret nobody keeps.

    The project ref is 20 random lowercase letters, the shape Supabase uses.
    Random rather than fixed so two mints never collide, and so this cannot be
    mistaken for a reference to a project that exists.
    """
    ref = "".join(secrets.choice(string.ascii_lowercase) for _ in range(20))
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"iss": "supabase", "ref": ref, "role": role,
               "iat": now, "exp": now + 10 * 365 * 24 * 3600}
    signing_input = f"{_b64(json.dumps(header).encode())}." \
                    f"{_b64(json.dumps(payload).encode())}"
    # Discarded on return: one HMAC is all it is for.
    secret = secrets.token_urlsafe(48)
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256)
    return f"{signing_input}.{_b64(sig.digest())}"


def _check(name: str, token: str, want_role: str) -> None:
    """Prove the production classifier agrees, before this key ships anywhere."""
    if _is_demo_jwt(token):
        raise SystemExit(
            f"{name}: classified as a published demo key — the stand would be "
            "damped to `low` and prove nothing")
    severity, _, detail = _jwt_severity(token)
    want_sev = "critical" if want_role == "service_role" else "low"
    if severity != want_sev:
        raise SystemExit(f"{name}: severity {severity!r}, expected "
                         f"{want_sev!r} ({detail})")
    found = classify(token)
    if want_role == "service_role" and found is None:
        raise SystemExit(
            f"{name}: app/proof/secret_registry does not recognise it, so the "
            "bundle check would read the stand as clean")


def main() -> int:
    role_a = _mint("service_role")
    role_b = _mint("service_role")
    anon = _mint("anon")

    _check("SERVICE_ROLE_A", role_a, "service_role")
    _check("SERVICE_ROLE_B", role_b, "service_role")
    _check("ANON", anon, "anon")

    if not os.environ.get("API_KEY_PEPPER", "").strip():
        raise SystemExit(
            "API_KEY_PEPPER is not set, so fingerprints come back empty and "
            "the rotation comparison cannot tell two keys apart. Export the "
            "same pepper production uses before minting.")
    fp_a, fp_b = fingerprint(role_a), fingerprint(role_b)
    if not fp_a or fp_a == fp_b:
        raise SystemExit(
            "the two service_role keys fingerprint identically — "
            "`replaced_still_shipped` would come back as `unchanged`, which is "
            "the one verdict this stand exists to distinguish")

    OUT.write_text(
        f"SERVICE_ROLE_A={role_a}\nSERVICE_ROLE_B={role_b}\nANON={anon}\n")
    OUT.chmod(0o600)

    # The tokens themselves are never printed. What a reader needs is that the
    # classifier agreed and that the two differ, and both are said without
    # putting a credential-shaped string on a terminal or in a log.
    print(f"minted 3 synthetic keys -> {OUT} (0600, gitignored)")
    print("  SERVICE_ROLE_A: critical, not demo-damped, "
          f"fingerprint {fp_a[:12]}…")
    print("  SERVICE_ROLE_B: critical, not demo-damped, "
          f"fingerprint {fp_b[:12]}…")
    print("  ANON:           low (publishable by design)")
    print("\nNone of these was issued by Supabase and none grants access to "
          "anything.\nThe signing secrets were discarded at mint time.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
