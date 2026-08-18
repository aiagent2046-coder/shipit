"""Work out WHICH Supabase project a probe would be aimed at, from the repo.

The live probe (app/proof/rls_probe.py) takes a project URL and an anon key.
Until now both arrived from a human typing them into a script. For the probe to
run as part of an audit, they have to come out of the customer's repository —
which is the moment the question stops being plumbing and becomes a security
boundary, because the repository is attacker-controlled input.

THE URL COMES OUT OF THE KEY, NOT OUT OF THE REPOSITORY.

A Supabase anon key is a JWT, and its payload carries the project it belongs
to:

    {"iss": "supabase", "ref": "egoprezwkjaqacxtjwfl", "role": "anon"}

So the URL is FORMATTED from the `ref` claim rather than matched anywhere. Two
things follow, and both are the point:

  * There is no pairing to get wrong. Reading a URL and a key as two
    independent matches lets a repository carrying several projects hand us
    one project's key aimed at another's address, and the answer would be a
    confident statement about the wrong database.
  * The SSRF surface shrinks to a shape. `rls_probe` already refuses anything
    that is not `https://<ref>.supabase.co`; here the ref itself can only come
    from inside a signed token the repository would have to have obtained.

We do NOT verify the signature. There is no key to verify it with and no need:
the claims are being used to decide where to point a request that is then
validated on its own, not to authenticate anybody.

A service_role KEY IS NEVER A PROBE CREDENTIAL. It bypasses RLS entirely, so
a probe using one reads every row of every table and would report "exposed"
about a database that is correctly locked — the finding would be manufactured
by our own choice of credential. It is also a far worse finding in its own
right, which the secrets scanner already raises as critical. Both reasons point
the same way: refuse, and say which of the two it was.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.secrets import iter_secret_matches

ANON_RULE_ID = "supabase-anon-key"

# The same shape rls_probe accepts, checked here too so a target is never
# built that the probe would then refuse — a refusal at the boundary can say
# why, and one deeper in reads as a malfunction.
_REF = re.compile(r"^[a-z0-9]{16,32}$")


@dataclass(frozen=True)
class SupabaseTarget:
    """A project a probe may be pointed at, with the key to use."""

    ref: str
    project_url: str
    anon_key: str
    source_path: str


@dataclass(frozen=True)
class TargetRefusal:
    """No probe, and the reason, in words a customer can be shown.

    A refusal is a RESULT, not an error. "We could not tell which project this
    is" and "we did not check" are the same sentence to a reader, and neither
    of them is "your database is fine" — the distinction `skipped` exists for
    in ExploitAttempt, arriving one layer earlier.
    """

    reason: str


def decode_jwt_claims(token: str) -> dict:
    """The payload of a JWT, without verifying anything. {} if unreadable."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def find_supabase_target(fileobj: BinaryIO) -> SupabaseTarget | TargetRefusal:
    """The one project this repository belongs to, or why we will not guess.

    Reads the repository bytes rather than the persisted findings, the same way
    app/fixpack/generate.py does, and for the same reason: a SecretFinding
    stores only a mask, and the raw key must never be written into an artifact
    that outlives the request.
    """
    fileobj.seek(0)
    candidates: dict[str, SupabaseTarget] = {}
    saw_service_role = False

    for finding, raw in iter_secret_matches(fileobj):
        claims = decode_jwt_claims(raw)
        if claims.get("iss") != "supabase":
            continue
        role = claims.get("role")
        if role == "service_role":
            saw_service_role = True
            continue
        # rule_id is checked as well as the role claim. They are derived from
        # the same decode today, and a probe credential is not the place to
        # rely on that staying true.
        if role != "anon" or finding.rule_id != ANON_RULE_ID:
            continue
        ref = str(claims.get("ref", ""))
        if not _REF.fullmatch(ref):
            continue
        candidates.setdefault(ref, SupabaseTarget(
            ref=ref,
            project_url=f"https://{ref}.supabase.co",
            anon_key=raw,
            source_path=finding.file,
        ))

    if len(candidates) == 1:
        return next(iter(candidates.values()))
    if len(candidates) > 1:
        # Two projects, and nothing in the repository says which one is live.
        # Probing the wrong one produces a confident answer about a database
        # the customer was not asking about.
        refs = ", ".join(sorted(candidates))
        return TargetRefusal(
            f"the repository carries anon keys for more than one Supabase "
            f"project ({refs}), so we cannot tell which one is yours to check"
        )
    if saw_service_role:
        return TargetRefusal(
            "the only Supabase key we found is a service_role key. We will "
            "not send that anywhere: it bypasses Row Level Security, so a "
            "check made with it would return rows whether or not your tables "
            "are protected. That key being in the repository is itself the "
            "more urgent finding"
        )
    return TargetRefusal(
        "no Supabase anon key was found in the repository, so there is no "
        "project for us to check"
    )
