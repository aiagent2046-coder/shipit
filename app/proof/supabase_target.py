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

# One sentence, two paths (found in the tree, or handed to us). A refusal the
# customer reads should not depend on which route the key arrived by.
_SERVICE_ROLE_REFUSAL = (
    "that is a service_role key, and we will not send it anywhere: it "
    "bypasses Row Level Security, so a check made with it would return rows "
    "whether or not your tables are protected. If it is committed to the "
    "repository, that is itself the more urgent finding"
)

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
    # "repository" when we found the key ourselves, "supplied" when the
    # customer handed it over. Recorded because the two are different acts and
    # the ledger should be able to say which one happened.
    source: str = "repository"


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


def target_from_key(anon_key: str) -> SupabaseTarget | TargetRefusal:
    """A target built from a key the customer handed us.

    MEASURED 2026-08-18: our own project's repository commits no key at all —
    a `.env.example` and nothing else. Good hygiene, and it means the premise
    this module was built on ("the anon key ships in the repo") holds for many
    vibe-coded repositories and not for the tidier ones. Without this path the
    check refuses exactly the customers who did the right thing.

    Nothing about the security posture changes. The URL is still FORMATTED
    from the key's own `ref` claim rather than accepted as a parameter, so a
    caller cannot aim this at an address of their choosing; a service_role key
    is still refused; the table name is still validated downstream. What is
    given up is only the claim that we found the key ourselves, which is why
    the target records which of the two happened.
    """
    key = (anon_key or "").strip()
    if not key:
        return TargetRefusal("no key was supplied")
    if not key.isascii():
        # The masked-value paste, which has cost this project two debugging
        # sessions: bullets copied instead of the characters, the same length
        # and non-ASCII. Named here rather than surfacing as a request failure.
        return TargetRefusal(
            "the key contains non-ASCII characters, which usually means a "
            "masked value was copied instead of the key itself"
        )
    claims = decode_jwt_claims(key)
    if claims.get("iss") != "supabase":
        return TargetRefusal(
            "the supplied key is not a Supabase key (no `supabase` issuer)")
    role = claims.get("role")
    if role == "service_role":
        return TargetRefusal(_SERVICE_ROLE_REFUSAL)
    if role != "anon":
        return TargetRefusal(
            f"the supplied key has role {role!r}; only an anon key may be used")
    ref = str(claims.get("ref", ""))
    if not _REF.fullmatch(ref):
        return TargetRefusal("the supplied key names no usable project ref")
    return SupabaseTarget(
        ref=ref,
        project_url=f"https://{ref}.supabase.co",
        anon_key=key,
        source_path="",
        source="supplied",
    )


def find_supabase_target(
    fileobj: BinaryIO, *, supplied_key: str | None = None,
) -> SupabaseTarget | TargetRefusal:
    """The one project this repository belongs to, or why we will not guess.

    A supplied key WINS over anything found in the tree. Handing one over is a
    deliberate act by somebody who knows which project is theirs, and our regex
    over their files is not better information than that. The target records
    which source it came from.

    Otherwise: reads the repository bytes rather than the persisted findings,
    the same way app/fixpack/generate.py does, and for the same reason — a
    SecretFinding stores only a mask, and the raw key must never be written
    into an artifact that outlives the request.
    """
    if supplied_key and supplied_key.strip():
        return target_from_key(supplied_key)

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
        return TargetRefusal(_SERVICE_ROLE_REFUSAL)
    return TargetRefusal(
        "no Supabase anon key was found in the repository, so there is no "
        "project for us to check"
    )
