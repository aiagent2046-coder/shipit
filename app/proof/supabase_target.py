"""Resolve a public Supabase credential to one hosted project.

Legacy anon JWTs identify their project through the ref claim. Publishable
keys are opaque: the owner must supply the Project URL explicitly. Repository
URLs are never used to pair an opaque key with a project. Both paths construct
one canonical HTTPS *.supabase.co origin after strict validation.

JWT claims are not authentication here; Supabase validates the key when the
request arrives. Secret and service_role keys are refused because they bypass
RLS and would manufacture an exposure finding.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
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
_PROJECT_URL = re.compile(r"https://([a-z0-9]{16,32})\.supabase\.co/?", re.IGNORECASE | re.ASCII)
_PUBLISHABLE_KEY = re.compile(r"sb_publishable_[A-Za-z0-9_-]+")
_MAX_KEY_LENGTH = 4096


def is_publishable_key(key: str) -> bool:
    """Check the public prefix/header-safe opaque format, not key validity."""
    return len(key) <= _MAX_KEY_LENGTH and _PUBLISHABLE_KEY.fullmatch(key) is not None


def _project_ref(project_url: str | None) -> str | TargetRefusal | None:
    if not project_url or not project_url.strip():
        return None
    match = _PROJECT_URL.fullmatch(project_url.strip())
    if match is None:
        return TargetRefusal(
            "Use your Project URL in the form https://<project-ref>.supabase.co, "
            "with no credentials, port, path, query or fragment.")
    return match.group(1).lower()


def _project_mismatch() -> TargetRefusal:
    return TargetRefusal(
        "The Project URL belongs to a different project than the legacy anon key; "
        "no database requests sent.")


@dataclass(frozen=True)
class SupabaseTarget:
    """A project a probe may be pointed at, with the key to use."""

    ref: str
    project_url: str
    anon_key: str = field(repr=False)
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
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        return {}
    return claims if isinstance(claims, dict) else {}


def target_from_key(
    anon_key: str, *, project_url: str | None = None,
) -> SupabaseTarget | TargetRefusal:
    """Use an explicitly supplied public key; opaque keys need a Project URL."""
    key = (anon_key or "").strip()
    if not key:
        return TargetRefusal("no key was supplied")
    if len(key) > _MAX_KEY_LENGTH:
        return TargetRefusal("the supplied public key is too long")
    if not key.isascii():
        # The masked-value paste, which has cost this project two debugging
        # sessions: bullets copied instead of the characters, the same length
        # and non-ASCII. Named here rather than surfacing as a request failure.
        return TargetRefusal(
            "the key contains non-ASCII characters, which usually means a "
            "masked value was copied instead of the key itself"
        )
    if any(ord(char) <= 32 or ord(char) == 127 for char in key):
        return TargetRefusal("the supplied public key contains whitespace or control characters")
    if key.startswith("sb_secret_"):
        return TargetRefusal(
            "sb_secret_ keys bypass Row Level Security; use a public publishable "
            "or legacy anon key instead")
    requested_ref = _project_ref(project_url)
    if isinstance(requested_ref, TargetRefusal):
        return requested_ref
    if key.startswith("sb_publishable_"):
        if not is_publishable_key(key):
            return TargetRefusal("the supplied publishable key has an invalid format")
        if not requested_ref:
            return TargetRefusal(
                "A publishable key does not contain a project address. "
                "Supply your Supabase Project URL to run the check.")
        return SupabaseTarget(
            ref=requested_ref, project_url=f"https://{requested_ref}.supabase.co",
            anon_key=key, source_path="", source="supplied",
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
            "the supplied JWT must have the anon role")
    ref = str(claims.get("ref", ""))
    if not _REF.fullmatch(ref):
        return TargetRefusal("the supplied key names no usable project ref")
    if requested_ref and requested_ref != ref:
        return _project_mismatch()
    return SupabaseTarget(
        ref=ref,
        project_url=f"https://{ref}.supabase.co",
        anon_key=key,
        source_path="",
        source="supplied",
    )


def find_supabase_target(
    fileobj: BinaryIO, *, supplied_key: str | None = None, project_url: str | None = None,
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
        return target_from_key(supplied_key, project_url=project_url)

    requested_ref = _project_ref(project_url)
    if isinstance(requested_ref, TargetRefusal):
        return requested_ref

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
        target = next(iter(candidates.values()))
        if requested_ref and requested_ref != target.ref:
            return _project_mismatch()
        return target
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
        "project for us to check. Supply a public publishable key with its "
        "Project URL, or a legacy anon key"
    )
