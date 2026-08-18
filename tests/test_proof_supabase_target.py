"""Which project a probe gets pointed at, and when it must not be pointed.

This is the seam where attacker-controlled input (a customer's repository)
decides the address of a request our infrastructure makes. Every test here is
about that: the URL never being a string somebody wrote, the credential never
being one that bypasses the thing we are checking, and every refusal being a
sentence rather than a silence.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile

from app.proof.supabase_target import (
    SupabaseTarget,
    TargetRefusal,
    decode_jwt_claims,
    find_supabase_target,
)

REF = "egoprezwkjaqacxtjwfl"
OTHER_REF = "qtnunqaxovzxzhxanurv"


def jwt(role: str = "anon", ref: str = REF, iss: str = "supabase") -> str:
    """A structurally real Supabase key. The signature is nonsense on purpose —
    nothing verifies it, and a test that needed a valid one would be asserting
    something this code does not do."""
    def seg(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    head = seg({"alg": "HS256", "typ": "JWT"})
    body = seg({"iss": iss, "ref": ref, "role": role,
                "iat": 1779635486, "exp": 2095211486})
    return f"{head}.{body}.XaMB3mjNqMf757EmpUpjnsJ5mldVtmsDiag7FQDjubg"


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def env(key: str) -> dict[str, str]:
    return {"repo/.env": f"VITE_SUPABASE_ANON_KEY={key}\n"}


# --- the address comes from the key ------------------------------------------

def test_the_project_url_is_built_from_the_key_not_read_from_the_repo() -> None:
    target = find_supabase_target(make_zip(env(jwt())))
    assert isinstance(target, SupabaseTarget)
    assert target.ref == REF
    assert target.project_url == f"https://{REF}.supabase.co"


def test_a_url_written_in_the_repo_cannot_redirect_the_probe() -> None:
    """The SSRF case, stated as a test rather than as a comment. A repository
    that names a different address gets the address in its own key anyway."""
    target = find_supabase_target(make_zip({
        "repo/.env": (
            f"VITE_SUPABASE_URL=http://169.254.169.254/latest/meta-data/\n"
            f"VITE_SUPABASE_ANON_KEY={jwt()}\n"
        ),
    }))
    assert isinstance(target, SupabaseTarget)
    assert target.project_url == f"https://{REF}.supabase.co"


# --- the credential ----------------------------------------------------------

def test_a_service_role_key_is_refused_and_the_reason_says_why() -> None:
    """THE ONE THAT MANUFACTURES ITS OWN FINDING. service_role bypasses RLS, so
    a probe using it returns rows whether or not the table is protected — the
    exposure would be created by our choice of credential."""
    result = find_supabase_target(make_zip(env(jwt(role="service_role"))))
    assert isinstance(result, TargetRefusal)
    assert "service_role" in result.reason
    assert "bypasses" in result.reason.lower()


def test_a_service_role_key_does_not_hide_an_anon_key_beside_it() -> None:
    """The control. Refusing on any sight of service_role would drop probes
    for repositories that leak one AND have a normal anon key — which is the
    combination most worth checking."""
    target = find_supabase_target(make_zip({
        "repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
        "repo/server/.env": f"SUPABASE_SERVICE_KEY={jwt(role='service_role')}\n",
    }))
    assert isinstance(target, SupabaseTarget)
    assert target.ref == REF


def test_a_jwt_that_is_not_supabase_is_not_a_target() -> None:
    result = find_supabase_target(make_zip(env(jwt(iss="some-other-issuer"))))
    assert isinstance(result, TargetRefusal)
    assert "no Supabase anon key" in result.reason


# --- ambiguity ---------------------------------------------------------------

def test_two_projects_in_one_repo_is_a_refusal_not_a_coin_toss() -> None:
    """Probing the wrong one produces a confident answer about a database the
    customer was not asking about."""
    result = find_supabase_target(make_zip({
        "repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
        "repo/.env.staging": f"VITE_SUPABASE_ANON_KEY={jwt(ref=OTHER_REF)}\n",
    }))
    assert isinstance(result, TargetRefusal)
    assert REF in result.reason
    assert OTHER_REF in result.reason


def test_the_same_key_in_several_files_is_still_one_project() -> None:
    """The control for the test above. An anon key is copied into every
    migration and every env sample, and refusing on that would refuse almost
    every real repository."""
    key = jwt()
    target = find_supabase_target(make_zip({
        "repo/.env": f"VITE_SUPABASE_ANON_KEY={key}\n",
        "repo/.env.example": f"VITE_SUPABASE_ANON_KEY={key}\n",
        "repo/src/lib/supabase.ts": f'const KEY = "{key}";\n',
    }))
    assert isinstance(target, SupabaseTarget)
    assert target.ref == REF


# --- nothing there -----------------------------------------------------------

def test_a_repo_with_no_supabase_key_is_a_refusal_with_a_sentence() -> None:
    result = find_supabase_target(make_zip({"repo/src/a.ts": "export const x=1;"}))
    assert isinstance(result, TargetRefusal)
    assert result.reason


def test_a_malformed_ref_is_not_turned_into_a_hostname() -> None:
    """The ref is interpolated into a URL, so its shape is checked before it
    gets there rather than after."""
    result = find_supabase_target(make_zip(env(jwt(ref="evil.example.com/x"))))
    assert isinstance(result, TargetRefusal)


# --- the decoder -------------------------------------------------------------

def test_claims_are_read_without_verifying_the_signature() -> None:
    claims = decode_jwt_claims(jwt())
    assert claims["ref"] == REF
    assert claims["role"] == "anon"


def test_a_broken_token_decodes_to_nothing_rather_than_raising() -> None:
    for junk in ("", "not-a-jwt", "a.b", "a.!!!!.c", "a." + base64.urlsafe_b64encode(
            b"[1,2,3]").decode().rstrip("=") + ".c"):
        assert decode_jwt_claims(junk) == {}


def test_the_key_is_carried_but_never_the_masked_finding() -> None:
    """The probe needs the literal. It comes from the repository bytes at probe
    time — the same route the Fix Pack takes — because a persisted finding
    stores only a mask and the raw value must not outlive the request."""
    target = find_supabase_target(make_zip(env(jwt())))
    assert isinstance(target, SupabaseTarget)
    assert target.anon_key == jwt()
    assert "•" not in target.anon_key
