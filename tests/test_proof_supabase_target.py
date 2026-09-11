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

import pytest

from app.proof.supabase_target import (
    SupabaseTarget,
    TargetRefusal,
    decode_jwt_claims,
    find_supabase_target,
    target_from_key,
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


# --- a key the customer hands over ------------------------------------------
#
# MEASURED 2026-08-18: our own project's repository commits no key at all — a
# `.env.example` and nothing else. Good hygiene, and it means the premise this
# module was built on holds for many vibe-coded repositories and not for the
# tidier ones. Without this path the check refuses exactly the customers who
# did the right thing.

def test_a_supplied_key_is_used_when_the_repo_has_none() -> None:
    target = find_supabase_target(
        make_zip({"repo/README.md": "# no keys here"}), supplied_key=jwt())
    assert isinstance(target, SupabaseTarget)
    assert target.ref == REF
    assert target.source == "supplied"


def test_a_supplied_key_wins_over_one_found_in_the_tree() -> None:
    """Handing one over is a deliberate act by somebody who knows which
    project is theirs. Our regex over their files is not better information."""
    target = find_supabase_target(
        make_zip(env(jwt(ref=OTHER_REF))), supplied_key=jwt())
    assert isinstance(target, SupabaseTarget)
    assert target.ref == REF


def test_the_url_is_still_built_from_the_key_not_from_the_caller() -> None:
    """The security property this whole module turns on survives the new path:
    a caller cannot aim the probe at an address of their choosing, because
    there is no address parameter — only a key, whose own claim names it."""
    target = find_supabase_target(
        make_zip({"repo/a.ts": "x"}), supplied_key=jwt(ref=OTHER_REF))
    assert isinstance(target, SupabaseTarget)
    assert target.project_url == f"https://{OTHER_REF}.supabase.co"


def test_a_supplied_service_role_key_is_refused_the_same_way() -> None:
    result = find_supabase_target(
        make_zip({"repo/a.ts": "x"}), supplied_key=jwt(role="service_role"))
    assert isinstance(result, TargetRefusal)
    assert "service_role" in result.reason
    assert "bypasses" in result.reason.lower()


def test_a_masked_paste_is_named_rather_than_failing_as_a_request() -> None:
    """Bullets copied instead of the characters — same length, non-ASCII. It
    has cost this project two debugging sessions, once surfacing as a
    UnicodeEncodeError and once as a plausible-looking empty result."""
    masked = "•" * len(jwt())
    result = find_supabase_target(make_zip({"repo/a.ts": "x"}),
                                  supplied_key=masked)
    assert isinstance(result, TargetRefusal)
    assert "masked" in result.reason


def test_a_non_supabase_jwt_supplied_by_hand_is_refused() -> None:
    result = find_supabase_target(make_zip({"repo/a.ts": "x"}),
                                  supplied_key=jwt(iss="auth0"))
    assert isinstance(result, TargetRefusal)


def test_an_empty_supplied_key_falls_back_to_the_repository() -> None:
    """A blank form field is not an instruction. It must not turn a repository
    that DOES carry a key into a refusal."""
    for blank in (None, "", "   "):
        target = find_supabase_target(make_zip(env(jwt())),
                                      supplied_key=blank)
        assert isinstance(target, SupabaseTarget), blank
        assert target.source == "repository"


PUBLISHABLE = "sb_publishable_syntheticPublicKeyForTests_1234"


def test_publishable_key_uses_only_the_explicit_hosted_project():
    archive = make_zip({**env(jwt(ref=OTHER_REF)), "repo/config.ts":
                        f"const url = 'https://{OTHER_REF}.supabase.co';"})
    target = find_supabase_target(archive, supplied_key=PUBLISHABLE,
                                 project_url=f" HTTPS://{REF.upper()}.SUPABASE.CO/ ")
    assert isinstance(target, SupabaseTarget)
    assert target.project_url == f"https://{REF}.supabase.co"
    assert target.anon_key == PUBLISHABLE
    assert target.source == "supplied"
    assert PUBLISHABLE not in repr(target)


def test_opaque_key_cannot_get_its_project_from_a_repository_or_legacy_key():
    target = find_supabase_target(make_zip({**env(jwt()), "repo/config.ts":
                                 f"const url = 'https://{REF}.supabase.co';"}),
                                 supplied_key=PUBLISHABLE)
    assert isinstance(target, TargetRefusal)
    assert "Project URL" in target.reason


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000",
    f"http://{REF}.supabase.co", f"https://{REF}.supabase.co:443",
    f"https://{REF}.supabase.co/rest/v1/users", f"https://{REF}.supabase.co?key=private-input",
    f"https://{REF}.supabase.co#private-input", f"https://private-input@{REF}.supabase.co",
    f"https://{REF}.supabase.co.evil.example", f"https://{REF}.supabase.co\\@evil.example",
    "https://example.com", "https://short.supabase.co", "https://" + "a" * 33 + ".supabase.co",
    "https://abcdefghijklmnopqrsK.supabase.co", f"https://{REF}.supabase.co\nprivate-input",
])
def test_explicit_url_cannot_expand_the_allowed_destination(url):
    result = target_from_key(PUBLISHABLE, project_url=url)
    assert isinstance(result, TargetRefusal)
    assert "private-input" not in result.reason
    assert PUBLISHABLE not in result.reason


@pytest.mark.parametrize("key", [
    "sb_secret_syntheticSecretKeyForTests", "sb_publishable_",
    "sb_publishable_bad\r\nAuthorization: private-input", "sb_publishable_with space",
    "sb_publishable_" + "x" * 4096, jwt(role="service_role"), jwt(role="private-input"),
    jwt().replace(".", "\r\n.", 1),
])
def test_invalid_or_privileged_supplied_keys_are_never_echoed(key):
    result = target_from_key(key, project_url=f"https://{REF}.supabase.co")
    assert isinstance(result, TargetRefusal)
    assert key not in result.reason and "private-input" not in result.reason


@pytest.mark.parametrize("supplied", [True, False])
def test_explicit_project_cannot_override_a_legacy_jwt_ref(supplied):
    result = find_supabase_target(make_zip(env(jwt())),
                                 supplied_key=jwt() if supplied else None,
                                 project_url=f"https://{OTHER_REF}.supabase.co")
    assert isinstance(result, TargetRefusal)
    assert "different project" in result.reason
    good = find_supabase_target(make_zip(env(jwt())),
                               supplied_key=jwt() if supplied else None,
                               project_url=f"https://{REF}.supabase.co/")
    assert isinstance(good, SupabaseTarget) and good.ref == REF


def test_a_supplied_key_with_a_malformed_ref_is_not_turned_into_a_hostname() -> None:
    """The ref is interpolated into a URL, and on this path the CALLER chose
    the key — so `https://{ref}.supabase.co` with a ref of `evil.example.com/x`
    resolves to a host that is not Supabase at all. `rls_probe` would refuse it
    too, but a refusal at the boundary can name the reason and one deeper in
    reads as a malfunction.

    Written because mutation testing said so: deleting the shape check left
    every other test green.
    """
    result = find_supabase_target(
        make_zip({"repo/a.ts": "x"}),
        supplied_key=jwt(ref="evil.example.com/x"))
    assert isinstance(result, TargetRefusal)
    assert "ref" in result.reason
