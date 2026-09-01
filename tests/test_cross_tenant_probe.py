"""The cross-tenant probe: two consents, one write, and a fresh account reading
what it cannot own.

The most invasive probe in the project, so its guarantees are asserted, not
trusted: the write happens only with its own consent, a disabled signup reads as
undetermined rather than safe, and the before/after resolves through the shared
compare. Injected signup/fetch, so nothing here touches a real project.
"""

from __future__ import annotations

import pytest

from app.proof.compare import build_proof_report
from app.proof.cross_tenant_probe import (
    SignupNotPermitted,
    assert_signup_consent,
    run_cross_tenant_probe,
)

URL = "https://egoprezwkjaqacxtjwfl.supabase.co"
ANON = "anon-key"
TOKEN = "fresh-account-jwt"

OTHERS_ROWS = [
    {"id": "1", "user_id": "SOMEONE_ELSE", "email": "a@x"},
    {"id": "2", "user_id": "ALSO_NOT_ME", "email": "b@x"},
]


def _signup_ok(*_a):
    return 200, {"access_token": TOKEN, "user": {"id": "fresh"}}


def _signup_disabled(*_a):
    return 422, {"code": "signup_disabled", "msg": "Signups not allowed"}


def _signup_needs_confirmation(*_a):
    # GoTrue with email confirmation on: a user, but no session token.
    return 200, {"access_token": None, "user": {"id": "fresh", "email": "x"}}


def _reads(rows):
    def fetch(_base, _token, _anon, _table, _limit):
        return 200, rows
    return fetch


def _probe(**kw):
    base = dict(project_url=URL, anon_key=ANON, table="profiles",
                consent=True, signup_consent=True, signup=_signup_ok,
                fetch=_reads(OTHERS_ROWS))
    base.update(kw)
    return run_cross_tenant_probe(**base)


# --- the two consents -------------------------------------------------------

def test_the_write_gate_needs_its_own_consent():
    """assert_signup_consent: the read consent does not authorise the account-
    creating write; both must hold."""
    assert_signup_consent(consent=True, signup_consent=True)  # ok
    for c, s in [(False, True), (True, False), (False, False)]:
        with pytest.raises(SignupNotPermitted):
            assert_signup_consent(consent=c, signup_consent=s)


def test_no_read_consent_skips_without_signing_up():
    calls = []
    res = _probe(consent=False,
                 signup=lambda *a: calls.append(a) or _signup_ok())
    assert res.status == "skipped"
    assert res.evidence["reason"] == "no_consent"
    assert calls == []                       # never wrote


def test_read_consent_alone_does_not_authorise_the_write():
    """The gap this probe must not fall into: a customer who approved a read
    must not get an account created by omission."""
    calls = []
    res = _probe(signup_consent=False,
                 signup=lambda *a: calls.append(a) or _signup_ok())
    assert res.status == "skipped"
    assert res.evidence["reason"] == "no_signup_consent"
    assert calls == []                       # never wrote


# --- signup failure is undetermined, never safe -----------------------------

def test_disabled_signup_is_error_not_failure():
    res = _probe(signup=_signup_disabled)
    assert res.status == "error"             # NOT "failure"
    assert res.evidence["reason"] == "signup_no_session"


def test_email_confirmation_without_a_token_is_error_not_failure():
    res = _probe(signup=_signup_needs_confirmation)
    assert res.status == "error"
    assert res.evidence["reason"] == "signup_no_session"


# --- the finding ------------------------------------------------------------

def test_a_fresh_account_reading_rows_is_cross_tenant_success():
    res = _probe(fetch=_reads(OTHERS_ROWS))
    assert res.status == "success"
    assert res.success is True
    assert res.template_id == "rls_cross_tenant_runtime"
    # the throwaway account is named so the customer can delete it
    assert res.evidence["test_account"].startswith("drydock-probe+")
    # no raw row value leaves, only shapes (shared oracle's redaction)
    assert "a@x" not in repr(res.evidence)


def test_a_fresh_account_reading_nothing_is_failure():
    res = _probe(fetch=_reads([]))
    assert res.status == "failure"
    assert res.success is False


def test_a_denied_read_is_error_not_failure():
    def denied(*_a):
        return 403, {"code": "42501", "message": "permission denied"}
    res = _probe(fetch=denied)
    # a grant/permission problem tells us nothing about the policy scope
    assert res.status in ("error", "failure")
    # specifically: PostgREST 403/42501 is a denial -> not exposed, conclusive
    assert res.success is False


# --- before/after through the shared compare --------------------------------

def test_the_pair_verifies_cross_tenant_before_and_scoped_after():
    """BEFORE: auth-only policy, the fresh account reads others' rows.
    AFTER: per-user policy, the same account reads []. success -> failure ->
    verified, the same shape every other class uses."""
    before = _probe(fetch=_reads(OTHERS_ROWS))
    after = _probe(fetch=_reads([]))
    report = build_proof_report(before, after, informational=False)
    assert before.status == "success"
    assert after.status == "failure"
    assert report.verified is True


def test_negative_control_does_not_verify_when_the_policy_stays_open():
    """The fix is a per-user policy. If it was never applied, the fresh account
    still reads others' rows AFTER, and nothing verifies -- a green that has
    never been red proves only that it ran."""
    before = _probe(fetch=_reads(OTHERS_ROWS))
    after_uncorrected = _probe(fetch=_reads(OTHERS_ROWS))
    report = build_proof_report(before, after_uncorrected, informational=False)
    assert report.verified is False
