"""Status table and the two rules this probe enforces in code.

Unlike every other template here, this one touches a REAL, LIVE database that
belongs to a real person. The two rules that follow from that are not comments
in a plan — they are branches with tests, because a plan cannot stop a caller
and a default can.
"""

from __future__ import annotations

import pytest

from app.proof.compare import build_proof_report
from app.proof.rls_probe import (
    TEMPLATE_ID,
    UnsafeProjectUrl,
    run_rls_probe,
    validate_project_url,
)

PROJECT = "https://abcdefghijklmnopqrst.supabase.co"
KEY = "anon-key-placeholder"
ROWS = [{"id": "u1", "email": "a@example.com"}]


def _fetch(status: int, body):
    def _fn(*_a, **_k):
        return status, body
    return _fn


def _probe(fetch, **kw):
    params = dict(project_url=PROJECT, anon_key=KEY, table="users",
                  consent=True, fetch=fetch)
    params.update(kw)
    return run_rls_probe(**params)


# --- rule 1: consent --------------------------------------------------------

def test_without_consent_nothing_is_requested() -> None:
    """`consent` has no default, so a caller that has not thought about it
    cannot accidentally read someone's database."""
    called: list = []

    def _spy(*a, **k):
        called.append(a)
        return 200, ROWS

    attempt = _probe(_spy, consent=False)
    assert called == []
    assert attempt.status == "skipped"


def test_no_consent_is_skipped_and_never_failure() -> None:
    """`failure` renders as "the attack did not work" and reads as safety. A
    check that never ran has said nothing — the same distinction #22 was
    about."""
    attempt = _probe(_fetch(200, ROWS), consent=False)
    assert attempt.status == "skipped"
    assert attempt.success is False
    assert attempt.evidence["reason"] == "no_consent"


def test_consent_is_a_required_keyword() -> None:
    with pytest.raises(TypeError):
        run_rls_probe(project_url=PROJECT, anon_key=KEY,  # type: ignore[call-arg]
                      table="users")


# --- rule 2: the repository does not choose the address ---------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "https://169.254.169.254.supabase.co.evil.test/",
    "https://internal-service.local/rest/v1/",
    "http://127.0.0.1:8000",
    "https://abcdefghijklmnopqrst.supabase.co.attacker.test",
    "https://attacker.test/?x=https://abcdefghijklmnopqrst.supabase.co",
    "file:///etc/passwd",
    "",
])
def test_only_a_supabase_project_url_is_ever_called(url) -> None:
    """The project URL is read out of the CUSTOMER'S OWN SOURCE. Unrestricted,
    this is an SSRF primitive: a repository could aim our infrastructure at a
    cloud metadata endpoint or an internal service and collect the answer.

    Same rule that keeps the CORS probe on loopback, from the other side —
    there the address had to be ours, here it must be theirs and of one exact
    shape.
    """
    with pytest.raises(UnsafeProjectUrl):
        validate_project_url(url)


def test_a_rejected_url_stops_the_request_rather_than_reporting_safety() -> None:
    called: list = []

    def _spy(*a, **k):
        called.append(a)
        return 200, []

    attempt = _probe(_spy, project_url="http://169.254.169.254/")
    assert called == []
    assert attempt.status == "skipped"
    assert attempt.evidence["reason"] == "unsafe_project_url"


def test_a_real_project_url_is_accepted() -> None:
    assert validate_project_url(PROJECT) == PROJECT
    assert validate_project_url(PROJECT + "/") == PROJECT


def test_loopback_is_refused_unless_explicitly_allowed() -> None:
    """The e2e stands up a local stack and needs this; production must not
    have it, or the probe becomes an SSRF into our own host."""
    with pytest.raises(UnsafeProjectUrl):
        validate_project_url("http://127.0.0.1:54321")
    assert validate_project_url("http://127.0.0.1:54321",
                                allow_loopback=True) == "http://127.0.0.1:54321"


def test_a_table_name_from_parsed_sql_is_not_trusted_into_the_path() -> None:
    attempt = _probe(_fetch(200, ROWS), table="users?select=*&evil=1")
    assert attempt.status == "skipped"
    assert attempt.evidence["reason"] == "unsafe_table_name"


# --- the status table -------------------------------------------------------

def test_rows_returned_is_a_confirmed_exposure() -> None:
    attempt = _probe(_fetch(200, ROWS))
    assert attempt.status == "success"
    assert attempt.success is True
    assert attempt.template_id == TEMPLATE_ID
    assert attempt.evidence["reason"] == "rows_readable"


def test_an_empty_result_is_a_failure_not_an_error() -> None:
    """The app answered; the attack returned nothing. That is a real, useful
    answer — and the flag saying it proves nothing on its own travels with
    it."""
    attempt = _probe(_fetch(200, []))
    assert attempt.status == "failure"
    assert attempt.evidence["alone_proves_nothing"] is True


def test_a_bad_key_is_an_error_not_a_failure() -> None:
    """A 401 with no PostgREST code is more likely our key than their safety,
    and reporting it as "checked, fine" is how a broken probe declares every
    customer secure."""
    attempt = _probe(_fetch(401, {"message": "Invalid API key"}))
    assert attempt.status == "error"


def test_a_request_that_never_completed_is_an_error() -> None:
    def _boom(*_a, **_k):
        raise TimeoutError("read timeout")

    attempt = _probe(_boom)
    assert attempt.status == "error"
    assert "TimeoutError" in attempt.detail


def test_a_server_error_is_an_error() -> None:
    assert _probe(_fetch(500, {"message": "boom"})).status == "error"


@pytest.mark.parametrize("status,body", [
    (200, ROWS), (200, []), (401, {}), (500, {}), (404, {"code": "PGRST205"}),
])
def test_every_outcome_is_one_of_the_four_declared_statuses(status, body) -> None:
    assert _probe(_fetch(status, body)).status in (
        "success", "failure", "skipped", "error")


# --- no customer data leaves -------------------------------------------------

def test_no_row_value_reaches_the_evidence() -> None:
    """proof_json is stored and rendered into a PR."""
    attempt = _probe(_fetch(200, [
        {"id": "u1", "email": "founder@example.com", "sentiment": "wary"}]))
    blob = repr(attempt.evidence)
    assert "founder@example.com" not in blob
    assert "wary" not in blob
    assert attempt.evidence["rows_read"] == 1


# --- pairing ----------------------------------------------------------------

def test_a_before_after_pair_composes_with_build_proof_report() -> None:
    """Two calls, compared by the same function the CORS and static paths use.

    This pairing is also what makes an empty `after` meaningful: the `before`
    half proved the table has rows, so the same request returning none is a
    real change rather than an empty table.
    """
    before = _probe(_fetch(200, ROWS))
    after = _probe(_fetch(200, []))
    report = build_proof_report(before, after, informational=False)
    assert report.verified is True
    assert report.template_id == TEMPLATE_ID


def test_two_empty_results_never_verify_anything() -> None:
    """Without a before that read rows, an empty after is just an empty
    table."""
    report = build_proof_report(_probe(_fetch(200, [])),
                                _probe(_fetch(200, [])), informational=False)
    assert report.verified is False


def test_a_skipped_before_can_never_be_verified() -> None:
    report = build_proof_report(_probe(_fetch(200, ROWS), consent=False),
                                _probe(_fetch(200, [])), informational=False)
    assert report.verified is False
