"""The operator-side locks on the only script that touches a real database.

`run_rls_probe` has its own consent gate and its own URL allowlist, tested in
tests/test_proof_rls_probe.py. These are the locks in front of it: the ones a
person trips over at 1am with a terminal open, which is when this script gets
run.

Every refusal here must happen BEFORE any request. A guard that fires after the
read has already happened is decoration.
"""

from __future__ import annotations

import pytest

import scripts.probe_supabase_rls_live as live

REF = "egoprezwkjaqacxtjwfl"
GOOD_KEY = "sb_publishable_" + "a" * 24


@pytest.fixture
def no_requests(monkeypatch):
    """Fail loudly if anything tries to probe during a refusal path."""
    def _boom(**_kw):
        raise AssertionError("a request was attempted after a refusal")

    monkeypatch.setattr(live, "run_rls_probe", _boom)
    return _boom


def _env(monkeypatch, *, consent: str | None, key: str | None) -> None:
    for name, value in (("RLS_PROBE_CONSENT", consent),
                        ("SUPABASE_ANON_KEY", key)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


# --- consent ----------------------------------------------------------------

def test_without_the_consent_phrase_nothing_is_probed(monkeypatch, no_requests):
    _env(monkeypatch, consent=None, key=GOOD_KEY)
    assert live.main([REF, "agent_projects"]) == 2


def test_a_near_miss_phrase_is_not_accepted(monkeypatch, no_requests):
    """The phrase is exact on purpose. `true`, `yes`, `1` are what someone
    types when they are guessing at a flag rather than confirming ownership of
    a database."""
    for wrong in ("true", "yes", "1", "i own this project", "I-OWN-THIS-PROJECT"):
        _env(monkeypatch, consent=wrong, key=GOOD_KEY)
        assert live.main([REF, "agent_projects"]) == 2, wrong


def test_the_exact_phrase_lets_the_probe_run(monkeypatch):
    seen: list = []

    def _fake(**kw):
        seen.append(kw)
        return _Attempt("failure")

    monkeypatch.setattr(live, "run_rls_probe", _fake)
    _env(monkeypatch, consent="i-own-this-project", key=GOOD_KEY)
    assert live.main([REF, "agent_projects"]) == 0
    assert seen and seen[0]["consent"] is True
    assert seen[0]["table"] == "agent_projects"


# --- the key ----------------------------------------------------------------

def test_a_masked_key_is_refused_before_any_request(monkeypatch, no_requests):
    """MEASURED 2026-08-18: the key arrived with every character replaced by a
    bullet — a masked rendering copied instead of the value. The mask preserves
    length, so 208 characters looked exactly right, and the failure surfaced as
    UnicodeEncodeError inside httpx and was reported as "the request did not
    complete" for every table.

    True, and useless. A key that cannot go in a header is fixable in seconds
    by the person at the keyboard; an infrastructure failure is not."""
    _env(monkeypatch, consent="i-own-this-project",
         key="eyJhbGci" + "•" * 200)
    assert live.main([REF, "agent_projects"]) == 2


def test_an_absent_key_is_refused(monkeypatch, no_requests):
    _env(monkeypatch, consent="i-own-this-project", key=None)
    assert live.main([REF, "agent_projects"]) == 2


def test_the_key_is_never_printed(monkeypatch, capsys):
    monkeypatch.setattr(live, "run_rls_probe",
                        lambda **_kw: _Attempt("failure"))
    _env(monkeypatch, consent="i-own-this-project", key=GOOD_KEY)
    live.main([REF, "agent_projects"])
    out = capsys.readouterr()
    assert GOOD_KEY not in out.out + out.err
    assert str(len(GOOD_KEY)) in out.out       # the length, and only that


# --- the exit code carries the finding --------------------------------------

def test_an_exposed_table_exits_non_zero(monkeypatch):
    """A wrapper should be able to notice a finding without parsing prose."""
    monkeypatch.setattr(live, "run_rls_probe",
                        lambda **_kw: _Attempt("success"))
    _env(monkeypatch, consent="i-own-this-project", key=GOOD_KEY)
    assert live.main([REF, "agent_projects"]) == 1


def test_a_closed_table_exits_zero(monkeypatch):
    monkeypatch.setattr(live, "run_rls_probe",
                        lambda **_kw: _Attempt("failure"))
    _env(monkeypatch, consent="i-own-this-project", key=GOOD_KEY)
    assert live.main([REF, "agent_projects"]) == 0


def test_an_error_is_not_reported_as_a_finding_nor_as_safety(monkeypatch):
    """`error` means the probe learned nothing. It must not raise the finding
    exit code, and it must not be silently folded into "closed" either — the
    caller sees ERROR in the table."""
    monkeypatch.setattr(live, "run_rls_probe", lambda **_kw: _Attempt("error"))
    _env(monkeypatch, consent="i-own-this-project", key=GOOD_KEY)
    assert live.main([REF, "agent_projects"]) == 0


class _Attempt:
    def __init__(self, status: str):
        self.status = status
        self.detail = "d"
        self.evidence = {"reason": "r"}
