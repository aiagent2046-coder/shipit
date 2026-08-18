"""The consented pass, and the four rules that govern making real requests.

The pieces below it are tested on their own. What is tested here is policy:
that consent cannot be skipped, that a refusal never reads as a clean bill of
health, that there is a ceiling on how many requests a repository can cause,
and that "not asked" stays distinguishable from "asked and nothing came back".
"""

from __future__ import annotations

import base64
import io
import json
import zipfile

from app.proof.rls_live_check import MAX_TABLES, run_live_rls_check

REF = "egoprezwkjaqacxtjwfl"


def jwt(role: str = "anon", ref: str = REF) -> str:
    """Structurally real, because the secrets scanner is what finds it.

    A shortened stand-in does not match the scanner's JWT rule, and the whole
    pass then reports "no Supabase key in this repository" — which is a
    correct answer to the wrong input, and how a first version of this file
    tested nothing.
    """
    def seg(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    head = seg({"alg": "HS256", "typ": "JWT"})
    body = seg({"iss": "supabase", "ref": ref, "role": role,
                "iat": 1779635486, "exp": 2095211486})
    return f"{head}.{body}.XaMB3mjNqMf757EmpUpjnsJ5mldVtmsDiag7FQDjubg"


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


REPO = make_zip({
    "repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
    "repo/supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        create table public.products (id uuid primary key, title text);
    """,
})


def rows(*_args, **_kwargs):
    """Every table hands back a row — an exposed project."""
    return 200, [{"id": "1", "email": "a@b.c"}]


def empty(*_args, **_kwargs):
    return 200, []


def denied(*_args, **_kwargs):
    return 401, {"message": "Invalid API key"}


# --- consent -----------------------------------------------------------------

def test_without_consent_nothing_is_read_and_nothing_is_claimed() -> None:
    calls = []

    def spy(*args, **kwargs):
        calls.append(args)
        return rows()

    result = run_live_rls_check(REPO, consent=False, fetch=spy)
    assert result.status == "refused"
    assert calls == []
    assert result.exposed_tables == []
    assert "consent" in result.reason


def test_a_refusal_never_reads_as_a_clean_bill_of_health() -> None:
    """`status` is the load-bearing word. "refused" and "checked, nothing came
    back" are different sentences, and only one of them is about the database."""
    for zip_bytes in (make_zip({"repo/README.md": "# no keys here"}),
                      make_zip({"repo/.env": f"KEY={jwt(role='service_role')}"})):
        result = run_live_rls_check(zip_bytes, consent=True, fetch=rows)
        assert result.status == "refused"
        assert result.reason
        assert result.attempts == []


# --- the ceiling -------------------------------------------------------------

def test_a_repository_cannot_cause_unbounded_requests() -> None:
    many = {"repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n"}
    many["repo/src/db.ts"] = "".join(
        f"supabase.from('t{i:03d}').select('*');\n" for i in range(200))
    calls = []

    def spy(base, key, table, limit):
        calls.append(table)
        return empty()

    result = run_live_rls_check(make_zip(many), consent=True, fetch=spy)
    assert len(calls) == MAX_TABLES
    assert len(result.checked) == MAX_TABLES


def test_the_tables_beyond_the_ceiling_are_named_not_just_dropped() -> None:
    """"We checked 12 of your 40 tables" is a different report from "we checked
    your tables", and the customer is the one who knows which of the other 28
    matter."""
    many = {"repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
            "repo/src/db.ts": "".join(
                f"supabase.from('t{i:03d}').select('*');\n" for i in range(20))}
    result = run_live_rls_check(make_zip(many), consent=True, fetch=empty)
    assert len(result.not_checked) == 20 - MAX_TABLES
    assert set(result.checked) & set(result.not_checked) == set()


def test_private_looking_tables_get_the_slots() -> None:
    """The ceiling and the ordering are one mechanism. A cap that spent its
    requests on whatever sorted first would make the ordering decorative."""
    entries = {"repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
               "repo/src/db.ts": "".join(
                   f"supabase.from('aaa{i:03d}').select('*');\n"
                   for i in range(30))}
    entries["repo/supabase/migrations/0001.sql"] = (
        "create table public.users (id uuid primary key, email text);")
    result = run_live_rls_check(make_zip(entries), consent=True,
                                fetch=empty, max_tables=3)
    assert "users" in result.checked


# --- what the answers mean ---------------------------------------------------

def test_rows_coming_back_is_the_only_thing_reported_as_exposed() -> None:
    result = run_live_rls_check(REPO, consent=True, fetch=rows)
    assert result.status == "checked"
    assert set(result.exposed_tables) == {"users", "products"}


def test_an_empty_answer_is_not_reported_as_exposed() -> None:
    """RLS filters rather than denies, so a protected table and an EMPTY table
    answer identically. Neither is `success`."""
    result = run_live_rls_check(REPO, consent=True, fetch=empty)
    assert result.exposed_tables == []
    assert all(a.status == "failure" for a in result.attempts)


def test_a_request_that_settled_nothing_is_counted_apart_from_a_clean_one() -> None:
    """A rejected key answers every table identically, and counting that as
    "we checked and it was fine" is the inflation this project removed twice."""
    result = run_live_rls_check(REPO, consent=True, fetch=denied)
    assert result.inconclusive == len(result.attempts)
    assert result.exposed_tables == []
    assert all(a.status != "failure" for a in result.attempts)


def test_a_transport_failure_is_an_error_not_a_pass() -> None:
    def boom(*_args, **_kwargs):
        raise TimeoutError("connect timed out")

    result = run_live_rls_check(REPO, consent=True, fetch=boom)
    assert result.inconclusive == len(result.attempts)
    assert result.exposed_tables == []


# --- the credential ----------------------------------------------------------

def test_the_result_does_not_carry_the_key() -> None:
    """It is derived from the repository at check time, used, and dropped. The
    result is persisted and rendered; the credential must not be in it."""
    result = run_live_rls_check(REPO, consent=True, fetch=rows)
    blob = json.dumps({
        "status": result.status, "reason": result.reason,
        "ref": result.project_ref, "checked": result.checked,
        "not_checked": result.not_checked,
        "attempts": [a.evidence for a in result.attempts],
        "details": [a.detail for a in result.attempts],
    })
    assert jwt() not in blob
    assert "eyJ" not in blob


def test_no_row_value_reaches_the_evidence() -> None:
    """The probe records column names, a count and value LENGTHS. A customer's
    user data must never land in something rendered into a report."""
    result = run_live_rls_check(REPO, consent=True, fetch=rows)
    blob = json.dumps([a.evidence for a in result.attempts])
    assert "a@b.c" not in blob


# --- the summary must not read as an all-clear ------------------------------
#
# MEASURED on the first live run through the endpoint: nine tables, nine empty
# answers, and a summary of `exposed_tables: []` with `inconclusive: 0`. Both
# numbers correct, the pair misleading — every attempt carried
# `alone_proves_nothing`, and what actually settled the run was a row count
# taken through the service role, which a customer does not have.

def test_empty_answers_are_counted_rather_than_read_as_protection() -> None:
    result = run_live_rls_check(REPO, consent=True, fetch=empty)
    assert result.exposed_tables == []
    assert result.inconclusive == 0
    # The number that stops the pair above from reading as "all clear".
    assert result.empty_but_unproven == len(result.attempts) > 0


def test_a_real_denial_is_not_counted_as_unproven() -> None:
    """THE CONTROL THAT MAKES THE COUNTER MEAN SOMETHING. The oracle also
    returns `failure` when the database REFUSED the key (42501) — that stands
    on its own, unlike an empty result, so counting it would put every
    correctly-locked table into a bucket labelled "we could not tell"."""
    def denied_by_rls(*_args, **_kwargs):
        return 403, {"code": "42501", "message": "permission denied"}

    result = run_live_rls_check(REPO, consent=True, fetch=denied_by_rls)
    assert all(a.status == "failure" for a in result.attempts)
    assert result.empty_but_unproven == 0
    assert result.inconclusive == 0


def test_a_table_postgrest_does_not_expose_is_not_counted_either() -> None:
    def undefined(*_args, **_kwargs):
        return 404, {"code": "PGRST205", "message": "not found"}

    result = run_live_rls_check(REPO, consent=True, fetch=undefined)
    assert result.empty_but_unproven == 0


def test_rows_coming_back_are_not_counted_as_unproven() -> None:
    result = run_live_rls_check(REPO, consent=True, fetch=rows)
    assert result.exposed_tables
    assert result.empty_but_unproven == 0


def test_a_refused_check_counts_nothing() -> None:
    result = run_live_rls_check(REPO, consent=False, fetch=empty)
    assert result.empty_but_unproven == 0
