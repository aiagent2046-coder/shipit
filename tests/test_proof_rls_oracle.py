"""What one PostgREST answer is allowed to mean.

The oracle is the half that can be wrong without anyone noticing, so the
status table is pinned here and the network is not involved.

The case that matters most is `200 []`. It is what a correctly protected table
returns AND what an empty table returns, and one request cannot separate them.
Calling it "protected" would repeat, in the opposite direction, the defect
removed from the CORS oracle — a verdict stated more strongly than the evidence
supports.
"""

from __future__ import annotations

from app.proof.rls_oracle import evaluate_rls_response, summarise_rows

ROWS = [
    {"id": "u1", "email": "founder@example.com", "sentiment": "positive"},
    {"id": "u2", "email": "other@example.com", "sentiment": "wary"},
]


# --- the status table -------------------------------------------------------

def test_rows_coming_back_is_the_exploit() -> None:
    v = evaluate_rls_response(200, ROWS, table="users")
    assert v.exposed is True
    assert v.reason == "rows_readable"
    assert v.conclusive
    assert v.evidence["rows_read"] == 2


def test_an_empty_array_is_not_proof_of_protection() -> None:
    """THE LOAD-BEARING CASE. A protected table and an empty table give the
    identical answer, so this verdict carries a flag saying so, and nothing
    downstream may quote it alone as "we checked, you are safe"."""
    v = evaluate_rls_response(200, [], table="users")
    assert v.exposed is False
    assert v.reason == "empty_result"
    assert v.evidence["alone_proves_nothing"] is True


def test_a_real_denial_stands_on_its_own() -> None:
    """Unlike an empty result: the database refused rather than returning
    nothing, so there is no second reading."""
    v = evaluate_rls_response(
        403, {"code": "42501", "message": "permission denied for table users"},
        table="users")
    assert v.exposed is False
    assert v.reason == "permission_denied"
    assert v.conclusive is True


def test_a_bare_401_is_more_likely_our_key_than_their_safety() -> None:
    """Guessing between "their table is protected" and "our key is wrong" is
    how a broken probe reports every customer as secure."""
    v = evaluate_rls_response(401, {"message": "Invalid API key"}, table="users")
    assert v.exposed is False
    assert v.conclusive is False


def test_a_missing_table_is_not_a_protected_table() -> None:
    v = evaluate_rls_response(404, {"code": "PGRST205"}, table="ghost")
    assert v.exposed is False
    assert v.reason == "table_not_exposed"


def test_a_server_error_tells_us_nothing() -> None:
    v = evaluate_rls_response(500, {"message": "boom"}, table="users")
    assert v.exposed is False
    assert v.conclusive is False
    assert v.reason == "unexpected_response"


def test_postgrest_answers_200_empty_when_rls_blocks_not_403() -> None:
    """Recorded as a test because the intuition is wrong and the whole status
    table depends on it: RLS FILTERS rows, it does not deny. Anyone expecting a
    denial reads the normal secure case as an error."""
    assert evaluate_rls_response(200, [], table="t").reason == "empty_result"
    assert evaluate_rls_response(200, [], table="t").exposed is False


# --- what may leave the probe -----------------------------------------------

def test_no_value_from_a_customers_row_survives_the_summary() -> None:
    """proof_json is stored and rendered into a PR. These are a customer's
    users' real records — the one thing that must not travel, redacted or
    otherwise."""
    summary = summarise_rows(ROWS)
    blob = repr(summary)
    assert "founder@example.com" not in blob
    assert "other@example.com" not in blob
    assert "positive" not in blob
    assert "u1" not in blob


def test_the_summary_still_proves_a_real_read_happened() -> None:
    """Column names and value lengths are what make this evidence rather than
    an assertion: `email: str(19)` says an address was there, `email` alone
    could be an empty column."""
    summary = summarise_rows(ROWS)
    assert summary["rows_read"] == 2
    assert "email" in summary["columns"]
    assert summary["shapes"]["email"] == "str(19)"


def test_the_evidence_of_an_exposure_carries_the_same_summary() -> None:
    v = evaluate_rls_response(200, ROWS, table="users")
    assert "founder@example.com" not in repr(v.evidence)
    assert v.evidence["columns"] == ["id", "email", "sentiment"]


def test_a_column_that_is_null_in_the_sample_is_described_not_guessed() -> None:
    summary = summarise_rows([{"id": "u1", "note": None}])
    assert summary["shapes"]["note"] == "null"


def test_rows_beyond_the_sample_are_counted_but_not_described() -> None:
    """The count is the customer's number; the shape only needs a few rows."""
    many = [{"email": f"user{i}@example.com"} for i in range(50)]
    summary = summarise_rows(many, limit=3)
    assert summary["rows_read"] == 50
    assert summary["columns"] == ["email"]


def test_columns_absent_from_the_first_row_are_still_reported() -> None:
    """PostgREST returns the selected columns per row; a nullable field can be
    missing from one and present in the next. Reading only the first row would
    under-report which fields were reachable."""
    summary = summarise_rows([{"id": "1"}, {"id": "2", "phone": "+70000000000"}])
    assert "phone" in summary["columns"]
