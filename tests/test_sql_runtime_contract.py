"""Independent-oracle, failure-boundary, and opt-in real PostgreSQL tests."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from app.proof import sql_runtime_contract as contract


# Capture before other tests temporarily alter environment variables.
_TEST_DSN = os.environ.get("SQL_CONTRACT_DATABASE_URL")


def _case(name):
    return next(case for case in contract._CASES if case.name == name)


def _rows(rows):
    return {"outcome": "rows", "rows": rows, "columns": list(contract._COLUMNS)}


def test_fixed_query_must_match_independent_oracle_not_baseline():
    case = _case("normal")
    wrong = _rows([])
    assert contract._evaluate_case(case, "before", wrong)["status"] == "failed"
    assert contract._evaluate_case(case, "after", wrong)["status"] == "failed"


def test_payload_literal_itself_is_preserved_by_parameterization():
    case = _case("sql_payload")
    expected = [(9, "' OR TRUE --")]
    assert contract._expected_rows(case) == expected
    assert contract._evaluate_case(case, "after", _rows(expected))["status"] == "passed"
    assert contract._evaluate_case(case, "after", _rows([]))["status"] == "failed"
    assert contract._evaluate_case(case, "after", _rows(list(contract._FIXTURES)))["status"] == "failed"


@pytest.mark.parametrize("stage", ["before", "mutation"])
@pytest.mark.parametrize("sqlstate", ["42601", "42501", "57014"])
def test_database_error_never_demonstrates_exploit_or_mutation(stage, sqlstate):
    verdict = contract._evaluate_case(
        _case("sql_payload"), stage,
        {"outcome": "database_error", "diagnostic": {"type": "DatabaseError", "sqlstate": sqlstate}},
    )
    assert verdict["status"] == "failed"
    assert verdict["exploit_observed"] is False
    assert verdict["mutation_detected"] is False


def test_mutant_must_reproduce_extra_rows_not_merely_differ():
    case = _case("sql_payload")
    assert contract._evaluate_case(case, "mutation", _rows([(9, "wrong")]))["status"] == "failed"
    assert contract._evaluate_case(case, "mutation", _rows(contract._expected_rows(case)))["status"] == "failed"
    verdict = contract._evaluate_case(case, "mutation", _rows(list(contract._FIXTURES)))
    assert verdict["status"] == "passed"
    assert verdict["mutation_detected"] is True


def test_null_operator_is_explicit_and_cannot_change_silently():
    equals = _case("null_equality")
    null_safe = _case("null_safe_equality")
    assert contract._expected_rows(equals) == []
    assert contract._expected_rows(null_safe) == [(7, None)]
    assert contract._evaluate_case(equals, "after", _rows([(7, None)]))["status"] == "failed"
    assert contract._evaluate_case(null_safe, "after", _rows([]))["status"] == "failed"


@pytest.mark.parametrize("rows,columns", [
    ([(True, "alice"), (8, "alice")], list(contract._COLUMNS)),
    ([(1, b"alice"), (8, "alice")], list(contract._COLUMNS)),
    ([(1, "alice"), (8, "alice")], [("id", 20), ("name", 25)]),
    ([(1, "alice"), (8, "alice")], [("name", 23), ("id", 25)]),
])
def test_matching_values_with_wrong_result_types_are_rejected(rows, columns):
    verdict = contract._evaluate_case(_case("normal"), "after", {
        "outcome": "rows", "rows": rows, "columns": columns,
    })
    assert verdict["reason"] == "result_shape_mismatch"


def test_quote_error_is_expected_control_but_not_security_proof():
    verdict = contract._evaluate_case(_case("quote"), "before", {
        "outcome": "database_error", "diagnostic": {"type": "SyntaxError", "sqlstate": "42601"},
    })
    assert verdict["status"] == "passed"
    assert verdict["exploit_observed"] is False
    assert verdict["mutation_detected"] is False


def test_row_limit_is_enforced_before_serializing_rows():
    verdict = contract._evaluate_case(_case("normal"), "after", _rows([(1, "alice")] * 33))
    assert verdict["reason"] == "row_limit_exceeded"
    assert "row_ids" not in verdict


class _Connection:
    """Fake only the transaction boundary; case results use explicit fixtures."""

    closed = False

    def __init__(self, *, rollback_error=False, table_survives=False):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE, server_version=170000)
        self.rollback_error = rollback_error
        self.table_survives = table_survives
        self.transaction_count = 0
        self.statements = []

    @contextmanager
    def transaction(self, *, force_rollback):
        assert force_rollback is True
        self.transaction_count += 1
        self.info.transaction_status = TransactionStatus.INTRANS
        try:
            yield
        finally:
            if self.rollback_error:
                raise RuntimeError("secret connection password must not be serialized")
            self.info.transaction_status = TransactionStatus.IDLE

    @contextmanager
    def cursor(self, *, row_factory):
        yield self

    def execute(self, query):
        self.statements.append(query)

    def executemany(self, query, rows):
        self.statements.append(query)

    def fetchone(self):
        return ("drydock_sql_contract_fixture" if self.table_survives and self.transaction_count > 1 else None,)


def _scripted_success(connection, case, stage):
    if stage != "after" and case.vulnerable_sqlstate:
        return {"outcome": "database_error", "diagnostic": {"sqlstate": case.vulnerable_sqlstate}}
    rows = list(contract._FIXTURES) if stage != "after" and case.attack else contract._expected_rows(case)
    return _rows(rows)


def test_rollback_failure_cannot_leave_a_verified_record(monkeypatch):
    monkeypatch.setattr(contract, "_execute_case", _scripted_success)
    result = contract.run_contract(_Connection(rollback_error=True))
    assert result["status"] == "unavailable"
    assert result["reason"] == "rollback_failed"
    assert result["synthetic_recipe_verified"] is False
    assert "secret" not in json.dumps(result)


def test_temporary_table_surviving_rollback_cannot_pass(monkeypatch):
    monkeypatch.setattr(contract, "_execute_case", _scripted_success)
    result = contract.run_contract(_Connection(table_survives=True))
    assert result["reason"] == "temporary_table_cleanup_failed"
    assert result["synthetic_recipe_verified"] is False


def test_busy_connection_is_not_touched_or_rolled_back():
    connection = _Connection()
    connection.info.transaction_status = TransactionStatus.INTRANS
    result = contract.run_contract(connection)
    assert result["reason"] == "connection_not_idle"
    assert connection.statements == []
    assert connection.transaction_count == 0


def test_complete_synthetic_result_never_claims_customer_verification(monkeypatch):
    monkeypatch.setattr(contract, "_execute_case", _scripted_success)
    result = contract.run_contract(_Connection())
    assert result["status"] == "passed"
    assert result["synthetic_recipe_verified"] is True
    assert result["runtime_verified"] is False
    assert result["customer_project_verified"] is False
    assert result["automatic_patch"] is False
    assert result["cleanup"] == {"rollback_completed": True, "temporary_table_absent": True}


def test_unchanged_parameterized_mutant_is_not_detected(monkeypatch):
    def broken_mutation(connection, case, stage):
        return _scripted_success(connection, case, "after" if stage == "mutation" else stage)

    monkeypatch.setattr(contract, "_execute_case", broken_mutation)
    result = contract.run_contract(_Connection())
    assert result["status"] == "failed"
    assert result["synthetic_recipe_verified"] is False
    mutation = result["stages"][2]
    payload = next(case for case in mutation["cases"] if case["case"] == "sql_payload")
    assert payload["reason"] == "attack_not_demonstrated"


@pytest.mark.parametrize('omitted', ['all', 'sql_payload', 'null_safe_equality'])
def test_missing_required_controls_cannot_verify_a_recipe(monkeypatch, omitted):
    monkeypatch.setattr(contract, '_execute_case', _scripted_success)
    selected = () if omitted == 'all' else tuple(case for case in contract._CASES if case.name != omitted)
    monkeypatch.setattr(contract, '_CASES', selected)
    result = contract.run_contract(_Connection())
    assert result['status'] == 'failed'
    assert result['synthetic_recipe_verified'] is False


@pytest.fixture
def postgres_connection():
    if not _TEST_DSN:
        pytest.skip("SQL_CONTRACT_DATABASE_URL is not configured")
    from scripts.verify_sql_runtime_contract import connect_target

    with connect_target(_TEST_DSN) as connection:
        yield connection


def test_real_postgresql_before_after_mutation_and_cleanup(postgres_connection):
    result = contract.run_contract(postgres_connection)
    assert result["status"] == "passed", result
    assert result["synthetic_recipe_verified"] is True
    assert result["cleanup"] == {"rollback_completed": True, "temporary_table_absent": True}
    assert postgres_connection.info.transaction_status == TransactionStatus.IDLE
    before, after, mutation = result["stages"]
    before_attack = next(case for case in before["cases"] if case["case"] == "sql_payload")
    after_attack = next(case for case in after["cases"] if case["case"] == "sql_payload")
    mutant_attack = next(case for case in mutation["cases"] if case["case"] == "sql_payload")
    assert before_attack["row_count"] == 9
    assert after_attack["row_ids"] == [9]
    assert mutant_attack["mutation_detected"] is True


def test_real_postgresql_repeated_run_and_settings_restored(postgres_connection):
    # SET LOCAL and the stand's temporary relation must not leak between runs.
    postgres_connection.execute("SET standard_conforming_strings = off")
    postgres_connection.commit()
    first = contract.run_contract(postgres_connection)
    second = contract.run_contract(postgres_connection)
    assert first["status"] == second["status"] == "passed"
    assert postgres_connection.execute("SHOW standard_conforming_strings").fetchone()[0] == "off"
    postgres_connection.rollback()


def test_real_postgresql_existing_temporary_table_is_preserved(postgres_connection):
    postgres_connection.execute("CREATE TEMP TABLE drydock_sql_contract_fixture (sentinel integer)")
    postgres_connection.execute("INSERT INTO pg_temp.drydock_sql_contract_fixture VALUES (123)")
    postgres_connection.commit()
    result = contract.run_contract(postgres_connection)
    assert result["status"] == "unavailable"
    assert result["reason"] == "temporary_table_conflict"
    assert result["synthetic_recipe_verified"] is False
    assert result["stages"] == []
    assert postgres_connection.execute("SELECT * FROM pg_temp.drydock_sql_contract_fixture").fetchall() == [(123,)]
    postgres_connection.rollback()
