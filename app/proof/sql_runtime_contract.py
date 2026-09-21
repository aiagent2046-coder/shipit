"""Execute a trusted, synthetic Psycopg parameterization contract.

This stand never accepts SQL, source code, fixtures, or expectations from a
project under audit. Its deliberately vulnerable query and its restored mutant
run only against the temporary table defined here. Passing proves this recipe
on these fixtures; it does not verify a customer application or authorize a
patch. The caller must supply a dedicated, already-open idle connection.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row


CONTRACT_ID = "sql-value-parameterization-python-psycopg3"
MAX_ROWS = 32
_TABLE = "pg_temp.drydock_sql_contract_fixture"
_SCHEMA = (
    "CREATE TEMP TABLE drydock_sql_contract_fixture "
    '(id integer PRIMARY KEY, name text COLLATE "C") ON COMMIT DROP'
)
_FIXTURES: tuple[tuple[int, str | None], ...] = (
    (1, "alice"),
    (2, "bob"),
    (3, ""),
    (4, "Привет 🛶"),
    (5, "O'Reilly"),
    (6, "path\\segment"),
    (7, None),
    (8, "alice"),
    (9, "' OR TRUE --"),
)
_COLUMNS = (("id", 23), ("name", 25))  # PostgreSQL int4 and text OIDs.


@dataclass(frozen=True)
class _Case:
    name: str
    value: str | None
    null_safe: bool = False
    attack: bool = False
    vulnerable_sqlstate: str | None = None


_CASES = (
    _Case("normal", "alice"),
    _Case("missing", "not-in-the-fixture"),
    _Case("empty", ""),
    _Case("unicode", "Привет 🛶"),
    _Case("quote", "O'Reilly", vulnerable_sqlstate="42601"),
    _Case("backslash", "path\\segment"),
    _Case("sql_payload", "' OR TRUE --", attack=True),
    _Case("null_equality", None),
    _Case("null_safe_equality", None, null_safe=True),
)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _expected_rows(case: _Case) -> list[tuple[int, str | None]]:
    """Independent Python oracle, including SQL's two explicit NULL contracts."""
    if case.value is None and not case.null_safe:
        return []
    return [row for row in _FIXTURES if row[1] == case.value]


def _query(case: _Case, stage: str) -> tuple[str, tuple[Any, ...] | None]:
    operator = "IS NOT DISTINCT FROM" if case.null_safe else "="
    prefix = f"SELECT id, name FROM {_TABLE} WHERE name {operator} "
    suffix = f"\nORDER BY id LIMIT {MAX_ROWS + 1}"
    if stage == "after":
        return prefix + "%s" + suffix, (case.value,)
    # Both the baseline and mutation deliberately restore interpolation. NULL
    # stays a SQL NULL, so the selected equality operator is never changed.
    literal = "NULL" if case.value is None else "'" + case.value + "'"
    return prefix + literal + suffix, None


def _diagnostic(exc: Exception) -> dict[str, str]:
    name = type(exc).__name__
    result = {"type": name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "Exception"}
    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and re.fullmatch(r"[0-9A-Z]{5}", sqlstate):
        result["sqlstate"] = sqlstate
    return result


def _execute_case(connection: Any, case: _Case, stage: str) -> dict[str, Any]:
    query, params = _query(case, stage)
    observation: dict[str, Any] = {"query_sha256": _digest(query)}
    try:
        # A syntax error in a vulnerable control must not poison later cases.
        # Always roll back each savepoint, including successful SELECTs.
        with connection.transaction(force_rollback=True):
            with connection.cursor(row_factory=tuple_row) as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchmany(MAX_ROWS + 1)
                description = cursor.description or ()
                columns = [(column.name, column.type_code) for column in description]
                observation.update(outcome="rows", rows=rows, columns=columns)
    except Exception as exc:
        observation.update(outcome="database_error", diagnostic=_diagnostic(exc))
    return observation


def _evaluate_case(case: _Case, stage: str, observation: dict[str, Any]) -> dict[str, Any]:
    """Judge against fixture semantics, never by comparing two executions."""
    expected = _expected_rows(case)
    record: dict[str, Any] = {
        "case": case.name,
        "null_semantics": "not_distinct" if case.null_safe else "equality",
        "status": "failed",
        "outcome": observation["outcome"],
        "expected_row_ids": [row[0] for row in expected],
        "expected_rows_sha256": _digest(expected),
        "query_sha256": observation.get("query_sha256", ""),
        "exploit_observed": False,
        "mutation_detected": False,
    }
    if observation["outcome"] != "rows":
        record["diagnostic"] = observation.get("diagnostic", {})
        expected_error = stage != "after" and case.vulnerable_sqlstate
        if expected_error and record["diagnostic"].get("sqlstate") == expected_error:
            record.update(status="passed", reason="expected_vulnerable_syntax_error")
        else:
            record["reason"] = "query_failed"
        return record

    rows = observation["rows"]
    columns = observation["columns"]
    record["row_count"] = len(rows)
    if len(rows) > MAX_ROWS:
        record["reason"] = "row_limit_exceeded"
        return record
    # Enforce both database column types and deserialized Python value types.
    # bool == 1 and loosely matching IDs alone must not satisfy the oracle.
    if tuple(columns) != _COLUMNS or any(
        not isinstance(row, (tuple, list))
        or len(row) != 2
        or type(row[0]) is not int
        or (row[1] is not None and type(row[1]) is not str)
        for row in rows
    ):
        record["reason"] = "result_shape_mismatch"
        return record
    rows = [tuple(row) for row in rows]
    record.update(
        row_ids=[row[0] for row in rows],
        rows_sha256=_digest(rows),
        columns=[{"name": name, "type_oid": oid} for name, oid in columns],
    )
    if case.attack and stage != "after":
        extra_ids = set(row[0] for row in rows) - set(row[0] for row in expected)
        # Exact fixture rows plus unauthorized extra rows prove exploitation.
        # Errors, merely different values, and empty results do not.
        exploited = rows == list(_FIXTURES) and bool(extra_ids)
        record.update(
            status="passed" if exploited else "failed",
            reason="extra_rows_observed" if exploited else "attack_not_demonstrated",
            exploit_observed=exploited,
            mutation_detected=exploited and stage == "mutation",
        )
    else:
        matches = rows == expected
        record.update(
            status="passed" if matches else "failed",
            reason="oracle_matched" if matches else "oracle_mismatch",
        )
    return record


def _base_record(connection: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "scope": "synthetic_recipe",
        "contract_id": CONTRACT_ID,
        "status": "unavailable",
        "reason": "not_executed",
        "synthetic_recipe_verified": False,
        "runtime_verified": False,
        "customer_project_verified": False,
        "automatic_patch": False,
        "psycopg_version": psycopg.__version__,
        "postgresql_version": getattr(connection.info, "server_version", None),
        "fixture_sha256": _digest(_FIXTURES),
        "schema_sha256": _digest(_SCHEMA),
        "limits": {"max_rows": MAX_ROWS, "statement_timeout_ms": 1500, "lock_timeout_ms": 500},
        "cleanup": {"rollback_completed": False, "temporary_table_absent": False},
        "stages": [],
    }


def _table_exists(cursor: Any) -> bool:
    cursor.execute("SELECT pg_catalog.to_regclass('pg_temp.drydock_sql_contract_fixture')")
    return cursor.fetchone()[0] is not None


def run_contract(connection: Any) -> dict[str, Any]:
    """Run all stages in rollback-only transactions on a dedicated connection.

    The connection remains open. Busy/failed/closed connections are rejected
    without issuing SQL or attempting to roll back someone else's transaction.
    No exception text, connection string, or project data enters the result.
    """
    record = _base_record(connection)
    if connection.closed or connection.info.transaction_status != TransactionStatus.IDLE:
        record["reason"] = "connection_not_idle"
        return record

    fixture_created = False
    phase = "execution"
    try:
        with connection.transaction(force_rollback=True):
            with connection.cursor(row_factory=tuple_row) as cursor:
                cursor.execute("SET LOCAL statement_timeout = '1500ms'")
                cursor.execute("SET LOCAL lock_timeout = '500ms'")
                cursor.execute("SET LOCAL idle_in_transaction_session_timeout = '5000ms'")
                cursor.execute("SET LOCAL search_path = pg_catalog, pg_temp")
                cursor.execute("SET LOCAL standard_conforming_strings = on")
                if _table_exists(cursor):
                    record["reason"] = "temporary_table_conflict"
                    return record
                cursor.execute(_SCHEMA)
                fixture_created = True
                cursor.executemany(f"INSERT INTO {_TABLE} (id, name) VALUES (%s, %s)", _FIXTURES)
            for stage in ("before", "after", "mutation"):
                cases = [_evaluate_case(case, stage, _execute_case(connection, case, stage)) for case in _CASES]
                record["stages"].append({
                    "stage": stage,
                    "status": "passed" if all(case["status"] == "passed" for case in cases) else "failed",
                    "cases": cases,
                })
            phase = "rollback"
        record["cleanup"]["rollback_completed"] = (
            not connection.closed and connection.info.transaction_status == TransactionStatus.IDLE
        )
        if not record["cleanup"]["rollback_completed"]:
            record["reason"] = "rollback_not_confirmed"
            return record
        # Independently check that rollback actually removed our temporary
        # relation. This read also runs in a rollback-only transaction.
        phase = "cleanup"
        with connection.transaction(force_rollback=True):
            with connection.cursor(row_factory=tuple_row) as cursor:
                cursor.execute("SET LOCAL statement_timeout = '1500ms'")
                record["cleanup"]["temporary_table_absent"] = not _table_exists(cursor)
        if not record["cleanup"]["temporary_table_absent"]:
            record["reason"] = "temporary_table_cleanup_failed"
            return record
        if connection.closed or connection.info.transaction_status != TransactionStatus.IDLE:
            record["reason"] = "cleanup_transaction_not_idle"
            return record
    except Exception as exc:
        record["reason"] = {
            "rollback": "rollback_failed",
            "cleanup": "cleanup_unavailable",
        }.get(phase, "execution_unavailable")
        record["diagnostic"] = _diagnostic(exc)
        return record

    required_cases = {"normal", "missing", "empty", "unicode", "quote", "backslash", "sql_payload",
                      "null_equality", "null_safe_equality"}
    controls = {stage["stage"]: next((case for case in stage["cases"] if case["case"] == "sql_payload"), {})
                for stage in record["stages"]}
    # A successful loop is insufficient: lost/skipped corpus cases, an attack
    # that never ran, or a mutant that survived cannot certify the recipe.
    passed = (fixture_created and set(controls) == {"before", "after", "mutation"}
              and all(stage["status"] == "passed" and len(stage["cases"]) == len(required_cases)
                      and {case["case"] for case in stage["cases"]} == required_cases
                      for stage in record["stages"])
              and controls["before"].get("exploit_observed") is True
              and controls["after"].get("reason") == "oracle_matched"
              and controls["mutation"].get("mutation_detected") is True)
    record.update(
        status="passed" if passed else "failed",
        reason="synthetic_contract_passed" if passed else "synthetic_contract_failed",
        synthetic_recipe_verified=passed,
    )
    return record
