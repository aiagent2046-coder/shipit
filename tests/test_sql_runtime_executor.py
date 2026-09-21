"""Native executor boundaries and rejection of corrupted synthetic evidence."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from app.proof import sql_runtime_contract as contract
from app.proof import sql_runtime_executor as executor


DSN = "postgresql://postgres:synthetic@localhost:5432/drydock_sql_contract"  # scan-allow: fake test DSN


@pytest.fixture(autouse=True)
def clean_libpq_environment(monkeypatch):
    for name in os.environ:
        if name.startswith("PG"):
            monkeypatch.delenv(name)


class _Connection:
    closed = False
    info = SimpleNamespace(transaction_status=TransactionStatus.IDLE, server_version=170011)

    @contextmanager
    def transaction(self, *, force_rollback):
        assert force_rollback is True
        yield

    @contextmanager
    def cursor(self, **kwargs):
        yield self

    def execute(self, query):
        pass

    def executemany(self, query, values):
        pass

    def fetchone(self):
        return (None,)


@pytest.fixture
def good_result(monkeypatch):
    expected_ids = {"normal": [1, 8], "missing": [], "empty": [3], "unicode": [4], "quote": [5],
                    "backslash": [6], "sql_payload": [9], "null_equality": [], "null_safe_equality": [7]}

    def fixed_observation(connection, case, stage):
        query, _ = contract._query(case, stage)
        observed = {"query_sha256": contract._digest(query)}
        if stage != "after" and case.name == "quote":
            return {**observed, "outcome": "database_error",
                    "diagnostic": {"type": "SyntaxError", "sqlstate": "42601"}}
        ids = list(range(1, 10)) if stage != "after" and case.name == "sql_payload" else expected_ids[case.name]
        return {**observed, "outcome": "rows", "rows": [row for row in contract._FIXTURES if row[0] in ids],
                "columns": [("id", 23), ("name", 25)]}

    monkeypatch.setattr(contract, "_execute_case", fixed_observation)
    return json.loads(json.dumps(contract.run_contract(_Connection())))


def test_all_27_cases_and_control_provenance_are_reduced_to_compact_summary(good_result):
    assert executor.validate_contract_result(good_result)
    result = executor.summarize_contract(good_result)
    encoded = json.dumps(good_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert result["evidence_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert result["status"] == "passed"
    assert result["synthetic_recipe_verified"] is True
    assert result["runtime_verified"] is result["customer_project_verified"] is result["automatic_patch"] is False
    proof = result["proof"]
    assert proof["executions"] == 27 and proof["cases_per_stage"] == 9
    assert proof["before_row_ids"] == proof["mutation_row_ids"] == list(range(1, 10))
    assert proof["after_row_ids"] == [9]
    assert proof["rollback_completed"] is proof["temporary_table_absent"] is True
    assert "stages" not in result and "query_sha256" not in json.dumps(result)


@pytest.mark.parametrize("change", [
    lambda r: r.update(runtime_verified=True),
    lambda r: r.update(customer_project_verified=True),
    lambda r: r.update(automatic_patch=True),
    lambda r: r.update(version=True),
    lambda r: r.update(synthetic_recipe_verified=1),
    lambda r: r.update(postgresql_version=True),
    lambda r: r.update(psycopg_version="2.9.0"),
    lambda r: r.update(fixture_sha256="0" * 64),
    lambda r: r.update(schema_sha256="0" * 64),
    lambda r: r["cleanup"].update(rollback_completed=1),
    lambda r: r["cleanup"].update(temporary_table_absent=False),
    lambda r: r["limits"].update(statement_timeout_ms=60000),
    lambda r: r["stages"].clear(),
    lambda r: r["stages"].pop(),
    lambda r: r["stages"].append(deepcopy(r["stages"][0])),
    lambda r: r["stages"][0]["cases"].pop(),
    lambda r: r["stages"][0]["cases"].__setitem__(6, deepcopy(r["stages"][0]["cases"][0])),
    lambda r: r["stages"][1]["cases"][6].update(row_ids=list(range(1, 10))),
    lambda r: r["stages"][2]["cases"][6].update(mutation_detected=False),
    lambda r: r["stages"][0]["cases"][6].update(exploit_observed=False),
    lambda r: r["stages"][0]["cases"][0].update(query_sha256="0" * 64),
    lambda r: r["stages"][1]["cases"][0].update(rows_sha256="0" * 64),
    lambda r: r["stages"][1]["cases"][0]["columns"][0].update(type_oid=20),
    lambda r: r["stages"][1]["cases"][7].update(row_ids=[7], row_count=1),
    lambda r: r["stages"][0]["cases"][4]["diagnostic"].update(sqlstate="57014"),
    lambda r: r.update(untrusted_field="SECRET"),
])
def test_forged_or_incomplete_success_never_establishes_evidence(good_result, change):
    change(good_result)
    assert not executor.validate_contract_result(good_result)
    result = executor.summarize_contract(good_result)
    assert result["status"] == "unavailable" and result["reason"] == "invalid_contract_result"
    assert result["synthetic_recipe_verified"] is False and result["proof"] is None
    assert "SECRET" not in json.dumps(result)


def test_failure_and_cleanup_errors_never_become_passed(good_result):
    failed = deepcopy(good_result)
    failed.update(status="failed", reason="synthetic_contract_failed", synthetic_recipe_verified=False)
    assert executor.summarize_contract(failed)["status"] == "failed"
    assert not executor.validate_contract_result(failed)
    failed.update(status="unavailable", reason="rollback_failed", diagnostic={"type": "Error"})
    result = executor.summarize_contract(failed)
    assert result["reason"] == "execution_unavailable" and result["proof"] is None


@pytest.mark.parametrize("enabled", [None, "", "0", "true", "yes"])
def test_factory_is_opt_in_and_does_not_read_project_configuration(monkeypatch, enabled):
    monkeypatch.delenv("SHIPIT_SQL_CONTRACT_AGENT_ENABLED", raising=False)
    if enabled is not None:
        monkeypatch.setenv("SHIPIT_SQL_CONTRACT_AGENT_ENABLED", enabled)
    monkeypatch.setenv("SQL_CONTRACT_DATABASE_URL", DSN)
    assert executor.executor_from_environment() is None


def test_enabled_missing_dedicated_target_does_not_fall_back_or_spawn(monkeypatch):
    monkeypatch.setenv("SHIPIT_SQL_CONTRACT_AGENT_ENABLED", "1")
    monkeypatch.delenv("SQL_CONTRACT_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", DSN)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *a, **kw: pytest.fail("must not spawn"))
    run = executor.executor_from_environment()
    assert isinstance(run, executor.SyntheticSqlExecutor)
    assert run()["reason"] == "database_not_configured"


@pytest.mark.parametrize("mode", ["remote", "wrong_database", "PGHOSTADDR", "PGSERVICE", "PGOPTIONS"])
def test_invalid_target_or_ambient_override_is_rejected_before_process_creation(monkeypatch, mode):
    dsn = DSN
    if mode == "remote":
        dsn = dsn.replace("localhost", "production.example")
    elif mode == "wrong_database":
        dsn = dsn.replace("drydock_sql_contract", "production")
    else:
        monkeypatch.setenv(mode, "SECRET")
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *a, **kw: pytest.fail("must not spawn"))
    result = executor.SyntheticSqlExecutor(dsn)()
    assert result["reason"] == ("ambient_libpq_options" if mode.startswith("PG") else "invalid_database_target")
    assert "SECRET" not in json.dumps(result) and "postgresql://" not in json.dumps(result)


def _child(monkeypatch, source, *, inspect=None):
    """Substitute only the child program; exercise real process I/O and cleanup."""
    popen = subprocess.Popen
    children = []

    def spawn(argv, **kwargs):
        if inspect is not None:
            inspect(argv, kwargs)
        process = popen([sys.executable, "-I", "-c", source], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(executor.subprocess, "Popen", spawn)
    return children


def test_fixed_worker_and_clean_environment_do_not_receive_unrelated_secrets(monkeypatch, good_result):
    for key in ("PYTHONPATH", "PYTHONHOME", "DATABASE_URL", "AITUNNEL_API_KEY", "LD_PRELOAD", "PGPASSWORD_FILE"):
        # PG* variables are separately rejected; do not set one in this success case.
        if not key.startswith("PG"):
            monkeypatch.setenv(key, "SECRET")
    monkeypatch.setenv("SQL_CONTRACT_DATABASE_URL", DSN)
    seen = []

    def inspect(argv, kwargs):
        seen.append(argv)
        assert argv == [sys.executable, "-I", str(executor._WORKER)]
        assert kwargs["cwd"] == str(executor._ROOT)
        assert kwargs["env"]["SQL_CONTRACT_DATABASE_URL"] == DSN
        assert set(kwargs["env"]) <= {"SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
                                      "SQL_CONTRACT_DATABASE_URL"}
        assert kwargs["stdin"] == kwargs["stderr"] == subprocess.DEVNULL
        assert "shell" not in kwargs and kwargs["close_fds"] is True

    _child(monkeypatch, "print(" + repr(json.dumps(good_result)) + ")", inspect=inspect)
    result = executor.SyntheticSqlExecutor()()
    assert result["status"] == "passed" and len(seen) == 1
    assert "SECRET" not in json.dumps(result) and DSN not in json.dumps(result)


def test_wall_timeout_kills_and_reaps_worker_without_retry(monkeypatch):
    monkeypatch.setattr(executor, "WALL_TIMEOUT_SECONDS", 0.05)
    children = _child(monkeypatch, "import time; time.sleep(10)")
    result = executor.SyntheticSqlExecutor(DSN)()
    assert result["reason"] == "execution_timeout"
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize("keep_running", [False, True])
def test_output_limit_discards_partial_data_and_reaps_worker(monkeypatch, keep_running):
    source = "import sys,time; sys.stdout.write('x' * 300000); sys.stdout.flush()"
    if keep_running:
        source += "; time.sleep(10)"
    children = _child(monkeypatch, source)
    result = executor.SyntheticSqlExecutor(DSN)()
    assert result["reason"] == "output_limit"
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize("payload,exitcode", [
    ('{"status":"passed"}', 0),
    ('{"status":"unavailable","status":"passed"}', 0),
    ('{"status":"unavailable","field":NaN}', 2),
    ("SECRET driver exception", 1),
])
def test_malformed_worker_protocol_does_not_leak_or_certify(monkeypatch, payload, exitcode):
    _child(monkeypatch, f"import sys; print({payload!r}); sys.exit({exitcode})")
    result = executor.SyntheticSqlExecutor(DSN)()
    assert result["reason"] == "invalid_contract_result" and result["proof"] is None
    assert "SECRET" not in json.dumps(result)


def test_nonzero_exit_cannot_certify_a_passed_json(monkeypatch, good_result):
    _child(monkeypatch, "import sys; print(" + repr(json.dumps(good_result)) + "); sys.exit(1)")
    assert executor.SyntheticSqlExecutor(DSN)()["reason"] == "invalid_contract_result"


def test_os_errors_and_stderr_never_expose_credentials(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("SECRET " + DSN)

    monkeypatch.setattr(executor.subprocess, "Popen", fail)
    result = executor.SyntheticSqlExecutor(DSN)()
    assert result["reason"] == "execution_unavailable"
    assert "SECRET" not in json.dumps(result) and DSN not in json.dumps(result)
