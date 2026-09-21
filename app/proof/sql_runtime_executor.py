"""Bounded native execution of the bundled synthetic SQL contract.

The executor accepts no project source, SQL, schema or expectations. Its child
process runs one fixed script against an explicitly selected disposable target.
Only a validated compact summary crosses back into the scanner.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from app.proof import sql_runtime_contract as contract
from scripts.verify_sql_runtime_contract import TargetError, target_options, unavailable


CONTRACT_ID = contract.CONTRACT_ID
WALL_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 256 * 1024
_POLL_SECONDS = 0.05
_ROOT = Path(__file__).resolve().parents[2]
_WORKER = _ROOT / "scripts" / "verify_sql_runtime_contract.py"
_STAGES = ("before", "after", "mutation")
_CASES = ("normal", "missing", "empty", "unicode", "quote", "backslash", "sql_payload",
          "null_equality", "null_safe_equality")
_BASE_KEYS = {"version", "scope", "contract_id", "status", "reason", "synthetic_recipe_verified",
              "runtime_verified", "customer_project_verified", "automatic_patch"}
_FULL_KEYS = _BASE_KEYS | {"psycopg_version", "postgresql_version", "fixture_sha256", "schema_sha256",
                           "limits", "cleanup", "stages"}
_UNAVAILABLE_REASONS = {
    "database_not_configured", "invalid_database_target", "ambient_libpq_options", "execution_unavailable",
    "execution_timeout", "output_limit", "invalid_contract_result", "unsupported_runtime",
}
_HARNESS_UNAVAILABLE_REASONS = {
    "not_executed", "connection_not_idle", "temporary_table_conflict", "rollback_not_confirmed",
    "temporary_table_cleanup_failed", "cleanup_transaction_not_idle", "rollback_failed", "cleanup_unavailable",
}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _base_valid(value: object) -> bool:
    return (isinstance(value, dict) and _BASE_KEYS <= value.keys()
            and value.keys() <= _FULL_KEYS | {"diagnostic"}
            and type(value.get("version")) is int and value["version"] == 1
            and value.get("scope") == "synthetic_recipe" and value.get("contract_id") == CONTRACT_ID
            and value.get("runtime_verified") is False and value.get("customer_project_verified") is False
            and value.get("automatic_patch") is False)


def validate_contract_result(value: object) -> bool:
    """Accept only the complete successful matrix for the bundled contract.

Reconstruct every expected structural record from trusted fixture semantics,
including result/query hashes, column OIDs, NULL handling and restored mutant.
Canonical comparison distinguishes booleans from integers and rejects extras.
This validates consistency of a trusted worker result, not its authenticity as
an arbitrary user-supplied artifact or the behavior of a customer application.
"""
    if not _base_valid(value) or set(value) != _FULL_KEYS:
        return False
    if (value.get("status") != "passed" or value.get("reason") != "synthetic_contract_passed"
            or value.get("synthetic_recipe_verified") is not True
            or value.get("psycopg_version") != contract.psycopg.__version__
            or type(value.get("postgresql_version")) is not int
            or not 100000 <= value["postgresql_version"] <= 2**31 - 1
            or value.get("fixture_sha256") != contract._digest(contract._FIXTURES)
            or value.get("schema_sha256") != contract._digest(contract._SCHEMA)
            or tuple(case.name for case in contract._CASES) != _CASES):
        return False
    expected_stages = []
    for stage in _STAGES:
        cases = []
        for case in contract._CASES:
            query, _ = contract._query(case, stage)
            observation = {"query_sha256": contract._digest(query)}
            if stage != "after" and case.vulnerable_sqlstate:
                observation.update(outcome="database_error", diagnostic={
                    "type": "SyntaxError", "sqlstate": case.vulnerable_sqlstate,
                })
            else:
                rows = (list(contract._FIXTURES) if stage != "after" and case.attack
                        else contract._expected_rows(case))
                observation.update(outcome="rows", rows=rows, columns=list(contract._COLUMNS))
            cases.append(contract._evaluate_case(case, stage, observation))
        expected_stages.append({"stage": stage, "status": "passed", "cases": cases})
    expected = {"stages": expected_stages,
                "limits": {"max_rows": 32, "statement_timeout_ms": 1500, "lock_timeout_ms": 500},
                "cleanup": {"rollback_completed": True, "temporary_table_absent": True}}
    try:
        return _canonical({key: value[key] for key in expected}) == _canonical(expected)
    except (ValueError, TypeError, RecursionError):
        return False


def summarize_contract(value: object) -> dict:
    """Reduce the trusted worker result to a bounded, source-free summary."""
    valid = _base_valid(value)
    if valid and value.get("status") == "passed":
        valid = validate_contract_result(value)
    elif valid and value.get("status") == "failed":
        valid = (value.get("synthetic_recipe_verified") is False
                 and value.get("reason") == "synthetic_contract_failed")
    elif valid and value.get("status") == "unavailable":
        valid = (value.get("synthetic_recipe_verified") is False and isinstance(value.get("reason"), str)
                 and value["reason"] in _UNAVAILABLE_REASONS | _HARNESS_UNAVAILABLE_REASONS)
    else:
        valid = False
    try:
        encoded = _canonical(value).encode("utf-8")
        valid = valid and len(encoded) <= MAX_OUTPUT_BYTES
    except (ValueError, TypeError, RecursionError, UnicodeError):
        valid = False
    if not valid:
        value = unavailable("invalid_contract_result")
        encoded = _canonical(value).encode("utf-8")
    status = value["status"]
    reason = value["reason"]
    if status == "unavailable" and reason not in _UNAVAILABLE_REASONS:
        reason = "execution_unavailable"
    proof = None
    if status == "passed":
        proof = {key: value[key] for key in ("fixture_sha256", "schema_sha256", "psycopg_version",
                                           "postgresql_version")}
        proof.update(executions=27, cases_per_stage=9, before_row_ids=list(range(1, 10)), after_row_ids=[9],
                     mutation_row_ids=list(range(1, 10)), rollback_completed=True, temporary_table_absent=True)
    return {"version": 1, "scope": "synthetic_recipe", "contract_id": CONTRACT_ID, "contract_revision": 1,
            "status": status, "reason": reason, "evidence_sha256": hashlib.sha256(encoded).hexdigest(),
            "synthetic_recipe_verified": status == "passed", "runtime_verified": False,
            "customer_project_verified": False, "automatic_patch": False, "proof": proof}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite_json_value")


class SyntheticSqlExecutor:
    """One bounded attempt per invocation; the coordinator owns reuse policy."""

    def __init__(self, dsn: str | None = None):
        self._dsn = os.environ.get("SQL_CONTRACT_DATABASE_URL", "") if dsn is None else dsn

    def __call__(self) -> dict:
        try:
            # Validate the parent's environment before constructing a clean
            # child environment: PG* overrides must be rejected, not hidden.
            target_options(self._dsn)
        except TargetError as exc:
            reason = str(exc)
            return summarize_contract(unavailable(reason if reason in _UNAVAILABLE_REASONS
                                                   else "invalid_database_target"))
        if sys.platform in {"emscripten", "wasi"} or not _WORKER.is_file():
            return summarize_contract(unavailable("unsupported_runtime"))
        child_env = {name: os.environ[name] for name in (
            "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
        ) if name in os.environ}
        child_env["SQL_CONTRACT_DATABASE_URL"] = self._dsn
        process = None
        try:
            with tempfile.TemporaryFile(mode="w+b") as output:
                started = time.monotonic()
                process = subprocess.Popen(
                    [sys.executable, "-I", str(_WORKER)], cwd=str(_ROOT), env=child_env,
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, close_fds=True,
                )
                while True:
                    if os.fstat(output.fileno()).st_size > MAX_OUTPUT_BYTES:
                        process.kill()
                        process.wait()
                        return summarize_contract(unavailable("output_limit"))
                    remaining = WALL_TIMEOUT_SECONDS - (time.monotonic() - started)
                    if remaining <= 0:
                        process.kill()
                        process.wait()
                        return summarize_contract(unavailable("execution_timeout"))
                    try:
                        returncode = process.wait(timeout=min(_POLL_SECONDS, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                output.seek(0)
                data = output.read(MAX_OUTPUT_BYTES + 1)
                if len(data) > MAX_OUTPUT_BYTES:
                    return summarize_contract(unavailable("output_limit"))
                raw = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
                if (not isinstance(raw, dict)
                        or returncode != {"passed": 0, "failed": 1, "unavailable": 2}.get(raw.get("status"))):
                    return summarize_contract(unavailable("invalid_contract_result"))
                return summarize_contract(raw)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            return summarize_contract(unavailable("invalid_contract_result"))
        except Exception:
            # OS/driver error strings can contain target credentials.
            return summarize_contract(unavailable("execution_unavailable"))
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()


def executor_from_environment() -> SyntheticSqlExecutor | None:
    if os.environ.get("SHIPIT_SQL_CONTRACT_AGENT_ENABLED") != "1":
        return None
    return SyntheticSqlExecutor()
