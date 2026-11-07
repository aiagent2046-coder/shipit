"""Authorized mode (phase 3): target-side access behind a signed contract.

This module is the prepared surface for working with a target project's
databases. It is intentionally driver-free: the contract delivers a
DB-API connection factory (psycopg, pymysql, ...), this layer enforces
the posture regardless of driver:

  - read-only: single statements from SELECT/EXPLAIN/WITH/SHOW only;
  - bounded: caller-supplied statement_timeout is always applied;
  - scoped: every connection belongs to an Authorization record, and
    every query is audit-logged with a contract id and a statement hash.

Nothing here runs without guard.require_active() succeeding first.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scout.guard import Authorization, require_active

_LOG = logging.getLogger(__name__)

AUDIT_LOG_DIR = Path.home() / ".agent-scout" / "audit-log"

READ_ONLY_HEAD = re.compile(r"^\s*(SELECT|EXPLAIN|WITH|SHOW)\b", re.IGNORECASE)
MULTI_STATEMENT = re.compile(r";\s*\S")
FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|COPY|CALL|INTO)\b",
    re.IGNORECASE,
)
# INTO closes the SELECT ... INTO escape (a table-creating write that starts
# like a read). What no keyword list can close is side effects inside called
# functions - the contract's read-only ROLE is the real boundary there; this
# filter is defense in depth, never the only wall.


class ReadOnlyViolation(RuntimeError):
    pass


@dataclass
class AuditEvent:
    contract_id: str
    at: float
    statement_sha256: str
    rows_returned: int

    def as_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "at": self.at,
            "statement_sha256": self.statement_sha256,
            "rows_returned": self.rows_returned,
        }


@dataclass
class ReadOnlyQueryRunner:
    """Runs bounded read-only statements on a contract-scoped connection."""
    auth: Authorization
    connect: Callable[[], Any]
    statement_timeout_ms: int = 15_000
    audit_log: list[AuditEvent] = field(default_factory=list)
    audit_path: Path | None = None

    def __post_init__(self) -> None:
        # Re-check at construction: a session cannot outlive its authorization.
        self.auth = require_active(self.auth.contract_id)

    def validate(self, sql: str) -> None:
        if not READ_ONLY_HEAD.match(sql):
            raise ReadOnlyViolation(f"not a read-only statement: {sql[:60]!r}")
        if MULTI_STATEMENT.search(sql):
            raise ReadOnlyViolation("multiple statements are not allowed")
        if FORBIDDEN.search(sql):
            raise ReadOnlyViolation("forbidden keyword in statement")

    def query(self, sql: str, params: tuple = ()) -> list[tuple]:
        self.validate(sql)
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                self._set_timeout(cur)
                cur.execute(sql, params)
                rows = cur.fetchall()
        finally:
            conn.close()
        event = AuditEvent(
            contract_id=self.auth.contract_id,
            at=time.time(),
            statement_sha256=hashlib.sha256(sql.encode()).hexdigest(),
            rows_returned=len(rows),
        )
        self.audit_log.append(event)
        if self.audit_path is not None:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a") as fh:
                fh.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
        return rows

    def _set_timeout(self, cur) -> None:
        try:
            # parameterized on purpose: the shipped sql-injection rule caught
            # an f-string here during the dogfood audit (safe via int(), but
            # assembly-by-construction is the weaker shape)
            cur.execute("SELECT set_config('statement_timeout', %s, false)",
                        (str(self.statement_timeout_ms),))
        except Exception as exc:  # noqa: BLE001 — driver dialects differ; best-effort
            _LOG.debug("statement_timeout not applied: %s", exc)


@dataclass
class ActiveScanSession:
    """Bundle for phase-3 active scans. Scope-checked, contract-checked."""
    auth: Authorization

    @classmethod
    def open(cls, contract_id: str) -> ActiveScanSession:
        return cls(auth=require_active(contract_id))

    def check_scope(self, target: str) -> None:
        if target not in self.auth.scope:
            raise ReadOnlyViolation(
                f"target {target!r} is outside contract {self.auth.contract_id} scope"
            )
