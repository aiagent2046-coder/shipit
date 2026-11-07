"""DB connectors for authorized sessions (phase 3).

The posture - read-only statements, statement_timeout, contract scope,
audit log - lives in scout.active and is driver-independent. This module
ships the driver factories that posture runs on: the contract delivers a
DSN, this turns it into a DB-API connect callable. PostgreSQL (psycopg)
first; other dialects as contracts need them.

DSN discipline: a DSN is a credential. It comes from the operator's
environment (SCOUT_DB_DSN), never from a command line - argv lands in
shell history and process listings.
"""
from __future__ import annotations

from collections.abc import Callable

DSN_ENV = "SCOUT_DB_DSN"


class DriverUnavailable(RuntimeError):
    pass


def postgres_connect(dsn: str) -> Callable[[], object]:
    """DB-API connect factory for PostgreSQL. Lazy import, honest error."""
    try:
        import psycopg
    except ImportError as exc:
        raise DriverUnavailable(
            "PostgreSQL support needs psycopg; install it with: "
            "pip install -e '.[active]'") from exc

    def connect():
        return psycopg.connect(dsn)

    return connect
