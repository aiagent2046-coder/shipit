"""DB connector tests: factory, driver honesty, durable audit log."""
from __future__ import annotations

import json
import sys
import types

import pytest

from scout import active, db, guard


@pytest.fixture
def auth_dir(tmp_path, monkeypatch):
    path = tmp_path / "authorizations"
    monkeypatch.setattr(guard, "AUTH_DIR", path)
    return path


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append(sql)

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, rows):
        self.cursor_obj = FakeCursor(rows)
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


def test_postgres_connect_factory_calls_psycopg(monkeypatch):
    made = []
    fake = types.ModuleType("psycopg")

    def fake_connect(dsn):
        made.append(dsn)
        return FakeConn([])
    fake.connect = fake_connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    connect = db.postgres_connect("postgresql://host/db")
    conn = connect()
    assert made == ["postgresql://host/db"] and isinstance(conn, FakeConn)


def test_postgres_connect_missing_driver_is_honest(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)  # import halted
    with pytest.raises(db.DriverUnavailable, match=r"pip install -e '\.\[active\]'"):
        db.postgres_connect("postgresql://host/db")


def test_runner_persists_audit_events(auth_dir, tmp_path):
    guard.activate("c-9", scope=["db"], hours=1)
    auth = guard.require_active("c-9")
    audit_path = tmp_path / "audit" / "c-9.jsonl"
    conn = FakeConn([(1, "row")])
    runner = active.ReadOnlyQueryRunner(auth=auth, connect=lambda: conn,
                                        audit_path=audit_path)
    runner.query("SELECT 1")
    lines = audit_path.read_text().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["contract_id"] == "c-9"
    assert event["rows_returned"] == 1
    assert len(event["statement_sha256"]) == 64
    assert runner.audit_log  # the in-memory log still works


def test_runner_without_audit_path_writes_nothing(auth_dir, tmp_path):
    guard.activate("c-10", scope=["db"], hours=1)
    auth = guard.require_active("c-10")
    runner = active.ReadOnlyQueryRunner(auth=auth,
                                        connect=lambda: FakeConn([]))
    runner.query("SELECT 1")
    assert not list(tmp_path.rglob("*.jsonl"))  # no audit file without a path


def test_statement_timeout_is_parameterized(auth_dir):
    # the shipped sql-injection rule caught an f-string here in the dogfood
    # audit; the timeout value must travel as a bound parameter
    guard.activate("c-11", scope=["db"], hours=1)
    auth = guard.require_active("c-11")

    class RecordingCursor(FakeCursor):
        def execute(self, sql, params=None):
            self.executed.append((sql, params))

    class RecordingConn(FakeConn):
        def cursor(self):
            self.rec = RecordingCursor(self.cursor_obj.rows)
            return self.rec

    conn = RecordingConn([(1,)])
    active.ReadOnlyQueryRunner(auth=auth, connect=lambda: conn).query("SELECT 1")
    timeout_sql, timeout_params = conn.rec.executed[0]
    assert "set_config" in timeout_sql and "%s" in timeout_sql
    assert "15000" not in timeout_sql  # the value is not assembled into the text
    assert timeout_params == ("15000",)
