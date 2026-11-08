"""Guard tests: the legal contour is enforced by code, not by discipline."""
from __future__ import annotations

import pytest

from scout import guard
from scout.active import ActiveScanSession, ReadOnlyQueryRunner, ReadOnlyViolation
from scout.guard import (
    ActiveModeUnauthorised,
    activate,
    enforce_passive_http,
    require_active,
    revoke,
)


@pytest.fixture(autouse=True)
def auth_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "AUTH_DIR", tmp_path / "authorizations")
    yield tmp_path


def test_passive_http_is_get_head_only() -> None:
    enforce_passive_http("GET")
    enforce_passive_http("head")
    with pytest.raises(ActiveModeUnauthorised):
        enforce_passive_http("POST")
    with pytest.raises(ActiveModeUnauthorised):
        enforce_passive_http("CONNECT")


def test_active_refused_without_record() -> None:
    with pytest.raises(ActiveModeUnauthorised):
        require_active("contract-404")


def test_activate_then_require() -> None:
    auth = activate("contract-1", ["db.example.com"], hours=1)
    loaded = require_active("contract-1")
    assert loaded.contract_id == auth.contract_id
    assert loaded.scope == ["db.example.com"]


def test_expired_record_refused() -> None:
    activate("contract-2", ["host"], hours=0)
    with pytest.raises(ActiveModeUnauthorised):
        require_active("contract-2")


def test_activation_requires_scope() -> None:
    with pytest.raises(ActiveModeUnauthorised):
        activate("contract-3", [])


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


def test_read_only_runner_rejects_writes() -> None:
    activate("contract-4", ["db"], hours=1)
    auth = require_active("contract-4")
    runner = ReadOnlyQueryRunner(auth=auth, connect=lambda: FakeConn([]))
    for bad in ["UPDATE t SET x=1", "DROP TABLE t", "SELECT 1; DROP TABLE t",
                "DELETE FROM t", "COPY t TO '/etc/passwd'"]:
        with pytest.raises(ReadOnlyViolation):
            runner.validate(bad)


def test_read_only_runner_queries_and_audits() -> None:
    activate("contract-5", ["db"], hours=1)
    auth = require_active("contract-5")
    conn = FakeConn([(1, "row")])
    runner = ReadOnlyQueryRunner(auth=auth, connect=lambda: conn)
    rows = runner.query("SELECT 1")
    assert rows == [(1, "row")]
    assert conn.closed
    assert len(runner.audit_log) == 1
    event = runner.audit_log[0]
    assert event.contract_id == "contract-5"
    assert event.rows_returned == 1
    assert len(event.statement_sha256) == 64


def test_session_scope_enforced() -> None:
    activate("contract-6", ["in-scope.example"], hours=1)
    session = ActiveScanSession.open("contract-6")
    session.check_scope("in-scope.example")
    with pytest.raises(ReadOnlyViolation):
        session.check_scope("not-in-scope.example")


def test_select_into_is_refused_like_a_write() -> None:
    # SELECT ... INTO creates a table - the dogfood-era filter let it through
    activate("contract-7", ["db"], hours=1)
    auth = require_active("contract-7")
    runner = ReadOnlyQueryRunner(auth=auth, connect=lambda: FakeConn([]))
    with pytest.raises(ReadOnlyViolation):
        runner.validate("SELECT * INTO newtable FROM oldtable")
    runner.validate("select 1")  # lowercase reads are fine
    runner.validate("   SELECT 1")  # leading whitespace is not a write
    with pytest.raises(ReadOnlyViolation):
        runner.validate("SELECT 1;\nDROP TABLE t")  # a newline hides nothing


def test_contract_ids_cannot_walk_the_filesystem(tmp_path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text('{"keep": true}')
    for bad in ("../../pwned", "../victim", "a/b", "..", "x y", "id.json/..", ""):
        with pytest.raises(ActiveModeUnauthorised, match="contract_id"):
            activate(bad, ["db"], hours=1)
        with pytest.raises(ActiveModeUnauthorised, match="contract_id"):
            require_active(bad)
        with pytest.raises(ActiveModeUnauthorised, match="contract_id"):
            revoke(bad)
    assert victim.is_file()
    assert not list((tmp_path / "authorizations").rglob("*.json"))


def test_revoke_removes_record_and_returns_status() -> None:
    activate("contract-rm", ["db"], hours=1)
    assert revoke("contract-rm") is True
    assert revoke("contract-rm") is False
    with pytest.raises(ActiveModeUnauthorised):
        require_active("contract-rm")


def test_contract_id_with_safe_punctuation_still_works() -> None:
    auth = activate("eng.2026-11_x", ["db"], hours=1)
    assert require_active("eng.2026-11_x").contract_id == "eng.2026-11_x"
    assert auth.contract_id == "eng.2026-11_x"
