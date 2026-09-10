from copy import deepcopy
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from scripts import requeue_blocked_fixpack as recovery

REQUEST = recovery.RecoveryRequest(
    expected_release="a" * 40,
    job_id="11111111-1111-4111-8111-111111111111",
    audit_id="22222222-2222-4222-8222-222222222222",
    payment_id="33333333-3333-4333-8333-333333333333",
)


def cli_args():
    return ["--expected-release", REQUEST.expected_release,
            "--job-id", REQUEST.job_id, "--audit-id", REQUEST.audit_id,
            "--payment-id", REQUEST.payment_id]


@pytest.fixture
def root_archive_owner(monkeypatch):
    """Model root ownership while exercising real modes, files and fsync in CI."""
    lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(
        st_mode=lstat(path).st_mode, st_uid=0))


@pytest.fixture
def snapshot():
    proof = {"template_id": "secrets_leak", "verified": False,
             "informational": False,
             "before": {"status": "success", "success": True},
             "after": {"status": "success", "success": True}}
    job = {"id": REQUEST.job_id, "audit_id": REQUEST.audit_id, "pack": "fixpack",
           "status": "blocked", "attempts": 1, "pr_url": None, "pr_delivered": False,
           "proof_json": proof, "detail": "proof gate (hard): exploit still succeeds",
           "started_at": "2026-01-01T00:00:00+00:00", "funding_key": "preserve-me"}
    payment = {"id": REQUEST.payment_id, "audit_id": REQUEST.audit_id,
               "fixpack_job_id": REQUEST.job_id, "product": "fixpack",
               "status": "completed", "refunded_at": None}
    return job, payment


@pytest.mark.parametrize("target,key,value", [
    ("job", "id", "wrong"), ("job", "audit_id", "wrong"),
    ("job", "pack", "preview"), ("job", "status", "failed"),
    ("job", "attempts", 2), ("job", "pr_url", "https://github.com/x/y/pull/1"),
    ("job", "pr_delivered", True), ("job", "detail", "semantic regression"),
    ("job", "proof_json", None), ("payment", "id", "wrong"),
    ("payment", "audit_id", "wrong"), ("payment", "fixpack_job_id", "wrong"),
    ("payment", "product", "subscription"), ("payment", "status", "pending"),
    ("payment", "refunded_at", "2026-09-10T09:00:00Z"),
])
def test_changed_order_is_refused(snapshot, target, key, value):
    job, payment = snapshot
    (job if target == "job" else payment)[key] = value
    with pytest.raises(recovery.RecoveryRefused):
        recovery.validate_snapshot(job, payment, False, REQUEST)


@pytest.mark.parametrize("key,value", [("template_id", "rls"), ("verified", True),
                                      ("informational", True), ("after", {}),
                                      ("before", {"status": "error", "success": False})])
def test_different_failure_is_refused(snapshot, key, value):
    job, payment = snapshot
    job["proof_json"][key] = value
    with pytest.raises(recovery.RecoveryRefused):
        recovery.validate_snapshot(job, payment, False, REQUEST)


def test_any_live_pack_blocks_recovery(snapshot):
    with pytest.raises(recovery.RecoveryRefused):
        recovery.validate_snapshot(*snapshot, True, REQUEST)


class Connection:
    def __init__(self, snapshot, *, busy=False, changed_rows=1):
        self.job, self.payment = deepcopy(snapshot)
        self.queries = []
        self.busy = busy
        self.changed_rows = changed_rows
        self.archived = False

    def execute(self, sql, params=None):
        self.queries.append((sql, params))
        if "pg_try_advisory" in sql:
            row = {"acquired": not self.busy}
        elif "FROM payments" in sql:
            row = self.payment
        elif "SELECT EXISTS" in sql:
            # The live-job check must cover all packs, matching the DB index.
            assert "pack =" not in sql
            row = {"found": False}
        elif "FROM fixpack_jobs WHERE id" in sql:
            row = self.job
        else:
            row = None
        if sql.startswith("UPDATE"):
            assert self.archived, "Evidence must be durable before the state change."
            assert "UPDATE fixpack_jobs SET status = 'paid', started_at = NULL, " in sql
            assert "detail = NULL, proof_json = NULL " in sql
            assert "attempts = %s" in sql.split("WHERE")[1]
            assert params == (REQUEST.job_id, REQUEST.expected_attempts)
            assert "attempts" not in sql.split("WHERE")[0]
            assert "funding_key" not in sql
        return type("Cursor", (), {"fetchone": lambda _: row,
                                   "rowcount": self.changed_rows})()


def test_default_is_read_only_and_never_archives(snapshot, monkeypatch):
    conn = Connection(snapshot)
    monkeypatch.setattr(recovery, "archive_failure", lambda *_: pytest.fail("archive"))
    result = recovery.recover(conn, REQUEST, apply=False)
    assert result["state"] == "eligible" and result["changed"] is False
    assert conn.queries[0][0] == "SET TRANSACTION READ ONLY"
    assert not any("UPDATE" in sql or "advisory" in sql for sql, _ in conn.queries)


@pytest.mark.parametrize("status", ["paid", "running", "delivered"])
def test_second_invocation_does_not_requeue_or_archive(snapshot, status, monkeypatch):
    snapshot[0]["status"] = status
    conn = Connection(snapshot)
    monkeypatch.setattr(recovery, "archive_failure", lambda *_: pytest.fail("archive"))
    result = recovery.recover(conn, REQUEST, apply=True)
    assert result["changed"] is False
    assert not any(sql.startswith("UPDATE") for sql, _ in conn.queries)


def test_processor_busy_refuses_before_order_changes(snapshot):
    conn = Connection(snapshot, busy=True)
    with pytest.raises(recovery.RecoveryRefused):
        recovery.recover(conn, REQUEST, apply=True)
    assert not any("FROM payments" in sql or "FROM fixpack_jobs" in sql
                   for sql, _ in conn.queries)


@pytest.mark.parametrize("rows", [0, 2])
def test_unexpected_update_count_raises_for_transaction_rollback(snapshot, monkeypatch, rows):
    conn = Connection(snapshot, changed_rows=rows)
    def archive(*_):
        conn.archived = True
        return Path("/protected/evidence.json")
    monkeypatch.setattr(recovery, "archive_failure", archive)
    with pytest.raises(recovery.RecoveryRefused):
        recovery.recover(conn, REQUEST, apply=True)


def test_apply_preserves_payment_attempts_and_archives_before_update(snapshot, monkeypatch):
    conn = Connection(snapshot)
    def archive(job, payment, request):
        assert request == REQUEST
        assert (job, payment) == snapshot
        conn.archived = True
        return Path("/protected/evidence.json")
    monkeypatch.setattr(recovery, "archive_failure", archive)
    result = recovery.recover(conn, REQUEST, apply=True)
    assert result["changed"] is True and result["attempts"] == 1
    updates = [sql for sql, _ in conn.queries if sql.startswith("UPDATE")]
    assert len(updates) == 1 and updates[0].startswith("UPDATE fixpack_jobs")
    assert conn.job == snapshot[0] and conn.payment == snapshot[1]


def test_evidence_file_is_private_and_complete(snapshot, monkeypatch, tmp_path, root_archive_owner):
    directory = tmp_path / "archive"
    monkeypatch.setattr(recovery, "ARCHIVE_DIR", directory)
    path = recovery.archive_failure(*snapshot, REQUEST)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    saved = json.loads(path.read_text())
    assert saved["job"] == snapshot[0] and saved["payment"] == snapshot[1]


def test_insecure_existing_archive_directory_is_refused(snapshot, monkeypatch, tmp_path):
    directory = tmp_path / "archive"
    directory.mkdir(mode=0o755)
    monkeypatch.setattr(recovery, "ARCHIVE_DIR", directory)
    with pytest.raises(recovery.RecoveryRefused):
        recovery.archive_failure(*snapshot, REQUEST)


def test_wrong_live_release_prevents_database_access(monkeypatch, tmp_path):
    wrong = tmp_path / REQUEST.expected_release
    wrong.mkdir()
    monkeypatch.setattr(recovery, "CURRENT", wrong)
    monkeypatch.setattr(recovery, "get_json", lambda _: {"release": "old"})
    with pytest.raises(recovery.RecoveryRefused, match="API has not activated"):
        recovery.check_runtime(REQUEST)


@pytest.mark.parametrize("field,value", [
    ("--expected-release", "main"), ("--expected-release", "a" * 39),
    ("--job-id", "invalid"), ("--audit-id", "invalid"),
    ("--payment-id", "invalid"), ("--expected-attempts", "0"),
    ("--expected-attempts", "-1"), ("--expected-attempts", "1.5"),
])
def test_invalid_cli_request_is_rejected_before_runtime_access(field, value):
    args = cli_args()
    if field in args:
        args[args.index(field) + 1] = value
    else:
        args += [field, value]
    with pytest.raises(SystemExit) as error:
        recovery.parse_args(args)
    assert error.value.code == 2


def test_cli_requires_explicit_order_and_revision_and_defaults_to_read_only():
    with pytest.raises(SystemExit):
        recovery.parse_args([])
    args = recovery.parse_args(cli_args())
    assert args.apply is False and args.expected_attempts == 1
    args = recovery.parse_args(cli_args() + ["--apply", "--expected-attempts", "2"])
    assert args.apply is True and args.expected_attempts == 2


@pytest.mark.parametrize("mode", [b"soft", b"off", b"disabled"])
def test_running_proof_gate_cannot_be_relaxed(monkeypatch, tmp_path, mode):
    current = tmp_path / REQUEST.expected_release
    current.mkdir()
    monkeypatch.setattr(recovery, "CURRENT", current)
    monkeypatch.setattr(recovery, "get_json", lambda url: (
        {"release": REQUEST.expected_release, "environment": "production"}
        if url.endswith("/version") else {"status": "ready", "db": True}))
    monkeypatch.setattr(recovery.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout="123"))
    monkeypatch.setattr(Path, "read_bytes", lambda _: b"PROOF_GATE_MODE=" + mode + b"\0")
    with pytest.raises(recovery.RecoveryRefused, match="must be hard"):
        recovery.check_runtime(REQUEST)


def test_public_runtime_must_match_local_runtime(monkeypatch, tmp_path):
    current = tmp_path / REQUEST.expected_release
    current.mkdir()
    monkeypatch.setattr(recovery, "CURRENT", current)
    def health(url):
        if url.endswith("/readyz"):
            return {"status": "ready", "db": True}
        return {"release": REQUEST.expected_release if "127.0.0.1" in url else "old",
                "environment": "production"}
    monkeypatch.setattr(recovery, "get_json", health)
    with pytest.raises(recovery.RecoveryRefused, match="API has not activated"):
        recovery.check_runtime(REQUEST)


def test_archive_failure_stops_the_update(snapshot, monkeypatch):
    conn = Connection(snapshot)
    def no_space(*_):
        raise OSError("disk full")
    monkeypatch.setattr(recovery, "archive_failure", no_space)
    with pytest.raises(OSError):
        recovery.recover(conn, REQUEST, apply=True)
    assert not any(sql.startswith("UPDATE") for sql, _ in conn.queries)


def test_non_root_archive_directory_is_refused(snapshot, monkeypatch, tmp_path):
    directory = tmp_path / "archive"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(recovery, "ARCHIVE_DIR", directory)
    monkeypatch.setattr(Path, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000))
    with pytest.raises(recovery.RecoveryRefused, match="root-owned"):
        recovery.archive_failure(*snapshot, REQUEST)


@pytest.fixture
def main_runtime(monkeypatch, tmp_path):
    """Exercise the CLI transaction with a simulated production host."""
    import psycopg
    from scripts import env_file

    current = tmp_path / REQUEST.expected_release
    current.mkdir()
    monkeypatch.setattr(recovery, "CURRENT", current)
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery.sys, "path", list(recovery.sys.path))
    monkeypatch.setattr(recovery, "open", lambda *a, **kw: (tmp_path / "deploy.lock").open("a"), raising=False)
    monkeypatch.setattr(recovery, "check_runtime", lambda request: None)
    monkeypatch.setattr(env_file, "read_values", lambda _: {"DATABASE_URL": "private-connection-value"})
    return psycopg


@pytest.mark.parametrize("commit_fails", [False, True])
def test_cli_reports_changed_only_after_commit(snapshot, monkeypatch, capsys, main_runtime, commit_fails):
    conn = Connection(snapshot)
    events = []

    class Transaction:
        def __enter__(self):
            return conn

        def __exit__(self, exc_type, exc, traceback):
            assert not capsys.readouterr().out, "A changed result must not precede the commit."
            assert exc_type is None
            events.append("commit")
            if commit_fails:
                raise RuntimeError("private-connection-value")

    def connect(dsn, **kwargs):
        assert dsn == "private-connection-value"
        assert kwargs["prepare_threshold"] is None
        assert kwargs["connect_timeout"] == 10
        return Transaction()

    def archive(*_):
        conn.archived = True
        return Path("/protected/evidence.json")

    monkeypatch.setattr(main_runtime, "connect", connect)
    monkeypatch.setattr(recovery, "archive_failure", archive)
    code = recovery.main(cli_args() + ["--apply"])
    output = capsys.readouterr()
    assert events == ["commit"]
    if commit_fails:
        assert code == 1 and output.out == ""
        assert "RuntimeError" in output.err and "private-connection-value" not in output.err
    else:
        assert code == 0 and json.loads(output.out)["changed"] is True


def test_deployment_lock_blocks_before_runtime_and_database(monkeypatch, capsys, main_runtime):
    def busy(*_):
        raise BlockingIOError("busy")

    monkeypatch.setattr(recovery.fcntl, "flock", busy)
    monkeypatch.setattr(recovery, "check_runtime", lambda *_: pytest.fail("runtime read during deployment"))
    monkeypatch.setattr(main_runtime, "connect", lambda *a, **kw: pytest.fail("database during deployment"))
    assert recovery.main(cli_args() + ["--apply"]) == 1
    assert not capsys.readouterr().out
