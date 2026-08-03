"""Payload staging: the bytes an audit job needs after its request is gone.

No database and no worker here -- this is the filesystem contract on its own,
so it runs in the default suite rather than behind DATABASE_URL.
"""

from __future__ import annotations

import os
import stat
import uuid

import pytest

import app.audit_spool as spool


@pytest.fixture
def spool_dir(tmp_path, monkeypatch):
    """Point the module at a tmp_path spool.

    SPOOL_DIR is read at import time into a module global, so the env var alone
    would not move it -- patch the resolved value, which is also what makes
    these tests safe to run on a host that really has /srv/shipit/spool."""
    monkeypatch.setattr(spool, "SPOOL_DIR", tmp_path / "spool")
    return tmp_path / "spool"


def test_stage_read_round_trip(spool_dir):
    job_id = str(uuid.uuid4())
    raw = b"PK\x03\x04 pretend this is a zip"

    path = spool.stage_archive(job_id, raw)

    assert spool.read_staged_archive(path) == raw
    assert path.endswith(f"{job_id}.zip")


def test_staged_archive_is_readable_by_the_workers_group_and_nobody_else(
        spool_dir):
    """The regression this file previously enshrined as correct.

    It used to assert 0600, which is right only if the writer and the reader
    are the same user. They are not: shipit.service has no User= and stages as
    root, while shipit-audit-worker.service runs as shipit-ops, so every zip
    audit on production died with EACCES in read_staged_archive. 0640 plus the
    setgid directory below is what gives those two identities -- and only those
    two -- access."""
    path = spool.stage_archive(str(uuid.uuid4()), b"secret source")

    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o640
    # Others get nothing: this is still a user's private source code.
    assert not mode & 0o007


def test_the_spool_directory_is_setgid_so_files_inherit_its_group(spool_dir):
    # Without the setgid bit the group-read bit above buys nothing on
    # production: a root-staged file would land root:root and shipit-ops would
    # still be locked out.
    spool.stage_archive(str(uuid.uuid4()), b"zip bytes")

    mode = os.stat(spool_dir).st_mode
    assert mode & stat.S_ISGID
    assert stat.S_IMODE(mode) == 0o2770
    assert not stat.S_IMODE(mode) & 0o007


def test_modes_do_not_depend_on_the_staging_process_umask(spool_dir):
    """os.open's and mkdir's mode arguments are both masked by the umask, so a
    host running the API under a restrictive umask would silently get 0600 and
    a non-setgid directory back -- the exact production failure, reintroduced
    invisibly. The explicit fchmod/chmod are what this pins."""
    old = os.umask(0o077)
    try:
        path = spool.stage_archive(str(uuid.uuid4()), b"zip bytes")
    finally:
        os.umask(old)

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert stat.S_IMODE(os.stat(spool_dir).st_mode) == 0o2770


def test_an_already_provisioned_directory_is_left_alone(spool_dir):
    # provision-audit-spool.sh owns this directory on a real host, where it may
    # be owned by another user; staging must not try to re-chmod it on every
    # upload, which could only ever fail.
    spool_dir.mkdir(parents=True)
    os.chmod(spool_dir, 0o2750)

    spool.stage_archive(str(uuid.uuid4()), b"zip bytes")

    assert stat.S_IMODE(os.stat(spool_dir).st_mode) == 0o2750


def test_staging_leaves_no_temporary_file_behind(spool_dir):
    # The .tmp + os.replace dance must not leak: a worker listing the spool
    # should see exactly one file per staged job.
    spool.stage_archive(str(uuid.uuid4()), b"zip bytes")
    assert [p.suffix for p in spool_dir.iterdir()] == [".zip"]


def test_cleanup_removes_the_file(spool_dir):
    path = spool.stage_archive(str(uuid.uuid4()), b"zip bytes")

    spool.cleanup_staged_archive(path)

    assert list(spool_dir.iterdir()) == []


def test_cleanup_is_idempotent_on_a_missing_file(spool_dir):
    # Cleanup runs on the success path, the failure path and any later sweep,
    # so "already gone" is the expected case. It must never be able to turn a
    # finished audit into a failed one.
    path = spool.stage_archive(str(uuid.uuid4()), b"zip bytes")
    spool.cleanup_staged_archive(path)

    spool.cleanup_staged_archive(path)  # no raise

    assert list(spool_dir.iterdir()) == []


def test_cleanup_never_raises_on_a_path_outside_the_spool(spool_dir, tmp_path):
    outsider = tmp_path / "not-ours.zip"
    outsider.write_bytes(b"someone else's file")

    spool.cleanup_staged_archive(str(outsider))

    assert outsider.exists(), "cleanup deleted a file outside the spool"


def test_read_rejects_a_path_outside_the_spool(spool_dir, tmp_path):
    # source_ref comes out of a database row, and a row is not an authenticated
    # input to a filesystem read.
    outsider = tmp_path / "etc-shadow-ish"
    outsider.write_bytes(b"root:x:0:0")

    with pytest.raises(ValueError, match="outside the spool"):
        spool.read_staged_archive(str(outsider))


def test_read_raises_file_not_found_when_the_archive_is_gone(spool_dir):
    path = spool.stage_archive(str(uuid.uuid4()), b"zip bytes")
    spool.cleanup_staged_archive(path)

    # The worker classifies this as permanent: re-running cannot bring the
    # bytes back.
    with pytest.raises(FileNotFoundError):
        spool.read_staged_archive(path)


def test_a_non_uuid_job_id_cannot_escape_the_spool(spool_dir):
    # The only caller-influenced component of a path in this module.
    with pytest.raises(ValueError, match="not a uuid"):
        spool.stage_archive("../../etc/cron.d/pwned", b"x")


def test_staging_refuses_once_the_spool_is_at_its_budget(spool_dir, monkeypatch):
    # Not a new limit: MAX_ARCHIVE_BYTES bounds one archive, this bounds how
    # many of them the host will hold at once.
    monkeypatch.setattr(spool, "MAX_SPOOL_BYTES", 100)
    spool.stage_archive(str(uuid.uuid4()), b"x" * 80)

    with pytest.raises(spool.SpoolFull):
        spool.stage_archive(str(uuid.uuid4()), b"y" * 80)

    # And it recovers once a finished job's archive is cleaned up, rather than
    # wedging the host until someone intervenes.
    for entry in spool_dir.iterdir():
        spool.cleanup_staged_archive(str(entry))
    spool.stage_archive(str(uuid.uuid4()), b"z" * 80)


def test_spool_bytes_used_is_zero_before_the_directory_exists(spool_dir):
    assert not spool_dir.exists()
    assert spool.spool_bytes_used() == 0
