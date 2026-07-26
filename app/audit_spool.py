"""On-disk staging for audit payloads that must outlive their HTTP request.

Migration 0001 records the deliberate absence of object storage: there is no
S3, no `s3_key`, and an uploaded archive has never been persisted anywhere --
it lives in the request body, is scanned inline, and is gone. That is exactly
what stops `POST /v1/audits` from becoming asynchronous: a worker in another
process cannot read bytes that only ever existed in the API process's memory.

This module is the smallest thing that closes that gap: a spool directory the
API writes to at intake and the worker reads from at claim time. It is a local
directory, not object storage, which is an explicit trade -- the queue and its
worker are single-host today (see deploy/systemd/shipit-audit-worker.service,
which runs beside shipit.service), so a shared filesystem is not yet needed.
`audit_jobs.source_kind` exists precisely so this can become an object-storage
key later without a schema change.

Only the 'zip' intake needs staging. A 'repo_url' job stores the URL itself in
source_ref and the worker re-fetches from GitHub, exactly as create_audit does
today -- re-downloading is cheaper and simpler than persisting a copy.
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from app.ingest.validators import MAX_ARCHIVE_BYTES

logger = logging.getLogger(__name__)

# Provisioned as 0700 shipit-ops by deploy/scripts/provision_spool.sh. Kept
# under /srv/shipit (the deploy root) rather than /var/lib so it sits with the
# releases it belongs to, and overridable so tests never touch the real path.
SPOOL_DIR = Path(os.environ.get("AUDIT_SPOOL_DIR", "/srv/shipit/spool"))

# Disk backstop. Not a new limit: one staged file is bounded by the intake's
# own MAX_ARCHIVE_BYTES (50 MB), so this is that same number times the number
# of worst-case archives the host is willing to hold at once. 20 -> ~1 GB,
# comfortably above AUDIT_WORKER_CONCURRENCY (4) in flight plus a backlog, and
# far below the disk a release needs. Tunable without a deploy.
MAX_SPOOL_ARCHIVES = int(os.environ.get("AUDIT_SPOOL_MAX_ARCHIVES", "20"))
MAX_SPOOL_BYTES = MAX_ARCHIVE_BYTES * MAX_SPOOL_ARCHIVES


class SpoolFull(Exception):
    """The spool directory is at its byte budget, so this archive was not
    staged. Raised at intake, where the caller still has the bytes and can
    answer 503 -- never mid-job, where there would be nothing to fall back to.

    Distinct from ArchiveValidationError on purpose: nothing is wrong with the
    submission, the host is simply out of room, so this is retryable and must
    not be reported to the user as a bad archive."""


def _spool_path(job_id: str) -> Path:
    """Resolve a job's staged-archive path, rejecting anything that is not a
    UUID.

    job_id reaches here from audit_jobs.id, so it is already a UUID -- but it
    is also the only caller-influenced part of a filesystem path in this
    module, and a path built from an unvalidated string is how directory
    traversal happens. Parsing it as a UUID and re-rendering the parsed value
    means the name written to disk cannot contain a separator, a '..', or a
    NUL, regardless of what was passed in."""
    try:
        parsed = uuid.UUID(str(job_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"job_id is not a uuid: {job_id!r}") from exc
    return SPOOL_DIR / f"{parsed}.zip"


def spool_bytes_used() -> int:
    """Total size of the staged archives currently on disk. Zero when the
    spool directory does not exist yet."""
    if not SPOOL_DIR.is_dir():
        return 0
    total = 0
    for entry in SPOOL_DIR.iterdir():
        try:
            if entry.is_file():
                total += entry.stat().st_size
        except OSError:
            # Raced with a cleanup_staged_archive: the file we just listed is
            # already gone. It contributes nothing, which is the right answer.
            continue
    return total


def stage_archive(job_id: str, raw: bytes) -> str:
    """Persist `raw` as this job's archive and return the path to record in
    audit_jobs.source_ref.

    Written to a temporary name in the same directory and then os.replace'd
    into place, so the final path either does not exist or is a complete
    archive -- never a half-written one. That matters because the worker's
    only signal that the payload is ready is the job leaving 'created' for
    'queued', and a crash between the two must not leave a claimable job
    pointing at a truncated file.

    Mode 0600 explicitly (not just inherited from the 0700 directory): the
    archive is a user's private source code, and the umask of whatever process
    stages it is not something to depend on.

    Raises SpoolFull if the directory is already at MAX_SPOOL_BYTES."""
    SPOOL_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    used = spool_bytes_used()
    if used + len(raw) > MAX_SPOOL_BYTES:
        raise SpoolFull(
            f"spool at {used} bytes, adding {len(raw)} would exceed the "
            f"{MAX_SPOOL_BYTES} byte budget"
        )
    path = _spool_path(job_id)
    tmp = path.with_suffix(".zip.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    return str(path)


def read_staged_archive(path: str) -> bytes:
    """Read back a staged archive.

    The path is re-checked against SPOOL_DIR rather than trusted: it arrives
    from audit_jobs.source_ref, and a repository row is not an authenticated
    input to a filesystem read. Confining it here means a source_ref that ever
    became attacker-influenced still cannot make the worker read /etc/shadow.

    Raises FileNotFoundError if the archive is gone (already cleaned up, or
    the host was rebuilt under a queued job) -- the worker classifies that as
    a permanent failure, since re-running cannot bring the bytes back."""
    resolved = Path(path).resolve()
    spool_root = SPOOL_DIR.resolve()
    if not resolved.is_relative_to(spool_root):
        raise ValueError(f"staged archive path is outside the spool: {path!r}")
    return resolved.read_bytes()


def cleanup_staged_archive(path: str) -> None:
    """Delete a staged archive once its job is terminal. Never raises.

    Idempotent by design: it is called on the success path, on the failure
    path, and potentially again by a later sweep, and an already-deleted file
    is the expected case rather than an error. A cleanup that could raise
    would be able to turn a finished audit into a failed one, which is exactly
    backwards -- the bytes are disposable, the result is not."""
    try:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(SPOOL_DIR.resolve()):
            logger.warning("refusing to clean up path outside the spool: %s", path)
            return
        resolved.unlink(missing_ok=True)
    except OSError:
        logger.warning("could not remove staged archive %s", path, exc_info=True)
