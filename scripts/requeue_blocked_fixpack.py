#!/usr/bin/env python3
"""Requeue one paid Fix Pack blocked by a diagnosed secrets proof failure.

Run with the active release's Python as root on the production host:
  requeue_blocked_fixpack.py --expected-release FULL_SHA --job-id UUID \
    --audit-id UUID --payment-id UUID [--expected-attempts N] [--apply]

Default: read-only. Use only after deploying a reviewed fix for this failure.
--apply archives the old failure and returns this same job to the paid queue.
No payment, new job, attempt counter, or verification policy is changed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.request import urlopen
from uuid import UUID

CURRENT = Path("/srv/shipit/current")
ARCHIVE_DIR = Path("/root/shipit-recovery")
PROCESSOR_LOCK = 0x46495850


@dataclass(frozen=True)
class RecoveryRequest:
    expected_release: str
    job_id: str
    audit_id: str
    payment_id: str
    expected_attempts: int = 1


class RecoveryRefused(RuntimeError):
    """A known precondition failed; messages contain no connection secrets."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryRefused(message)


def get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as response:
        require(response.status == 200, "Health endpoint did not return HTTP 200.")
        payload = json.loads(response.read(64 * 1024))
    require(isinstance(payload, dict), "Health response is not an object.")
    return payload


def check_runtime(request: RecoveryRequest) -> None:
    require(CURRENT.resolve(strict=True).name == request.expected_release,
            "The active release directory is not the expected reviewed release.")
    for base in ("http://127.0.0.1:8000", "https://api.drydock.co"):
        version = get_json(base + "/version")
        require(version.get("release") == request.expected_release,
                "The running API has not activated the reviewed release.")
        require(version.get("environment") == "production",
                "The API does not report the production environment.")
        health = get_json(base + "/readyz")
        require(health.get("status") == "ready" and health.get("db") is True,
                "The production API/database is not ready.")

    # Read only this setting from the running API's environment; do not print
    # its other variables or assume that the env file equals the running state.
    pid = subprocess.run(
        ["systemctl", "show", "shipit.service", "--property=MainPID", "--value"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout.strip()
    require(pid.isdigit() and int(pid) > 0, "The API service has no running PID.")
    raw_env = Path(f"/proc/{pid}/environ").read_bytes()
    mode = next((entry.split(b"=", 1)[1] for entry in raw_env.split(b"\0")
                 if entry.startswith(b"PROOF_GATE_MODE=")), b"hard")
    require((mode or b"hard").strip().lower() == b"hard",
            "The running proof gate must be hard before recovery.")


def validate_snapshot(job: dict | None, payment: dict | None,
                      another_live_job: bool, request: RecoveryRequest) -> str:
    require(job is not None and payment is not None, "Order/payment was not found.")
    require(str(job["id"]) == request.job_id and str(job["audit_id"]) == request.audit_id
            and job["pack"] == "fixpack", "Order identity does not match.")
    require(str(payment["id"]) == request.payment_id
            and str(payment["fixpack_job_id"]) == request.job_id
            and str(payment["audit_id"]) == request.audit_id
            and payment["product"] == "fixpack", "Payment linkage does not match.")
    require(payment["status"] == "completed" and payment["refunded_at"] is None,
            "Payment is no longer completed and unrefunded.")
    if job["status"] in {"paid", "running", "delivered"}:
        return "already_processed_or_queued"
    require(job["status"] == "blocked" and job["attempts"] == request.expected_attempts,
            "The job no longer matches the diagnosed blocked attempt.")
    require(not job["pr_url"] and not job["pr_delivered"],
            "A pull request was already recorded for this job.")
    require(not another_live_job, "Another paid/running job exists for this audit.")
    proof = job.get("proof_json")
    require(isinstance(proof, dict) and proof.get("template_id") == "secrets_leak"
            and proof.get("verified") is False and proof.get("informational") is False,
            "Stored proof does not match the diagnosed secrets proof failure.")
    for side in ("before", "after"):
        attempt = proof.get(side)
        require(isinstance(attempt, dict) and attempt.get("status") == "success"
                and attempt.get("success") is True,
                "Stored exploit results no longer match the diagnosed failure.")
    require(str(job.get("detail") or "").startswith("proof gate (hard):"),
            "The block reason is not the diagnosed hard proof gate failure.")
    return "eligible"


def archive_failure(job: dict, payment: dict, request: RecoveryRequest) -> Path:
    ARCHIVE_DIR.mkdir(mode=0o700, exist_ok=True)
    info = ARCHIVE_DIR.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700,
            "Recovery archive directory must be root-owned with mode 0700.")
    fd, name = tempfile.mkstemp(prefix=f"{request.job_id}-attempt-{request.expected_attempts}-", suffix=".json",
                                dir=ARCHIVE_DIR)
    path = Path(name)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"purpose": "pre-requeue evidence; does not imply DB commit",
                   "recovery_release": request.expected_release, "job": job, "payment": payment},
                  stream, ensure_ascii=False, indent=2, default=str)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(ARCHIVE_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return path


def recover(conn, request: RecoveryRequest, *, apply: bool) -> dict:
    if not apply:
        conn.execute("SET TRANSACTION READ ONLY")
    conn.execute("SET LOCAL statement_timeout = '15s'")
    conn.execute("SET LOCAL lock_timeout = '3s'")
    if apply:
        lock = conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS acquired",
                            (PROCESSOR_LOCK,)).fetchone()
        require(lock and lock["acquired"],
                "The Fix Pack processor is busy; retry after it finishes.")
    suffix = " FOR UPDATE" if apply else ""
    # Payment first: match the normal payment->job lock order.
    payment = conn.execute(
        "SELECT id, audit_id, fixpack_job_id, product, status, refunded_at "
        "FROM payments WHERE id = %s" + suffix, (request.payment_id,),
    ).fetchone()
    job = conn.execute(
        "SELECT id, audit_id, pack, status, attempts, started_at, pr_url, "
        "pr_delivered, detail, proof_json, funding_key "
        "FROM fixpack_jobs WHERE id = %s" + suffix, (request.job_id,),
    ).fetchone()
    other = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM fixpack_jobs WHERE audit_id = %s "
        "AND id <> %s AND status IN ('paid', 'running')) AS found",
        (request.audit_id, request.job_id),
    ).fetchone()["found"]
    state = validate_snapshot(job, payment, other, request)
    result = {"job_id": request.job_id, "release": request.expected_release, "state": state,
              "changed": False, "attempts": job["attempts"]}
    if state != "eligible" or not apply:
        return result
    archive = archive_failure(job, payment, request)
    cursor = conn.execute(
        "UPDATE fixpack_jobs SET status = 'paid', started_at = NULL, "
        "detail = NULL, proof_json = NULL "
        "WHERE id = %s AND status = 'blocked' AND attempts = %s "
        "AND pr_url IS NULL AND pr_delivered IS FALSE",
        (request.job_id, request.expected_attempts),
    )
    require(cursor.rowcount == 1, "The guarded update did not affect exactly one job.")
    result.update(state="requeued", changed=True, archive=str(archive))
    return result


def full_revision(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError("expected a full lowercase 40-character commit SHA")
    return value


def order_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a UUID") from error


def positive_attempts(value: str) -> int:
    try:
        attempts = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer of at least 1") from error
    if attempts < 1:
        raise argparse.ArgumentTypeError("expected an integer of at least 1")
    return attempts


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-release", required=True, type=full_revision)
    parser.add_argument("--job-id", required=True, type=order_uuid)
    parser.add_argument("--audit-id", required=True, type=order_uuid)
    parser.add_argument("--payment-id", required=True, type=order_uuid)
    parser.add_argument("--expected-attempts", type=positive_attempts, default=1)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    request = RecoveryRequest(args.expected_release, args.job_id, args.audit_id,
                              args.payment_id, args.expected_attempts)
    try:
        require(os.geteuid() == 0, "Run this recovery tool as root on production.")
        # Serialize with the standard release/rollback scripts too: no release
        # can switch between the runtime check and the database commit.
        with open("/run/lock/shipit-deploy.lock", "a") as deployment_lock:
            fcntl.flock(deployment_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check_runtime(request)
            sys.path.insert(0, str(CURRENT.resolve()))
            import psycopg
            from psycopg.rows import dict_row
            from scripts.env_file import read_values

            dsn = read_values(Path("/opt/shipit/.env")).get("DATABASE_URL")
            require(bool(dsn), "DATABASE_URL was not found in the deployment config.")
            with psycopg.connect(dsn, connect_timeout=10, prepare_threshold=None,
                                 row_factory=dict_row) as conn:
                result = recover(conn, request, apply=args.apply)
            # Report success only AFTER the transaction commits.
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except RecoveryRefused as error:
        print(f"Recovery refused: {error}", file=sys.stderr)
    except Exception as error:
        # Database/HTTP exceptions can contain credentials or private evidence.
        print(f"Recovery did not complete: {type(error).__name__}. "
              "Connection details are hidden; rerun the read-only diagnosis.",
              file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
