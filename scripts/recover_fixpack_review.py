#!/usr/bin/env python3
"""Recover the full review owed for an already delivered Fix Pack.

Default is a read-only diagnosis (including public GitHub reads). --apply runs
the normal audit pipeline on the verified source revision. It never requeues a
Fix Pack, charges a payment, opens a PR, or publishes the private report link.

Run with the active release's Python as root. When copied outside the checkout,
keep requeue_blocked_fixpack.py alongside this file for the shared runtime guard.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import fcntl
import io
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urljoin, urlsplit

if __package__:
    from . import requeue_blocked_fixpack as guards
else:
    import requeue_blocked_fixpack as guards

STATE_DIR = Path("/root/shipit-review-recovery")
GITHUB_API = "https://api.github.com"
FULL_BASIS = "static+llm"


@dataclass(frozen=True)
class ReviewRequest:
    expected_release: str
    job_id: str
    audit_id: str
    payment_id: str
    source_revision: str


def repository_parts(repo_url: str) -> tuple[str, str]:
    parsed = urlsplit(repo_url)
    guards.require(parsed.scheme == "https" and parsed.netloc == "github.com"
                   and not parsed.query and not parsed.fragment,
                   "The original audit does not identify a public GitHub repository.")
    parts = parsed.path.strip("/").split("/")
    guards.require(len(parts) == 2 and all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts),
                   "The original repository path is invalid.")
    owner, repo = parts
    repo = repo.removesuffix(".git")
    guards.require(bool(repo) and owner not in {".", ".."} and repo not in {".", ".."},
                   "The original repository path is invalid.")
    return owner, repo


def validate_order(job: dict | None, payment: dict | None, request: ReviewRequest) -> tuple[str, str, int]:
    guards.require(job is not None and payment is not None, "Order/payment was not found.")
    guards.require(str(job["id"]) == request.job_id and str(job["audit_id"]) == request.audit_id
                   and job["pack"] == "fixpack", "Order identity does not match.")
    guards.require(job["status"] == "delivered" and job["pr_delivered"] is True and bool(job["pr_url"]),
                   "The Fix Pack must already be delivered; diagnose its current processing state first.")
    guards.require(str(payment["id"]) == request.payment_id
                   and str(payment["fixpack_job_id"]) == request.job_id
                   and str(payment["audit_id"]) == request.audit_id
                   and payment["product"] == "fixpack", "Payment linkage does not match.")
    guards.require(payment["status"] == "completed" and payment["refunded_at"] is None,
                   "Payment is no longer completed and unrefunded.")
    owner, repo = repository_parts(str(job.get("repo_url") or ""))
    match = re.fullmatch(rf"https://github\.com/{re.escape(owner)}/{re.escape(repo)}/pull/([1-9][0-9]*)",
                         str(job["pr_url"]))
    guards.require(match is not None, "The recorded pull request belongs to a different repository.")
    return owner, repo, int(match[1])


def validate_pr(pr: dict, owner: str, repo: str, number: int, request: ReviewRequest) -> None:
    guards.require(pr.get("number") == number
                   and (pr.get("base", {}).get("repo") or {}).get("full_name") == f"{owner}/{repo}"
                   and (pr.get("head", {}).get("repo") or {}).get("full_name") == f"{owner}/{repo}"
                   and pr.get("head", {}).get("ref") == f"drydock/fix-pack-{request.job_id}",
                   "The public pull request does not match this Fix Pack job.")
    body = pr.get("body")
    guards.require(isinstance(body, str) and bool(body.strip()), "The pull request body could not be checked.")
    guards.require(not re.search(r"^###\s+Your full review\s*$", body, re.MULTILINE | re.IGNORECASE),
                   "This pull request already contains its full review; diagnose that report instead.")


def proof_matches_source(job: dict, owner: str, repo: str, revision: str) -> bool:
    """Match the GitHub zipball prefix recorded by the actual proof scanner."""
    proof = job.get("proof_json") or {}
    paths = []
    for side in ("before", "after"):
        attempt = proof.get(side) or {}
        evidence = attempt.get("evidence") or {}
        for sample in evidence.get("samples") or []:
            if isinstance(sample, dict) and isinstance(sample.get("file"), str):
                paths.append(sample["file"])
    prefix = f"{owner}-{repo}-{revision[:7]}/"
    return bool(paths) and all(path.startswith(prefix) for path in paths)


def _public_bytes(url: str, *, limit: int, transport=None, redirects: bool = False) -> bytes:
    """Bound both JSON and archive downloads; never send application credentials."""
    import httpx

    with httpx.Client(timeout=httpx.Timeout(60, connect=10), transport=transport,
                      follow_redirects=False, headers={"Accept": "application/vnd.github+json",
                                                      "X-GitHub-Api-Version": "2022-11-28"}) as client:
        for _ in range(4):
            parsed = urlsplit(url)
            guards.require(parsed.scheme == "https" and parsed.netloc in {"api.github.com", "codeload.github.com"},
                           "GitHub returned an unexpected archive download host.")
            with client.stream("GET", url) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    guards.require(redirects and bool(response.headers.get("location")),
                                   "Unexpected redirect from the public GitHub API.")
                    url = urljoin(url, response.headers["location"])
                    continue
                guards.require(response.status_code == 200, "Public GitHub download did not return HTTP 200.")
                declared = response.headers.get("content-length")
                guards.require(declared is None or (declared.isdigit() and int(declared) <= limit),
                               "The GitHub response exceeds the download limit.")
                data = bytearray()
                for chunk in response.iter_bytes(64 * 1024):
                    data.extend(chunk)
                    guards.require(len(data) <= limit, "The GitHub response exceeds the download limit.")
                return bytes(data)
    raise guards.RecoveryRefused("GitHub redirected the archive too many times.")


def fetch_pr(owner: str, repo: str, number: int) -> dict:
    data = json.loads(_public_bytes(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{number}", limit=1024 * 1024))
    guards.require(isinstance(data, dict), "GitHub did not return a pull request object.")
    return data


def fetch_source_zip(owner: str, repo: str, revision: str, *, transport=None) -> bytes:
    from app.ingest.validators import MAX_ARCHIVE_BYTES

    guards.full_revision(revision)
    return _public_bytes(f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{revision}",
                         limit=MAX_ARCHIVE_BYTES, transport=transport, redirects=True)


class ReviewStore:
    """Short, read-only transactions. No row/processor lock survives a network call."""

    def __init__(self, dsn: str):
        self.dsn = dsn

    @contextmanager
    def connection(self):
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self.dsn, connect_timeout=10, prepare_threshold=None, row_factory=dict_row) as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            conn.execute("SET LOCAL statement_timeout = '15s'")
            yield conn

    def snapshot(self, request: ReviewRequest) -> tuple[dict | None, dict | None]:
        with self.connection() as conn:
            job = conn.execute(
                "SELECT j.id, j.audit_id, j.pack, j.status, j.pr_url, j.pr_delivered, j.attempts, "
                "j.started_at, j.proof_json, a.repo_url FROM fixpack_jobs j "
                "JOIN audits a ON a.id = j.audit_id WHERE j.id = %s", (request.job_id,),
            ).fetchone()
            payment = conn.execute(
                "SELECT id, fixpack_job_id, audit_id, product, status, refunded_at "
                "FROM payments WHERE id = %s", (request.payment_id,),
            ).fetchone()
        return job, payment

    def incomplete_source(self, job: dict, digest: str) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT id FROM audits WHERE repo_url = %s AND content_hash = %s "
                "AND created_at >= %s AND status = 'completed' "
                "AND score_json->>'basis' IN ('static_only', 'static+partial') LIMIT 1",
                (job["repo_url"], digest, job["started_at"]),
            ).fetchone()
        return row is not None

    def audit(self, audit_id: str) -> dict | None:
        with self.connection() as conn:
            return conn.execute(
                "SELECT id, status, repo_url, content_hash, engine_version, score_json, access_token "
                "FROM audits WHERE id = %s", (audit_id,),
            ).fetchone()


class BaselineRepairRepository:
    """Reuse full analysis while letting the normal pipeline retry an unfinished included preview."""

    def __init__(self, repo):
        self.repo = repo

    async def get_by_content_hash(self, digest, engine, basis):
        row = await self.repo.get_by_content_hash(digest, engine, basis)
        if row and basis == FULL_BASIS:
            baseline = (row.get("score_json") or {}).get("free_baseline") or {}
            if baseline.get("status") != "completed":
                row = deepcopy(row)
                row["score_json"].pop("free_baseline", None)
        return row

    async def create(self, **values):
        return await self.repo.create(**values)


def _protected_fd(path: Path) -> int:
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600):
        os.close(fd)
        raise guards.RecoveryRefused("Recovery files must be root-owned regular files with mode 0600.")
    return fd


@contextmanager
def review_lock(request: ReviewRequest):
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    info = STATE_DIR.lstat()
    guards.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                   "The review recovery directory must be root-owned with mode 0700.")
    with os.fdopen(_protected_fd(STATE_DIR / f"{request.job_id}.lock"), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise guards.RecoveryRefused("A review recovery for this job is already running.") from error
        yield STATE_DIR


def save_private_result(directory: Path, job_id: str, result: dict) -> Path:
    destination = directory / f"{job_id}-review.json"
    fd, name = tempfile.mkstemp(prefix="review-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, destination)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(name).unlink(missing_ok=True)
    return destination


async def recover_review(request: ReviewRequest, *, apply: bool, directory: Path, store,
                         runner, llm_client, audit_repo, llm_usage_repo, repo_fetcher,
                         engine: str, pr_loader=fetch_pr, downloader=fetch_source_zip) -> dict:
    from app.ingest.validators import validate_zip
    from app.scan.pipeline import content_digest

    job, payment = store.snapshot(request)
    owner, repo, number = validate_order(job, payment, request)
    validate_pr(pr_loader(owner, repo, number), owner, repo, number, request)
    raw = downloader(owner, repo, request.source_revision)
    validate_zip(io.BytesIO(raw), size_bytes=len(raw))
    digest = content_digest(raw)
    guards.require(proof_matches_source(job, owner, repo, request.source_revision)
                   or store.incomplete_source(job, digest),
                   "The source revision does not match the saved proof or incomplete review; "
                   "diagnose its source first.")
    summary = {"job_id": request.job_id, "release": request.expected_release,
               "source_revision": request.source_revision, "content_hash": digest,
               "fixpack_status": "delivered", "pr_url": job["pr_url"], "state": "eligible", "applied": False}
    if not apply:
        return summary
    # Public reads can take time. Revalidate entitlement immediately before any
    # LLM call, without carrying a database transaction into the audit pipeline.
    validate_order(*store.snapshot(request), request)
    result = await runner(
        job["repo_url"], llm_client=llm_client, audit_repo=BaselineRepairRepository(audit_repo),
        repo_fetcher=repo_fetcher, llm_usage_repo=llm_usage_repo, job_type="fixpack_review", zip_bytes=raw,
    )
    guards.require(isinstance(result, dict) and bool(result.get("audit_id")),
                   "The full review did not return a saved audit; the delivered Fix Pack was not changed.")
    saved = store.audit(str(result["audit_id"]))
    guards.require(saved is not None and str(saved["id"]) == str(result["audit_id"])
                   and saved["status"] == "completed" and saved["content_hash"] == digest
                   and saved["repo_url"] == job["repo_url"] and saved["engine_version"] == engine
                   and bool(result.get("access_token")) and saved["access_token"] == result["access_token"],
                   "The returned review could not be verified against its stored audit.")
    score = saved.get("score_json") or {}
    basis = score.get("basis")
    guards.require(result.get("basis") == basis, "The reported and stored review basis do not agree.")
    baseline = (score.get("free_baseline") or {}).get("status", "missing")
    ready = basis == FULL_BASIS and baseline == "completed"
    summary.update(state="full_review_ready" if ready else "review_incomplete", applied=True,
                   review_audit_id=str(saved["id"]), basis=basis, free_baseline_status=baseline,
                   analysis_reused=bool(result.get("reused")),
                   limitations=(score.get("scan_manifest") or {}).get("limitations") or [])
    # This private ownership link is deliberately absent from stdout/logs/PRs.
    private = {**summary, "report_url": f"https://drydock.co/audit/{saved['id']}?token={saved['access_token']}"}
    summary["private_result_file"] = str(save_private_result(directory, request.job_id, private))
    return summary


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-release", required=True, type=guards.full_revision)
    parser.add_argument("--job-id", required=True, type=guards.order_uuid)
    parser.add_argument("--audit-id", required=True, type=guards.order_uuid)
    parser.add_argument("--payment-id", required=True, type=guards.order_uuid)
    parser.add_argument("--source-revision", required=True, type=guards.full_revision)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def load_environment() -> dict:
    sys.path.insert(0, str(guards.CURRENT.resolve(strict=True)))
    from scripts.env_file import read_values

    values = read_values(Path("/opt/shipit/.env"))
    guards.require(bool(values.get("DATABASE_URL")), "DATABASE_URL was not found in the deployment config.")
    os.environ.update(values)
    return values


@contextmanager
def configure_private_log(path: Path):
    from app.logging_config import build_handler, configure_logging, log_level_from_env

    root = logging.getLogger()
    previous_handlers, previous_level = root.handlers[:], root.level
    with os.fdopen(_protected_fd(path), "a", encoding="utf-8") as stream:
        handler = build_handler()
        handler.setStream(stream)
        for previous in previous_handlers:
            root.removeHandler(previous)
        root.addHandler(handler)
        root.setLevel(log_level_from_env())
        configure_logging()
        try:
            yield stream
        finally:
            root.removeHandler(handler)
            handler.close()
            for previous in previous_handlers:
                root.addHandler(previous)
            root.setLevel(previous_level)


async def run_on_production(request: ReviewRequest, apply: bool, directory: Path, dsn: str) -> dict:
    from app.db import AuditRepository, LlmUsageRepository, close_pool
    from app.ingest.github_fetch import fetch_repo_zip
    from app.llm.client import LLMClient
    from app.log_context import log_context
    from app.main import run_repo_audit
    from app.scan.pipeline import AUDIT_ENGINE_VERSION

    try:
        with log_context(job_id=request.job_id, audit_id=request.audit_id, trace_id=request.job_id):
            return await recover_review(
                request, apply=apply, directory=directory, store=ReviewStore(dsn),
                runner=run_repo_audit, llm_client=LLMClient(), audit_repo=AuditRepository(),
                llm_usage_repo=LlmUsageRepository(), repo_fetcher=fetch_repo_zip, engine=AUDIT_ENGINE_VERSION,
            )
    finally:
        await close_pool()


def main(argv=None) -> int:
    args = parse_args(argv)
    request = ReviewRequest(args.expected_release, args.job_id, args.audit_id, args.payment_id, args.source_revision)
    previous_umask = None
    try:
        guards.require(os.geteuid() == 0, "Run this recovery tool as root on production.")
        previous_umask = os.umask(0o077)
        with review_lock(request) as directory:
            # Shared deployment lock: a release cannot switch while this
            # recovery imports and executes its reviewed code. Other job
            # recoveries remain independent; no global DB processor lock.
            with open("/run/lock/shipit-deploy.lock", "a") as deployment_lock:
                fcntl.flock(deployment_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                guards.check_runtime(request)
                values = load_environment()
                log_path = directory / f"{request.job_id}-review.log"
                with configure_private_log(log_path):
                    result = asyncio.run(run_on_production(request, args.apply, directory, values["DATABASE_URL"]))
                result["log_file"] = str(log_path)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 2 if result["state"] == "review_incomplete" else 0
    except guards.RecoveryRefused as error:
        print(f"Review recovery refused: {error}", file=sys.stderr)
    except Exception as error:
        # DB/provider exceptions may include credentials or customer source.
        print(f"Review recovery did not complete: {type(error).__name__}. "
              "The delivered Fix Pack and payment were not changed.", file=sys.stderr)
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
