"""Shared test fixtures.

Autouse: give every test a fresh, generous rate limiter so tests in
different files that each hit /v1/audits a few times never trip each
other's daily budget (they'd otherwise all share the same TestClient
key). Tests that want to exercise real limiting override
`get_rate_limiter` themselves inside the test body — see
test_ratelimit.py — which simply shadows this default for the
duration of that test.

Autouse: keep DATABASE_URL out of the default suite regardless of what
the shell happens to have exported. Without this, a DATABASE_URL left
over from running scripts/verify_db_locally.py by hand makes
unrelated tests (test_fixpack_api.py, test_ingest_api.py, ...) open
real connections to Supabase through app/db.py's module-global pool --
slow, and the pool ends up bound to one test's asyncio event loop
while a later test runs on a different (already-closed) one, which is
what the `Event loop is closed` / `another operation is in progress`
cascade actually was. tests/test_db.py sets DATABASE_URL back
explicitly, per test, where it wants the configured-path behavior.
"""

from __future__ import annotations

import os
import urllib.parse
import uuid

import pytest

import app.audit_spool as spool_mod
import app.db as db_mod
from app.accounts import api_key_prefix, generate_api_key
from app.main import app, get_audit_job_repo, get_rate_limiter
from app.ratelimit import RateLimiter



# Hosts a test suite is allowed to write to. An empty hostname is a Unix
# socket (postgresql://user@/db?host=/tmp/pg), which cannot reach a hosted
# database.
DISPOSABLE_DB_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1"})


def is_disposable_database(url: str) -> bool:
    """Whether DATABASE_URL points somewhere this suite may write to.

    On 2026-07-22 tests/test_db_postgres_smoke.py was run four times against
    the PRODUCTION database. It writes a fix_outcomes row and then calls
    set_pr_merged_by_pr_url on its own fabricated PR link, so production ended
    up holding four outcomes claiming a merged pull request that never
    existed. They were still there on 2026-08-02, one distinct audit short of
    declaring two rules ready to learn from, on a 100% merge rate that was
    entirely our own test data.

    Nothing failed at the time. The suite passed, because from its point of
    view it had done exactly what it meant to.

    The check is on the HOST, not the database name. A name is a convention
    someone can match by accident -- a hosted database called `shipit_test`
    is still hosted -- while a local socket or loopback address cannot reach
    anyone else's data by construction.

    Deliberately no override. An escape hatch would be one more environment
    variable to export by mistake, and the mistake this exists to prevent was
    exporting an environment variable. If a remote throwaway database is ever
    genuinely needed, add the hatch then, on purpose.
    """
    parsed = urllib.parse.urlsplit(url)
    return (parsed.hostname or "") in DISPOSABLE_DB_HOSTS


def pytest_configure(config):
    """Refuse to start rather than refuse to write.

    Before collection, so it lands before any fixture, any import side effect
    and any connection -- the point is that nothing gets a chance to write.
    """
    url = os.environ.get("DATABASE_URL", "")
    if not url or is_disposable_database(url):
        return

    host = urllib.parse.urlsplit(url).hostname
    raise pytest.UsageError(
        f"DATABASE_URL points at host {host!r}, which is not a disposable "
        "test database. This suite writes real rows and cleans up nothing; "
        "run it against localhost or a Unix socket. "
        "(On 2026-07-22 it was pointed at production and seeded the "
        "fix_outcomes knowledge base with four fabricated merge verdicts.)"
    )


@pytest.fixture(autouse=True)
def _generous_rate_limit_by_default():
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=10_000)
    yield
    app.dependency_overrides.pop(get_rate_limiter, None)


@pytest.fixture(autouse=True)
def _no_ambient_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_mod._pool = None
    yield
    db_mod._pool = None


@pytest.fixture(autouse=True)
def audit_spool_dir(tmp_path, monkeypatch):
    """Point the archive spool at a per-test directory.

    Autouse for the same reason DATABASE_URL is stripped above: since the queue
    cutover, POST /v1/audits with a file writes the upload to disk, and the
    default target is the production spool (/srv/shipit/spool). No test may
    write there, and no test may see another test's staged archives. Returned
    so a test can assert on what was staged."""
    directory = tmp_path / "spool"
    monkeypatch.setattr(spool_mod, "SPOOL_DIR", directory)
    return directory


class FakeAuditQueue:
    """The slice of AuditJobRepository that create_audit uses, in memory.

    Models the two behaviours the endpoint's correctness rests on: the
    partial unique index over live states (a second submission with the same
    idempotency_key joins the existing job and reports inserted=False), and the
    'created' -> 'queued' transition that only completes once the payload is
    staged. The SQL behind both is covered against real Postgres in
    tests/test_audit_jobs_repo.py."""

    def __init__(self, *, unavailable: bool = False):
        # unavailable models a deployment with no DATABASE_URL, where every
        # repository method degrades to None/False.
        self.unavailable = unavailable
        self.rows: dict[str, dict] = {}
        self.live_keys: dict[str, str] = {}
        self.enqueued: list[dict] = []
        self.abandoned: list[dict] = []

    _LIVE = ("created", "queued", "claimed", "running")

    async def enqueue(self, *, job_id=None, initial_state="queued", **fields):
        if self.unavailable:
            return None
        self.enqueued.append({"initial_state": initial_state, **fields})
        existing = self.live_keys.get(fields["idempotency_key"])
        if existing is not None:
            return {**self.rows[existing], "inserted": False}
        row_id = job_id or str(uuid.uuid4())
        row = {
            "id": row_id,
            "state": initial_state,
            # Deliberately fake: the real token is minted by the database.
            "access_token": f"fake-job-token-{row_id}",
            **fields,
        }
        self.rows[row_id] = row
        self.live_keys[fields["idempotency_key"]] = row_id
        return {**row, "inserted": True}

    async def mark_queued(self, *, job_id, source_ref=None):
        row = self.rows.get(job_id)
        if self.unavailable or row is None or row["state"] != "created":
            return False
        row["state"] = "queued"
        if source_ref is not None:
            row["source_ref"] = source_ref
        return True

    async def abandon_created(self, *, job_id, error_code, error_message):
        row = self.rows.get(job_id)
        if row is None or row["state"] != "created":
            return False
        row["state"] = "dead_letter"
        row["error_code"] = error_code
        self.live_keys.pop(row["idempotency_key"], None)
        self.abandoned.append({"job_id": job_id, "error_code": error_code})
        return True

    @property
    def only(self) -> dict:
        """The single job this queue holds, asserting there is exactly one."""
        assert len(self.rows) == 1, f"expected one job, have {len(self.rows)}"
        return next(iter(self.rows.values()))


class FakeAccountRepo:
    """AccountRepository's real post-0019 contract, in memory.

    Lives here, shared, because four copies of this fake used to live in four
    billing test files and all four got the same thing wrong: they stored the
    account dict with its `api_key` and handed that same dict back from
    get_by_id. The real repository cannot do that -- migration 0019 dropped
    accounts.api_key, so only key_prefix and key_hash are at rest and
    get_by_id's SELECT has no key text to return. That divergence is what made
    a production KeyError on `get_by_id(...)["api_key"]` inexpressible in the
    suite, in four places at once.

    So the invariant here is deliberate and load-bearing: the plaintext key is
    returned by create() and rotate_key() and is stored NOWHERE. Rows are
    handed out as copies, so a caller can't write a key back into storage and
    quietly restore the old, wrong behaviour.
    """

    def __init__(self):
        self.by_id: dict[str, dict] = {}
        self.rotations: list[str] = []

    def _issue(self, account_id: str, api_key: str) -> dict:
        stored = self.by_id[account_id]
        stored["key_prefix"] = api_key_prefix(api_key)
        # Stands in for the real HMAC-with-env-pepper digest: what matters for
        # these tests is only that it is not the key text itself.
        stored["key_hash"] = f"hash-of:{api_key}"
        return {**stored, "api_key": api_key}

    async def create(self, *, api_key: str, tier: str):
        account_id = str(uuid.uuid4())
        self.by_id[account_id] = {
            "id": account_id, "tier": tier,
            "created_at": "2026-07-14T10:00:00Z",
        }
        return self._issue(account_id, api_key)

    async def get_by_id(self, account_id: str):
        stored = self.by_id.get(account_id)
        return dict(stored) if stored is not None else None

    async def rotate_key(self, account_id: str):
        if account_id not in self.by_id:
            return None
        self.rotations.append(account_id)
        return self._issue(account_id, generate_api_key())


class FakeKeyDeliveryMixin:
    """PaymentRepository's one-shot key-delivery claim (migration 0024) for the
    in-memory payment fakes, defined once so all of them agree on the rule that
    matters: a completed payment can be claimed exactly once. Expects the host
    class to keep payment rows in `self.rows`, keyed by id."""

    rows: dict[str, dict]

    async def claim_key_delivery(self, payment_id: str) -> bool:
        row = self.rows[payment_id]
        if row.get("status") != "completed" or row.get("key_delivered_at"):
            return False
        row["key_delivered_at"] = "2026-07-14T10:05:00Z"
        return True

    async def release_key_delivery(self, payment_id: str) -> None:
        self.rows[payment_id]["key_delivered_at"] = None


FIXPACK_LIVE_STATUSES = ("paid", "running")


def fixpack_live_job(jobs, audit_id):
    """The one live Fix Pack job for an audit, or None -- the in-memory stand-in
    for the arbiter of FixpackJobRepository.create_paid's ON CONFLICT
    (fixpack_jobs_audit_live_idx, migration 0025).

    Shared by the FakeFixpackRepo in each billing test file so both agree on the
    predicate, including the part that is easy to get wrong: only 'paid' and
    'running' collide. A terminal job ('failed', 'delivered', ...) must NOT, or
    the fakes would forbid the re-purchase-after-failure the real index allows.
    A null audit_id never collides (Postgres treats NULLs as distinct)."""
    if audit_id is None:
        return None
    for job in jobs:
        if (job.get("audit_id") == audit_id
                and job.get("status") in FIXPACK_LIVE_STATUSES):
            return job
    return None


class FakeCompletionCasMixin:
    """PaymentRepository's compare-and-set completion gate for the in-memory
    payment fakes, defined once so all four of them agree on it and none can
    drift back to the unconditional overwrite the real SQL no longer does.

    Mirrors the predicate in app/db.py exactly -- `where id = %s and (status =
    'pending' or (status = 'completed' and external_ref = %s))` -- and therefore
    the contract that matters to callers: a row on success, including on a replay
    of the SAME charge, and None when the row is already completed under a
    DIFFERENT one. A fake that kept returning None unconditionally would let a
    caller mishandle that refusal and still pass.

    Expects the host class to keep payment rows in `self.rows`, keyed by id."""

    rows: dict[str, dict]

    def _cas_complete(self, payment_id: str, external_ref: str) -> dict | None:
        row = self.rows[payment_id]
        if row.get("status") == "pending":
            return row
        if row.get("status") == "completed" and row.get("external_ref") == (
            external_ref
        ):
            return row
        return None

    async def mark_completed(self, payment_id, *, account_id, external_ref):
        row = self._cas_complete(payment_id, external_ref)
        if row is None:
            return None
        row.update(
            status="completed", account_id=account_id, external_ref=external_ref)
        return row

    async def mark_completed_fixpack(self, payment_id, *, external_ref):
        row = self._cas_complete(payment_id, external_ref)
        if row is None:
            return None
        row.update(status="completed", external_ref=external_ref)
        return row


class NullLlmUsageRepo:
    """LlmUsageRepository's no-DATABASE_URL behaviour: records nothing."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **fields):
        self.rows.append(fields)
        return None

    async def sum_anon_spend_today(self):
        # None is the no-journal answer, which reads as "no cap to enforce".
        return None


class RecordingAuditRepo:
    """AuditRepository with no cache and a record of everything persisted."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **fields):
        row = {"id": str(uuid.uuid4()), **fields}
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        return None


async def run_audit_job(raw: bytes, *, llm_client, audit_repo=None,
                        llm_usage_repo=None, account_id=None) -> dict:
    """Stage `raw` as a zip job and run it through the worker.

    The worker half of an audit for tests that care about what a scan produces
    rather than about the endpoint. Goes through the real spool so the payload
    handoff -- the part that only exists because the scan moved to another
    process -- is exercised rather than assumed. Returns the persisted row."""
    from app.audit_spool import stage_archive
    from app.worker.main import _execute_job

    repo = audit_repo or RecordingAuditRepo()
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "source_kind": "zip",
        "source_ref": stage_archive(job_id, raw),
        "account_id": account_id,
        "attempts": 1,
        "max_attempts": 3,
    }
    audit_id = await _execute_job(
        job, llm_client=llm_client, audit_repo=repo,
        llm_usage_repo=llm_usage_repo or NullLlmUsageRepo(),
    )
    return next(r for r in repo.rows if r["id"] == audit_id)


async def drain_audit_queue(queue, *, audit_repo, llm_client,
                            llm_usage_repo=None) -> list[str]:
    """Run every queued job in `queue` through the worker and return audit ids.

    The other half of an audit since the cutover. A test that used to assert on
    what POST /v1/audits returned now has two steps -- the endpoint queues, the
    worker scans -- and this is the second one, running the real
    `_execute_job` (payload load, validation, cache check, scan, persist)
    rather than a stand-in, so the assertions still cover the code that
    produces the result."""
    from app.worker.main import _execute_job

    audit_ids = []
    for row in list(queue.rows.values()):
        if row["state"] != "queued":
            continue
        audit_id = await _execute_job(
            row, llm_client=llm_client, audit_repo=audit_repo,
            llm_usage_repo=llm_usage_repo or NullLlmUsageRepo(),
        )
        row["state"] = "succeeded"
        row["audit_id"] = audit_id
        queue.live_keys.pop(row["idempotency_key"], None)
        audit_ids.append(audit_id)
    return audit_ids


@pytest.fixture(autouse=True)
def audit_queue():
    """Give every test a working audit queue behind POST /v1/audits.

    Autouse, like the rate limiter above and for the same reason: the endpoint
    now needs a queue to accept anything at all, and without one every test that
    posts an audit would get 503 queue_unavailable. A test that wants the
    unconfigured deployment specifically overrides get_audit_job_repo itself,
    which shadows this for its duration."""
    queue = FakeAuditQueue()
    app.dependency_overrides[get_audit_job_repo] = lambda: queue
    yield queue
    app.dependency_overrides.pop(get_audit_job_repo, None)


@pytest.fixture(autouse=True)
def _no_ambient_llm_providers(monkeypatch):
    """Same isolation principle as DATABASE_URL above, third instance
    of the class: a shell with AITUNNEL_*/ANTHROPIC_* exported (e.g.
    after `set -a; . ./.env` for a manual script run) made the default
    suite construct a real provider chain and spend real money on real
    LLM calls — one visible assertion failure, several silent paid
    calls, 4-minute suite. Tests that want an LLM pass explicit fake
    providers or monkeypatch get_llm_client; nothing may inherit them
    from the ambient environment."""
    for var in ("AITUNNEL_API_KEY", "AITUNNEL_BASE_URL",
                "ANTHROPIC_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _no_ambient_production_integrations(monkeypatch):
    """Never let the default test suite use production integrations.

    The production VPS exports real GitHub App and sandbox-runner settings.
    Tests that need these values must set or monkeypatch them explicitly.

    Also drops app_auth_ok's cached verdict, which is module-level and would
    otherwise let one test's credentials answer another test's health probe.
    """
    from app.deploypack.github_app import reset_app_auth_cache

    reset_app_auth_cache()
    variables = (
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_PRIVATE_KEY_B64",
        "GITHUB_APP_SLUG",
        "GITHUB_PR_TOKEN",
        "SANDBOX_RUNNER_URL",
        "SANDBOX_RUNNER_UDS",
        "SANDBOX_RUNNER_TOKEN",
        "SANDBOX_RUNNER_VERIFICATION_TIMEOUT_S",
        "FIXPACK_VERIFIED_BUILD_GATE",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET",
        # The operator's own Telegram id. Stripped for two reasons: it is the
        # allowlist the bank-transfer confirm button checks against, and its
        # absence is itself a behaviour under test (an unset allowlist must
        # reject everyone, never allow everyone).
        "TELEGRAM_ADMIN_CHAT_ID",
        "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "USDT_POLL_TOKEN",
        # A private individual's real banking details on the production host.
        "BANK_TRANSFER_CARD",
        "BANK_TRANSFER_BANK_NAME",
        "BANK_TRANSFER_SWIFT",
        "BANK_TRANSFER_BENEFICIARY",
        "BANK_TRANSFER_ACCOUNT",
        "BANK_TRANSFER_ADDRESS",
        "BANK_TRANSFER_PRO_PRICE_USD",
        "BANK_TRANSFER_FIXPACK_PRICE_USD",
    )

    for variable in variables:
        monkeypatch.delenv(variable, raising=False)

    # sandbox_client reads these values at import time, before pytest
    # fixtures execute. Override the module-level values as well so a test
    # can never contact the real production runner accidentally.
    import app.sandbox_client as sandbox_client_mod

    monkeypatch.setattr(sandbox_client_mod, "SANDBOX_RUNNER_URL", "")
    monkeypatch.setattr(
        sandbox_client_mod,
        "SANDBOX_RUNNER_UDS",
        "/tmp/shipit-pytest-no-sandbox-runner.sock",
    )
    monkeypatch.setattr(sandbox_client_mod, "SANDBOX_RUNNER_TOKEN", "")
    monkeypatch.setattr(
        sandbox_client_mod,
        "SANDBOX_RUNNER_VERIFICATION_TIMEOUT_S",
        960.0,
    )


def enable_monitoring(monkeypatch):
    """Opt this test into monitoring being on sale.

    MONITORING_FOR_SALE is False (#184): the price was a placeholder, the LLM
    spend was attributed to the anonymous bucket, and that bucket's cap stopped
    guarding anything once free audits went static-only. The machinery was NOT
    deleted, only withdrawn from sale, so its tests keep exercising it by
    flipping the flag.

    Every binding, because each module that imported the name holds its own
    reference and a test that patched only some of them would pass while the
    rest stayed off. Add a target here when a new module imports the flag.
    """
    for target in ("app.main.MONITORING_FOR_SALE",
                   "app.routes.paypal.MONITORING_FOR_SALE",
                   "app.billing.telegram_stars.MONITORING_FOR_SALE"):
        monkeypatch.setattr(target, True)


def force_pro_account(monkeypatch, account_id="11111111-1111-1111-1111-111111111111"):
    """Make requests in this test authenticate as a paying account.

    Patches resolve_account instead of wiring a real key and its HMAC: these
    tests are about what the scan and the cache do for a paying caller, and the
    free tier is static-only by policy, so without an account there is no LLM
    stage left to observe at all.

    Patched on app.accounts, the module that defines it, so this keeps working
    no matter which route module the calling handler lives in. Callers reach it
    as accounts.resolve_account(...) rather than importing the name.
    """
    async def _resolve(request, account_repo):
        return {"id": account_id, "tier": "pro"}

    monkeypatch.setattr("app.accounts.resolve_account", _resolve)
    return account_id
