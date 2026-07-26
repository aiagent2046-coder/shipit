"""Stage 4 step 2: enforcement (the control layer over step 1's accounting).

Five mechanisms, each an independent guard that must degrade honestly rather
than crash:
  * per-job cost cap -- the scan loop stops mid-way and returns a PARTIAL result
    flagged cost_cap_exceeded, never a 500;
  * anonymous daily $-cap -- once total free spend hits the ceiling, a new
    anonymous audit soft-degrades to static-only (no LLM row), not a 402/429;
  * pro accounts are NOT subject to that $-cap (only the call-count limit);
  * emergency stop -- a DB flag that 503s direct API calls and no-ops the
    monitoring drain, with a mandatory operator alert.

The $-cap guards are checked where the spend now happens -- in the worker, at
claim time, from the job's own account_id -- so those tests post to the endpoint
and then drain the queue. The emergency stop stays an endpoint test: it exists
to stop work from being ACCEPTED, and does that before anything is queued.

A fifth mechanism used to live here: an asyncio semaphore bounding concurrent
run_scan calls inside the API process. The queue cutover deleted it. The bound
that matters is now AUDIT_WORKER_CONCURRENCY, the worker's slot count (see
tests/test_audit_worker.py) -- a limit in a process that no longer runs scans
was bounding nothing.
"""

import io
import json
import uuid
import zipfile
from decimal import Decimal

from fastapi.testclient import TestClient

import app.main as main_mod
from app.llm.client import LLMClient, LLMUsage, Provider
from app.scan.llm_scan import run_llm_scan
from app.main import (
    app,
    get_account_repo,
    get_audit_repo,
    get_llm_client,
    get_llm_usage_repo,
    get_service_flags_repo,
    get_monitoring_repo,
    get_subscription_repo,
    get_repo_fetcher,
    get_billing_transport,
)
from tests.conftest import drain_audit_queue

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def _both_rubrics_zip() -> io.BytesIO:
    # Content hits BOTH the 'auth' (password/token) and 'security' (cors/env/sql)
    # keyword sets, so a normal scan makes two .complete() calls -- which is what
    # lets the cost cap prove it stopped early at one.
    return make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // token cors env sql query",
    })


class CountingLLM(LLMClient):
    """Records each .complete() call and returns a fixed usage. `per_call`
    tokens let a test drive the accumulated cost across the cap threshold."""

    def __init__(self, *, input_tokens: int, output_tokens: int,
                 model: str = "claude-sonnet-4.6"):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self.calls = 0
        self._in = input_tokens
        self._out = output_tokens
        self._model = model

    def complete(self, system, user, max_tokens=4096):
        self.calls += 1
        return "[]", LLMUsage(model=self._model,
                              input_tokens=self._in, output_tokens=self._out)


# --------------------------------------------------------------------------
# 1. Per-job cost cap: interrupts the loop, returns a partial result + flag.
# --------------------------------------------------------------------------

def test_cost_cap_interrupts_loop_and_flags_partial():
    # One call at 1,000,000 input tokens = exactly $3.00 = the cap, so the loop
    # stops after the FIRST rubric even though a second would otherwise run.
    llm = CountingLLM(input_tokens=1_000_000, output_tokens=0)
    _findings, stats = run_llm_scan(_both_rubrics_zip(), llm)
    assert llm.calls == 1                 # stopped before the second rubric
    assert stats.calls == 1
    assert stats.cost_cap_exceeded is True


def test_cost_cap_not_tripped_runs_full_scan():
    # Cheap calls never approach $3.00, so both rubrics run and the flag stays
    # down -- the cap must not fire on ordinary traffic.
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    _findings, stats = run_llm_scan(_both_rubrics_zip(), llm)
    assert llm.calls == 2
    assert stats.calls == 2
    assert stats.cost_cap_exceeded is False


# --------------------------------------------------------------------------
# Test doubles for the endpoint-level enforcement tests.
# --------------------------------------------------------------------------

class FakeAuditRepo:
    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, *, stack, file_count, score_total, score_json,
                     findings_json, repo_url=None, content_hash=None,
                     engine_version=None):
        row = {"id": str(uuid.uuid4()), "stack": stack, "status": "completed",
               "file_count": file_count, "score_total": score_total,
               "score_json": score_json, "findings_json": findings_json,
               "repo_url": repo_url, "content_hash": content_hash,
               "engine_version": engine_version, "access_token": "tok"}
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version):
        return None


class FakeUsageRepo:
    """Captures llm_usage writes and serves a controllable anon-spend total."""

    def __init__(self, anon_spend: Decimal | None = Decimal("0")):
        self.rows: list[dict] = []
        self._anon_spend = anon_spend
        self.sum_calls = 0

    async def create(self, **kwargs):
        self.rows.append(kwargs)
        return {"id": str(uuid.uuid4()), **kwargs}

    async def sum_anon_spend_today(self):
        self.sum_calls += 1
        return self._anon_spend


class FakeServiceFlagsRepo:
    def __init__(self, *, enabled=True, note=None):
        self.flag = {"key": "llm_paid_ops", "enabled": enabled, "note": note}
        self.set_calls: list[dict] = []

    async def get(self, key):
        return dict(self.flag) if key == "llm_paid_ops" else None

    async def set(self, key, *, enabled, note=None):
        self.set_calls.append({"key": key, "enabled": enabled, "note": note})
        self.flag = {"key": key, "enabled": enabled, "note": note}
        return dict(self.flag)


def _capture_alerts(monkeypatch):
    """Replace main.notify_operator with an async recorder. Returns the list of
    (text, dedupe_key) tuples it was called with."""
    sent: list[tuple[str, str | None]] = []

    async def fake_notify(text, *, dedupe_key=None, **kwargs):
        sent.append((text, dedupe_key))
        return True

    monkeypatch.setattr(main_mod, "notify_operator", fake_notify)
    return sent


def _auth_zip() -> io.BytesIO:
    return make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    })


def _clear():
    for dep in (get_audit_repo, get_llm_usage_repo, get_llm_client,
                get_account_repo, get_service_flags_repo):
        app.dependency_overrides.pop(dep, None)
    main_mod._reset_service_flag_cache()


def _reset_cache_before():
    main_mod._reset_service_flag_cache()


# --------------------------------------------------------------------------
# 2. Anonymous daily $-cap: soft-degrade to static-only, not an error.
# --------------------------------------------------------------------------

async def test_anon_daily_cap_soft_degrades_to_static_only(monkeypatch,
                                                           audit_queue):
    _reset_cache_before()
    _capture_alerts(monkeypatch)
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo(anon_spend=Decimal("2.50"))  # over the $2.00 cap
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        resp = client.post("/v1/audits",
                           files={"archive": ("app.zip", _auth_zip(), "application/zip")})
        await drain_audit_queue(audit_queue, audit_repo=audit_repo,
                                llm_client=llm, llm_usage_repo=usage_repo)
    finally:
        _clear()

    # Soft-degrade: the submission is still accepted and still produces a real
    # report -- the LLM stage is what gets dropped, not the audit.
    assert resp.status_code == 202
    assert audit_repo.rows[0]["score_json"]["basis"] == "static_only"
    assert llm.calls == 0                  # no LLM spend past the cap
    assert usage_repo.rows == []           # calls=0 -> no usage row


async def test_anon_under_cap_runs_llm(monkeypatch, audit_queue):
    _reset_cache_before()
    _capture_alerts(monkeypatch)
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo(anon_spend=Decimal("0.10"))  # well under cap
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        resp = client.post("/v1/audits",
                           files={"archive": ("app.zip", _auth_zip(), "application/zip")})
        await drain_audit_queue(audit_queue, audit_repo=audit_repo,
                                llm_client=llm, llm_usage_repo=usage_repo)
    finally:
        _clear()

    assert resp.status_code == 202
    assert audit_repo.rows[0]["score_json"]["basis"] == "static+llm"
    assert llm.calls == 1
    assert len(usage_repo.rows) == 1


# --------------------------------------------------------------------------
# 3. Pro accounts are NOT subject to the new $-cap.
# --------------------------------------------------------------------------

async def test_pro_account_not_subject_to_dollar_cap(monkeypatch, audit_queue):
    _reset_cache_before()
    _capture_alerts(monkeypatch)

    async def fake_resolve(request, account_repo):
        return {"id": str(uuid.uuid4()), "tier": "pro"}

    monkeypatch.setattr(main_mod, "resolve_account", fake_resolve)

    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo(anon_spend=Decimal("99.00"))  # anon is way over
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        resp = client.post("/v1/audits",
                           files={"archive": ("app.zip", _auth_zip(), "application/zip")},
                           headers={"Authorization": "Bearer sk_live_x"})
        # The API key is resolved at intake and its account stamped on the job;
        # that stamp is the only thing the worker has to go on later.
        assert audit_queue.only["account_id"] is not None
        await drain_audit_queue(audit_queue, audit_repo=audit_repo,
                                llm_client=llm, llm_usage_repo=usage_repo)
    finally:
        _clear()

    assert resp.status_code == 202
    # Pro ran the LLM despite anon spend being over the cap, and the anon
    # aggregate was never even consulted for a pro caller.
    assert llm.calls == 1
    assert usage_repo.sum_calls == 0
    assert len(usage_repo.rows) == 1
    assert usage_repo.rows[0]["account_id"] is not None


# --------------------------------------------------------------------------
# 4. Emergency stop: 503 for API, skip-drain for monitoring, mandatory alert.
# --------------------------------------------------------------------------

def test_emergency_stop_blocks_audit_with_503_and_alerts(monkeypatch):
    _reset_cache_before()
    alerts = _capture_alerts(monkeypatch)
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: FakeAuditRepo()
    app.dependency_overrides[get_llm_usage_repo] = lambda: FakeUsageRepo()
    app.dependency_overrides[get_llm_client] = lambda: llm
    app.dependency_overrides[get_service_flags_repo] = \
        lambda: FakeServiceFlagsRepo(enabled=False, note="paused by alice")
    try:
        resp = client.post("/v1/audits",
                           files={"archive": ("app.zip", _auth_zip(), "application/zip")})
    finally:
        _clear()

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["reason"] == "service_paused"
    assert detail["detail"] == "paused by alice"
    assert llm.calls == 0                   # nothing spent while paused
    # Mandatory operator alert fired on the emergency stop.
    assert any(k == "llm-paid-ops-paused" for _t, k in alerts)


def test_emergency_stop_not_engaged_allows_audit(monkeypatch, audit_queue):
    _reset_cache_before()
    _capture_alerts(monkeypatch)
    app.dependency_overrides[get_audit_repo] = lambda: FakeAuditRepo()
    app.dependency_overrides[get_service_flags_repo] = \
        lambda: FakeServiceFlagsRepo(enabled=True)
    try:
        resp = client.post("/v1/audits",
                           files={"archive": ("app.zip", _auth_zip(), "application/zip")})
    finally:
        _clear()

    # The mirror of the test above: with the stop off, the submission is
    # accepted and reaches the queue.
    assert resp.status_code == 202
    assert len(audit_queue.rows) == 1


class _FlagMonitoringRepo:
    """Fails loudly if the drain touches it while paused -- the monitoring flow
    must claim NOTHING when the emergency stop is engaged."""

    def __init__(self):
        self.claims = 0

    async def reap_stale_running(self, **kwargs):
        raise AssertionError("must not reap while paused")

    async def claim_one_pending(self):
        raise AssertionError("must not claim while paused")


def test_emergency_stop_skips_monitoring_drain(monkeypatch):
    _reset_cache_before()
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    _capture_alerts(monkeypatch)
    runs = _FlagMonitoringRepo()
    app.dependency_overrides[get_subscription_repo] = lambda: object()
    app.dependency_overrides[get_monitoring_repo] = lambda: runs
    app.dependency_overrides[get_audit_repo] = lambda: FakeAuditRepo()
    app.dependency_overrides[get_repo_fetcher] = lambda: (lambda o, r: b"zip")
    app.dependency_overrides[get_llm_client] = lambda: object()
    app.dependency_overrides[get_billing_transport] = lambda: object()
    app.dependency_overrides[get_service_flags_repo] = \
        lambda: FakeServiceFlagsRepo(enabled=False, note="maintenance")
    try:
        resp = client.post("/internal/monitoring/process-pending",
                           headers={"Authorization": "Bearer montoken"})
    finally:
        for dep in (get_subscription_repo, get_monitoring_repo, get_audit_repo,
                    get_repo_fetcher, get_llm_client, get_billing_transport,
                    get_service_flags_repo):
            app.dependency_overrides.pop(dep, None)
        main_mod._reset_service_flag_cache()

    assert resp.status_code == 200
    assert resp.json() == {"skipped_paused": True}
    assert runs.claims == 0


# --------------------------------------------------------------------------
# 5. The 80%-of-cap operator alert fires as spend approaches the ceiling.
# --------------------------------------------------------------------------

async def test_alert_fires_at_80_percent_of_daily_cap(monkeypatch, audit_queue):
    _reset_cache_before()
    alerts = _capture_alerts(monkeypatch)
    audit_repo = FakeAuditRepo()
    # $1.70 is 85% of the $2.00 cap: over the 80% alert line but under the cap,
    # so the LLM still runs AND the operator is warned.
    usage_repo = FakeUsageRepo(anon_spend=Decimal("1.70"))
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        client.post("/v1/audits",
                    files={"archive": ("app.zip", _auth_zip(), "application/zip")})
        await drain_audit_queue(audit_queue, audit_repo=audit_repo,
                                llm_client=llm, llm_usage_repo=usage_repo)
    finally:
        _clear()

    assert llm.calls == 1                                  # under cap: LLM ran
    assert any(k == "anon-budget-80" for _t, k in alerts)


# --------------------------------------------------------------------------
# Toggle endpoint auth + behaviour.
# --------------------------------------------------------------------------

def test_toggle_503_when_token_not_configured(monkeypatch):
    monkeypatch.delenv("SERVICE_FLAGS_TOKEN", raising=False)
    resp = client.post("/internal/service-flags/llm_paid_ops",
                       json={"enabled": False})
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "service_flags_not_configured"


def test_toggle_401_on_wrong_token(monkeypatch):
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flagtok")
    resp = client.post("/internal/service-flags/llm_paid_ops",
                       json={"enabled": False},
                       headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_toggle_sets_flag_and_alerts_on_disable(monkeypatch):
    _reset_cache_before()
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flagtok")
    alerts = _capture_alerts(monkeypatch)
    flags = FakeServiceFlagsRepo(enabled=True)
    app.dependency_overrides[get_service_flags_repo] = lambda: flags
    try:
        resp = client.post("/internal/service-flags/llm_paid_ops",
                           json={"enabled": False, "note": "incident 42"},
                           headers={"Authorization": "Bearer flagtok"})
    finally:
        app.dependency_overrides.pop(get_service_flags_repo, None)
        main_mod._reset_service_flag_cache()

    assert resp.status_code == 200
    assert resp.json() == {"key": "llm_paid_ops", "enabled": False,
                           "note": "incident 42"}
    assert flags.set_calls == [{"key": "llm_paid_ops", "enabled": False,
                                "note": "incident 42"}]
    assert any(k == "llm-paid-ops-paused" for _t, k in alerts)


def test_toggle_rejects_non_boolean_enabled(monkeypatch):
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flagtok")
    app.dependency_overrides[get_service_flags_repo] = \
        lambda: FakeServiceFlagsRepo(enabled=True)
    try:
        resp = client.post("/internal/service-flags/llm_paid_ops",
                           json={"enabled": "yes"},
                           headers={"Authorization": "Bearer flagtok"})
    finally:
        app.dependency_overrides.pop(get_service_flags_repo, None)
    assert resp.status_code == 422
