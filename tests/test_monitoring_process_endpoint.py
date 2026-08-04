"""Tests for POST /internal/monitoring/process-pending — the scheduled
processor that drains the continuous-monitoring backlog.

This is the SLOW half of Phase C monitoring, moved off the GitHub push
webhook (see MONITORING_ASYNC_PLAN.md and tests/test_monitoring.py, which
now only covers the fast enqueue). The audit itself (run_repo_audit) is
monkeypatched so the suite never fetches a repo, runs an LLM, or touches a
database — the focus here is the processor's diff + notify + durable-lease
behaviour, mirroring tests/test_fixpack_process_endpoint.py.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

import app.main as main_mod
from app.ingest.github_fetch import RepoFetchError
from app.main import (
    app,
    get_audit_repo,
    get_billing_transport,
    get_llm_client,
    get_monitoring_repo,
    get_repo_fetcher,
    get_subscription_repo,
)

client = TestClient(app)


def _f(rule_id, file, severity, line=1):
    return {"rule_id": rule_id, "file": file, "severity": severity, "line": line}


class FakeSubscriptionRepo:
    def __init__(self, subs):
        self._subs = subs

    async def list_active_for_repo(self, repo_full_name):
        return [s for s in self._subs if s.get("repo_full_name") == repo_full_name]


class FakeAuditRepo:
    def __init__(self, previous=None):
        self._previous = previous

    async def get_latest_by_repo_url(self, repo_full_name, basis):
        return self._previous


class FakeMonitoringRepo:
    """Stateful lease model so reap + claim behave like the real Postgres
    primitives: runs carry status/attempts, and `age_minutes` stands in for how
    long ago a 'running' lease was taken. One processor pass reaps stale leases,
    then claims each 'pending' run exactly once into 'running'. Mirrors
    LeaseFixpackRepo in tests/test_fixpack_process_endpoint.py."""

    def __init__(self, runs):
        self.runs = {r["id"]: dict(r) for r in runs}
        self.order = [r["id"] for r in runs]
        self.claims = 0

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        requeued = failed = 0
        for r in self.runs.values():
            if r["status"] == "running" and r.get("age_minutes", 0) >= max_age_minutes:
                if r["attempts"] < max_attempts:
                    r["status"], r["age_minutes"] = "pending", 0
                    requeued += 1
                else:
                    r["status"], r["error"] = "failed", "stale lease reaped"
                    failed += 1
        return {"requeued": requeued, "failed": failed}

    async def claim_one_pending(self):
        for rid in self.order:
            r = self.runs[rid]
            if r["status"] == "pending":
                r["status"], r["age_minutes"] = "running", 0
                r["attempts"] += 1
                self.claims += 1
                return dict(r)
        return None

    async def mark_done(self, run_id):
        self.runs[run_id]["status"] = "done"

    async def mark_failed(self, run_id, error):
        self.runs[run_id]["status"] = "failed"
        self.runs[run_id]["error"] = error


def _run(repo="acme/app", *, status="pending", attempts=0, age_minutes=0):
    return {"id": "run-1", "repo_full_name": repo, "status": status,
            "attempts": attempts, "age_minutes": age_minutes, "error": None}


def _override(*, subscription_repo, monitoring_repo, audit_repo):
    app.dependency_overrides[get_subscription_repo] = lambda: subscription_repo
    app.dependency_overrides[get_monitoring_repo] = lambda: monitoring_repo
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    app.dependency_overrides[get_repo_fetcher] = lambda: (lambda o, r: b"zip")
    app.dependency_overrides[get_llm_client] = lambda: object()
    app.dependency_overrides[get_billing_transport] = lambda: object()


def _clear():
    for dep in (get_subscription_repo, get_monitoring_repo, get_audit_repo,
                get_repo_fetcher, get_llm_client, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def _capture_dms(monkeypatch):
    sent = []

    async def fake_send(chat_id, text, *, token, transport=None, reply_markup=None):
        sent.append((str(chat_id), text))
        return {"ok": True}

    monkeypatch.setattr(main_mod.telegram_stars, "send_message", fake_send)
    monkeypatch.setattr(main_mod.telegram_stars, "bot_token_from_env",
                        lambda: "bot-token")
    return sent


def _audit_returns(monkeypatch, findings):
    async def fake_audit(repo_url, *, llm_client, audit_repo, repo_fetcher,
                         llm_usage_repo=None, job_type="audit"):
        return {"audit_id": "a-new", "findings": findings,
                "repo_url": repo_url, "reused": False}

    monkeypatch.setattr(main_mod, "run_repo_audit", fake_audit)


def _audit_raises(monkeypatch, exc):
    async def fake_audit(repo_url, *, llm_client, audit_repo, repo_fetcher,
                         llm_usage_repo=None, job_type="audit"):
        raise exc

    monkeypatch.setattr(main_mod, "run_repo_audit", fake_audit)


def auth(token="montoken"):
    return {"Authorization": f"Bearer {token}"}


# --- auth / configuration guards ------------------------------------------

def test_503_when_token_not_configured(monkeypatch):
    monkeypatch.delenv("MONITORING_PROCESS_TOKEN", raising=False)
    resp = client.post("/internal/monitoring/process-pending")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "monitoring_process_not_configured"


def test_401_when_no_auth_header(monkeypatch):
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    resp = client.post("/internal/monitoring/process-pending")
    assert resp.status_code == 401


def test_401_when_wrong_token(monkeypatch):
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    resp = client.post("/internal/monitoring/process-pending", headers=auth("nope"))
    assert resp.status_code == 401


# --- the happy path: audit + diff + notify --------------------------------

def test_new_critical_notifies_all_subscribers(monkeypatch):
    """A pending run re-audits, diffs against the baseline (r1), finds a new
    critical (r2), DMs every active subscriber, and marks the run done."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    sent = _capture_dms(monkeypatch)
    _audit_returns(monkeypatch, [_f("r1", "a.py", "critical"),
                                 _f("r2", "b.py", "critical")])

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
        {"repo_full_name": "acme/app", "telegram_chat_id": "222",
         "telegram_user_id": "222"},
    ])
    audits = FakeAuditRepo(previous={"findings_json": [_f("r1", "a.py", "critical")]})
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs, audit_repo=audits)
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json() == {
        "processed": 1, "notified": 1, "no_new": 0, "unfetchable": 0,
        "unauditable": 0, "no_subscription": 0, "failed": 0, "requeued": 0,
    }
    assert len(sent) == 2                        # both subscribers DM'd
    assert "b.py" in sent[0][1] and "r2" in sent[0][1]
    assert runs.runs["run-1"]["status"] == "done"
    assert runs.claims == 1                       # leased 'pending' -> 'running' once


def test_no_new_findings_is_silent(monkeypatch):
    """Re-audit surfaces the same findings as the baseline (only line drift) ->
    nothing new -> no DM, run still closed out as done."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    sent = _capture_dms(monkeypatch)
    _audit_returns(monkeypatch, [_f("r1", "a.py", "critical", line=99)])

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
    ])
    audits = FakeAuditRepo(previous={"findings_json": [_f("r1", "a.py", "critical", line=1)]})
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs, audit_repo=audits)
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["no_new"] == 1
    assert resp.json()["notified"] == 0
    assert sent == []
    assert runs.runs["run-1"]["status"] == "done"


def test_unfetchable_repo_is_benign_done(monkeypatch):
    """Repo went private/deleted (RepoFetchError) -> benign terminal 'done',
    counted as unfetchable, no DM."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    sent = _capture_dms(monkeypatch)
    _audit_raises(monkeypatch, RepoFetchError("404"))

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
    ])
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["unfetchable"] == 1
    assert resp.json()["failed"] == 0
    assert sent == []
    assert runs.runs["run-1"]["status"] == "done"


def test_unauditable_repo_is_benign_done(monkeypatch):
    """run_repo_audit returns None (unsupported stack / bad zip) -> benign
    terminal 'done', counted as unauditable."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    _capture_dms(monkeypatch)

    async def fake_audit(repo_url, *, llm_client, audit_repo, repo_fetcher,
                         llm_usage_repo=None, job_type="audit"):
        return None

    monkeypatch.setattr(main_mod, "run_repo_audit", fake_audit)

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
    ])
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["unauditable"] == 1
    assert runs.runs["run-1"]["status"] == "done"


def test_no_subscription_at_process_time_is_benign(monkeypatch):
    """Every subscription lapsed between enqueue and processing -> nothing to
    notify. The audit is never even run; the run is closed out as done."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    _capture_dms(monkeypatch)

    async def boom(*a, **k):
        raise AssertionError("must not audit when there are no subscribers")

    monkeypatch.setattr(main_mod, "run_repo_audit", boom)

    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=FakeSubscriptionRepo([]), monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["no_subscription"] == 1
    assert runs.runs["run-1"]["status"] == "done"


# --- observability: a failed run must never be silent ---------------------

def test_unexpected_error_marks_failed_with_detail_and_logs(monkeypatch, caplog):
    """Regression guard mirroring the Fix Pack silent-failure hardening: an
    unexpected error during processing must land the run on 'failed' with a
    diagnosable error AND log a full traceback — never a silent 'failed' row."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    _capture_dms(monkeypatch)
    _audit_raises(monkeypatch, RuntimeError("scan blew up: boom"))

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
    ])
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        with caplog.at_level("ERROR"):
            resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["failed"] == 1
    assert runs.runs["run-1"]["status"] == "failed"
    error = runs.runs["run-1"]["error"]
    assert error and "RuntimeError" in error and "boom" in error
    assert any(
        rec.exc_info is not None and "run-1" in rec.getMessage()
        for rec in caplog.records
    )


def test_one_bad_dm_does_not_abort_the_rest(monkeypatch):
    """A single failing subscriber DM must not abort the run: the other
    subscriber is still notified and the run lands on 'done', not 'failed'."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    _audit_returns(monkeypatch, [_f("r2", "b.py", "critical")])
    monkeypatch.setattr(main_mod.telegram_stars, "bot_token_from_env",
                        lambda: "bot-token")

    delivered = []

    async def flaky_send(chat_id, text, *, token, transport=None, reply_markup=None):
        if str(chat_id) == "111":
            raise RuntimeError("telegram 403 blocked")
        delivered.append(str(chat_id))
        return {"ok": True}

    monkeypatch.setattr(main_mod.telegram_stars, "send_message", flaky_send)

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
        {"repo_full_name": "acme/app", "telegram_chat_id": "222",
         "telegram_user_id": "222"},
    ])
    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=subs, monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json()["notified"] == 1          # the run itself counts as notified
    assert delivered == ["222"]                  # the good DM still went out
    assert runs.runs["run-1"]["status"] == "done"


# --- durable lease / restart recovery -------------------------------------

def test_claim_hands_back_each_run_once():
    """The atomic-claim contract that stops double-processing: once a 'pending'
    run is claimed it is 'running', so a second claim returns None."""
    repo = FakeMonitoringRepo([_run()])
    first = asyncio.run(repo.claim_one_pending())
    second = asyncio.run(repo.claim_one_pending())
    assert first is not None and first["id"] == "run-1"
    assert first["status"] == "running"
    assert second is None
    assert repo.claims == 1


def test_stale_running_run_requeued_then_delivered_once(monkeypatch):
    """Restart recovery without a duplicate notify: a run left 'running' by a
    crashed worker (old lease, attempts < MAX) is reaped back to 'pending',
    re-claimed, audited, and delivered — DMs fire exactly once."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    sent = _capture_dms(monkeypatch)
    _audit_returns(monkeypatch, [_f("r2", "b.py", "critical")])

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111"},
    ])
    # lease taken 30m ago (> 15m stale threshold), one prior attempt.
    runs = FakeMonitoringRepo([_run(status="running", attempts=1, age_minutes=30)])
    _override(subscription_repo=subs, monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    body = resp.json()
    assert body["requeued"] == 1                 # stale lease recovered
    assert body["notified"] == 1
    assert body["processed"] == 1
    assert len(sent) == 1                        # exactly ONE DM despite the crash
    assert runs.runs["run-1"]["status"] == "done"
    assert runs.runs["run-1"]["attempts"] == 2   # one retry after the crash


def test_poison_pill_fails_after_max_attempts(monkeypatch):
    """A run that has already exhausted its attempts and is found stale is
    failed (not re-queued forever) — bounded retries. No audit, no DM."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    sent = _capture_dms(monkeypatch)

    async def boom(*a, **k):
        raise AssertionError("a poison-pill run must not be re-audited")

    monkeypatch.setattr(main_mod, "run_repo_audit", boom)

    runs = FakeMonitoringRepo([_run(status="running", attempts=3, age_minutes=30)])
    _override(subscription_repo=FakeSubscriptionRepo([]), monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    body = resp.json()
    assert body["failed"] == 1
    assert body["processed"] == 0                # nothing left to claim
    assert sent == []
    assert runs.runs["run-1"]["status"] == "failed"


def test_no_pending_runs_returns_zero_summary(monkeypatch):
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")
    runs = FakeMonitoringRepo([])
    _override(subscription_repo=FakeSubscriptionRepo([]), monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json() == {
        "processed": 0, "notified": 0, "no_new": 0, "unfetchable": 0,
        "unauditable": 0, "no_subscription": 0, "failed": 0, "requeued": 0,
    }


def test_lock_busy_returns_skipped_locked(monkeypatch):
    """When another run already holds the advisory lock, the processor does no
    work and reports skipped_locked rather than stampeding the backlog."""
    monkeypatch.setenv("MONITORING_PROCESS_TOKEN", "montoken")

    @asynccontextmanager
    async def busy_lock():
        raise main_mod.ProcessorLockBusy()
        yield  # unreachable, keeps this a valid async context manager

    monkeypatch.setattr(main_mod, "monitoring_processor_lock", busy_lock)

    runs = FakeMonitoringRepo([_run()])
    _override(subscription_repo=FakeSubscriptionRepo([]), monitoring_repo=runs,
              audit_repo=FakeAuditRepo(previous=None))
    try:
        resp = client.post("/internal/monitoring/process-pending", headers=auth())
    finally:
        _clear()

    assert resp.json() == {"skipped_locked": True}
    assert runs.claims == 0                       # nothing claimed/processed
