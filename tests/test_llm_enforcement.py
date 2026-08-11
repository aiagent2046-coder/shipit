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

import math
import io
import json
import uuid
import zipfile
from decimal import Decimal

from fastapi.testclient import TestClient

import app.main as main_mod
from app import accounts, alerts
from app.llm.client import LLMClient, LLMUsage, Provider
from app.scan.llm_scan import JOB_COST_CAP_USD, run_llm_scan
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
from app.scan.pipeline import AUDIT_ENGINE_VERSION, content_digest
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
    # Derived from the cap, not from a hardcoded dollar figure. Written as
    # "1,000,000 input tokens = exactly $3.00 = the cap", this test broke the
    # moment the cap moved -- reporting a raised constant as a broken guard,
    # which is the one failure that teaches an author to weaken the guard. What
    # it means to assert is that the loop stops once spend reaches the cap,
    # whatever the cap is: input is $3.00/MTok, so that is one call of
    # cap/3.00 million tokens.
    # Rounded UP, not truncated. int() was exact while the cap was 6.00 --
    # 2,000,000 tokens on the nose -- and silently wrong at 6.50, where
    # 2,166,666.67 truncates to a call costing a fraction of a cent less than
    # the cap, so the loop was right to make a second one and the test failed
    # for arithmetic rather than for behaviour. The intent is "one call that
    # reaches the cap", which is a ceiling for any cap that is not a multiple
    # of the per-token price.
    at_the_cap = math.ceil(JOB_COST_CAP_USD / Decimal("3.00") * 1_000_000)
    llm = CountingLLM(input_tokens=at_the_cap, output_tokens=0)
    _findings, stats = run_llm_scan(_both_rubrics_zip(), llm)
    assert llm.calls == 1                 # stopped before the second rubric
    assert stats.calls == 1
    assert stats.cost_cap_exceeded is True


def test_cost_cap_not_tripped_runs_full_scan():
    # Cheap calls never approach the cap, so both rubrics run and the flag stays
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
        self.basis_queries: list[str] = []

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

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        # Honours basis, like the real repository: a fake that ignored it would
        # make the pricing-boundary test below pass vacuously.
        self.basis_queries.append(basis)
        return next(
            (r for r in self.rows
             if r["content_hash"] == content_hash
             and r["engine_version"] == engine_version
             and (r["score_json"] or {}).get("basis") == basis),
            None,
        )


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

    monkeypatch.setattr(alerts, "notify_operator", fake_notify)
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

    # Still accepted, still a real report -- the LLM stage is what is absent.
    # Note the cap is no longer what causes this: anonymous audits are
    # static-only at any spend level (see the test below). This case is kept
    # because being over the cap must not break the audit either.
    assert resp.status_code == 202
    assert audit_repo.rows[0]["score_json"]["basis"] == "static_only"
    assert llm.calls == 0                  # no LLM spend past the cap
    assert usage_repo.rows == []           # calls=0 -> no usage row


async def test_anon_is_static_only_even_far_under_the_cap(monkeypatch,
                                                          audit_queue):
    """The free tier is static-only by policy, not because money ran out.

    This used to assert the opposite -- an anonymous audit under the cap ran the
    LLM. The product changed: the static rules and secret scanning are free to
    run and are what find committed credentials, while the auth and injection
    rubrics are the paid depth. Spend is now irrelevant to this decision, which
    is why the budget here is nearly untouched and the LLM still never runs.
    """
    _reset_cache_before()
    _capture_alerts(monkeypatch)
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo(anon_spend=Decimal("0.10"))  # nowhere near it
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
    assert audit_repo.rows[0]["score_json"]["basis"] == "static_only"
    assert llm.calls == 0
    assert usage_repo.rows == []


# --------------------------------------------------------------------------
# 3. Pro accounts are NOT subject to the new $-cap.
# --------------------------------------------------------------------------

async def test_pro_account_not_subject_to_dollar_cap(monkeypatch, audit_queue):
    _reset_cache_before()
    _capture_alerts(monkeypatch)

    async def fake_resolve(request, account_repo):
        return {"id": str(uuid.uuid4()), "tier": "pro"}

    monkeypatch.setattr(accounts, "resolve_account", fake_resolve)

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

    # The LLM does not run for an anonymous caller at any spend level, but the
    # operator alert must still fire: monitoring re-audits write usage rows with
    # a null account_id and never consult this cap, so this is the only warning
    # that anonymous-attributed spend is climbing.
    assert llm.calls == 0
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


async def test_anonymous_caller_is_not_served_a_paid_audit_from_the_cache(
    monkeypatch, audit_queue
):
    """The content-hash cache must not cross the pricing boundary.

    Before the scan depth became part of the cache key, a repository that a
    paying account had already audited would be handed to the next anonymous
    visitor complete with its LLM findings and its score: the paid product,
    free, with nothing in the logs to notice. The mirror case is as bad -- a
    payer served a free static-only row.
    """
    _reset_cache_before()
    _capture_alerts(monkeypatch)
    raw = _auth_zip().getvalue()
    audit_repo = FakeAuditRepo()
    # Exactly what a paying account's audit of this content would have left.
    await audit_repo.create(
        stack="nextjs", file_count=2, score_total=4.2,
        score_json={"total": 4.2, "categories": {}, "basis": "static+llm"},
        findings_json=[{"rule_id": "llm-auth", "title": "paid-only finding",
                        "severity": "high", "confidence": 0.9,
                        "category": "Auth"}],
        content_hash=content_digest(raw), engine_version=AUDIT_ENGINE_VERSION,
    )
    llm = CountingLLM(input_tokens=1000, output_tokens=200)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", io.BytesIO(raw), "application/zip")},
        )
        await drain_audit_queue(audit_queue, audit_repo=audit_repo,
                                llm_client=llm)
    finally:
        _clear()

    assert resp.status_code == 202
    # Asked only for free depth, never for the paid row.
    assert audit_repo.basis_queries
    assert set(audit_repo.basis_queries) == {"static_only"}
    # A second row, scanned fresh at free depth, rather than the seeded one.
    assert len(audit_repo.rows) == 2
    fresh = audit_repo.rows[1]
    assert fresh["score_json"]["basis"] == "static_only"
    assert not any((f.get("rule_id") or "").startswith("llm-")
                   for f in fresh["findings_json"])
    assert llm.calls == 0


def test_the_cost_cap_sits_above_what_a_full_scan_is_meant_to_spend():
    """The cap is a backstop against a runaway loop, not a budget.

    If it sits below the intended cost of a scan, every large-repo Fix Pack
    stops mid-way and returns a partial result flagged cost_cap_exceeded --
    silently, and only on the product that was paid for. That is not
    hypothetical: raising MAX_TOTAL_CHARS to 900_000 while leaving the cap at
    $3.00 does exactly this, and no other test notices, because the cap tests
    derive their token counts FROM the cap and so move with it.

    Priced from app/llm/pricing.py so a price rise fails here rather than in
    production. Output is bounded by the 8192 max_tokens each call requests.
    """
    from app.llm.client import DEFAULT_MODEL
    from app.llm.pricing import cost_usd
    from app.scan.llm_scan import MAX_TOTAL_CHARS, RUBRICS

    # A deliberate 2x safety factor, NOT a description of anything that runs.
    # It used to say "what a Fix Pack runs", and that was wrong and expensively
    # so: nothing in the codebase passes `passes=2`. run_scan is only ever
    # called with llm_passes=1, and a Fix Pack's deep review is a second
    # single-pass audit through run_repo_audit, with its own cap.
    #
    # Reading this comment as fact produced a cost analysis off by double --
    # "$6.38 per Fix Pack" against a $10 price, when the real per-scan ceiling
    # is four calls and $3.19, with $3.53 the worst ever measured. Kept at 2
    # anyway: a cap has to sit above the intended cost with room, and doubling
    # here is what stops someone lowering JOB_COST_CAP_USD to just above
    # today's traffic.
    passes = 2
    calls = len(RUBRICS) * passes
    # ~4 characters per token is the standard rough conversion; the point is
    # the order of magnitude, not a token-exact figure.
    worst_case = cost_usd(DEFAULT_MODEL,
                          input_tokens=MAX_TOTAL_CHARS // 4 * calls,
                          output_tokens=8192 * calls)

    assert JOB_COST_CAP_USD > worst_case, (
        f"JOB_COST_CAP_USD is {JOB_COST_CAP_USD}, but a two-pass scan at "
        f"MAX_TOTAL_CHARS={MAX_TOTAL_CHARS:,} costs about {worst_case:.2f}. "
        "Every Fix Pack on a large repository would stop mid-scan and return "
        "a partial result. Raise the cap, or lower the budget."
    )
