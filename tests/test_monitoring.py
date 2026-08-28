"""Phase C continuous monitoring.

Three layers, all in-memory (no DB, no network):

  1. new_high_severity_findings -- the pure diff: which critical/high findings
     are new since the previous audit. Covers the deliberate design choices
     (line-drift is NOT a new finding; a medium->high re-score is NOT flagged).
  2. normalize_repo_full_name -- the SINGLE normalization both the push webhook
     and the stored audit route through. A dedicated test (the founder's
     explicit ask): a push payload's `owner/repo` and an audit's full repo_url
     must resolve to the same key across casing, a trailing '.git', and a
     trailing slash, or the whole diff is silently buried.
  3. POST /v1/webhooks/github `push` event -- now the FAST half only (see
     MONITORING_ASYNC_PLAN.md): (a) no active subscription -> no enqueue;
     (b) inside the monitoring interval -> no enqueue; (c) eligible -> claim
     + enqueue one 'pending'
     run + ACK 200, with run_repo_audit booby-trapped to prove the audit never
     runs on the HTTP path. The slow half (audit + diff + notify) is covered in
     tests/test_monitoring_process_endpoint.py. Re-uses the same TestClient +
     dependency-override pattern as tests/test_fix_outcomes.py.
"""

import datetime
import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import app.main as main_mod
from app.monitor import (
    MONITORING_INTERVAL_HOURS,
    normalize_repo_full_name,
    repo_url_from_full_name,
)
from app.monitor.diff import new_high_severity_findings
from app.main import (
    app,
    get_monitoring_repo,
    get_subscription_repo,
)
from tests.conftest import enable_monitoring

client = TestClient(app)


# --- 1. the diff -----------------------------------------------------------

def _f(rule_id, file, severity, line=1):
    return {"rule_id": rule_id, "file": file, "severity": severity, "line": line}


def test_diff_all_new_when_no_previous():
    current = [_f("r1", "a.py", "critical"), _f("r2", "b.py", "high")]
    new = new_high_severity_findings(None, current)
    assert {(f["rule_id"], f["file"]) for f in new} == {("r1", "a.py"), ("r2", "b.py")}


def test_diff_ignores_medium_and_low():
    current = [_f("r1", "a.py", "medium"), _f("r2", "b.py", "low"),
               _f("r3", "c.py", "high")]
    new = new_high_severity_findings([], current)
    assert [f["rule_id"] for f in new] == ["r3"]


def test_diff_line_drift_is_not_new():
    # Same (rule_id, file), different line -> the finding moved because unrelated
    # code shifted above it. Must NOT be reported as new.
    previous = [_f("r1", "a.py", "critical", line=10)]
    current = [_f("r1", "a.py", "critical", line=42)]
    assert new_high_severity_findings(previous, current) == []


def test_diff_medium_to_high_rescore_is_not_new():
    # Same (rule_id, file) that was medium before and high now: a re-score of the
    # SAME issue, not a new one. Severity-escalation alerts are a deliberate
    # non-goal of the MVP.
    previous = [_f("r1", "a.py", "medium")]
    current = [_f("r1", "a.py", "high")]
    assert new_high_severity_findings(previous, current) == []


def test_diff_genuinely_new_high_is_reported():
    previous = [_f("r1", "a.py", "critical")]
    current = [_f("r1", "a.py", "critical"), _f("r2", "b.py", "high")]
    new = new_high_severity_findings(previous, current)
    assert [(f["rule_id"], f["file"]) for f in new] == [("r2", "b.py")]


# --- 2. normalization (founder's explicit dedicated test) ------------------

def test_normalization_push_name_and_repo_url_agree_across_variants():
    """The push side receives `owner/repo`; the stored audit side has a full
    URL. Every casing/.git/trailing-slash variant of BOTH must collapse to one
    canonical key, and the two sides must agree -- otherwise the push and its
    diff baseline never join and the alert is silently lost."""
    canonical = "acme/app"

    # What a push payload's repository.full_name might look like.
    push_variants = ["acme/app", "Acme/App", "ACME/APP", "acme/app/"]
    # What audits.repo_url might have been stored as at intake.
    url_variants = [
        "https://github.com/acme/app",
        "https://github.com/Acme/App",
        "https://github.com/acme/app.git",
        "https://github.com/acme/app/",
        "https://github.com/ACME/APP.git/",
    ]

    for v in push_variants:
        assert normalize_repo_full_name(v) == canonical, v
    for v in url_variants:
        assert normalize_repo_full_name(v) == canonical, v

    # And the round trip is stable: full_name -> url -> full_name.
    assert normalize_repo_full_name(repo_url_from_full_name(canonical)) == canonical


def test_normalization_rejects_unparseable():
    for bad in [None, "", "not-a-repo", "https://gitlab.com/a/b",
                "https://github.com/only-one-segment", "a/b/c"]:
        assert normalize_repo_full_name(bad) is None, bad


# --- 3. the push webhook end-to-end ----------------------------------------

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _push_payload(*, full_name="acme/app", default_branch="main",
                  ref="refs/heads/main") -> bytes:
    return json.dumps({
        "ref": ref,
        "repository": {
            "full_name": full_name,
            "default_branch": default_branch,
            "html_url": f"https://github.com/{full_name}",
        },
    }).encode()


def _post_push(body: bytes, *, secret="whsecret"):
    return client.post(
        "/v1/webhooks/github", content=body,
        headers={"X-Hub-Signature-256": _sign(secret, body),
                 "X-GitHub-Event": "push"},
    )


class FakeSubscriptionRepo:
    def __init__(self, subs):
        self._subs = subs
        self.claims: list[tuple[str, datetime.datetime]] = []

    async def list_active_for_repo(self, repo_full_name):
        return [s for s in self._subs if s.get("repo_full_name") == repo_full_name]

    async def claim_for_monitoring(self, repo_full_name, at):
        # Mirrors the real conditional UPDATE...RETURNING: eligible iff no row
        # for this repo was monitored within MONITORING_INTERVAL_HOURS. On
        # success stamps all the repo's rows and reports the win; otherwise
        # no-op and reports the loss.
        #
        # The interval is READ from the constant, not written out again. This
        # fake used to hardcode 24 beside a `interval '24 hours'` literal in
        # app/db.py, so the two agreed only by coincidence -- widening one
        # would have left this whole file green while production kept the old
        # cap. tests/test_db_postgres_smoke.py checks the SQL itself.
        rows = [s for s in self._subs if s.get("repo_full_name") == repo_full_name]
        cutoff = at - datetime.timedelta(hours=MONITORING_INTERVAL_HOURS)
        recent = any(
            s.get("last_monitored_at") is not None and s["last_monitored_at"] >= cutoff
            for s in rows
        )
        if recent:
            return False
        for s in rows:
            s["last_monitored_at"] = at
        self.claims.append((repo_full_name, at))
        return True


class FakeMonitoringRepo:
    """In-memory stand-in for MonitoringRunRepository. The webhook only touches
    enqueue: it records each 'pending' run so a test can assert the push
    enqueued exactly one (or zero) run without any audit."""

    def __init__(self):
        self.enqueued: list[str] = []

    async def enqueue(self, repo_full_name):
        run_id = f"run-{len(self.enqueued) + 1}"
        self.enqueued.append(repo_full_name)
        return {"id": run_id, "repo_full_name": repo_full_name,
                "status": "pending"}


def _fail_if_audited(monkeypatch):
    """Assert the fast webhook path never runs the audit: run_repo_audit is the
    slow work that moved to the processor, so a call from the webhook is a bug."""
    async def _boom(*a, **k):
        raise AssertionError("run_repo_audit must NOT run on the webhook path")

    monkeypatch.setattr(main_mod, "run_repo_audit", _boom)


def _override(*, subscription_repo, monitoring_repo):
    app.dependency_overrides[get_subscription_repo] = lambda: subscription_repo
    app.dependency_overrides[get_monitoring_repo] = lambda: monitoring_repo


def _clear():
    for dep in (get_subscription_repo, get_monitoring_repo):
        app.dependency_overrides.pop(dep, None)


def test_push_scenario_a_no_subscription_no_enqueue(monkeypatch):
    enable_monitoring(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    subs = FakeSubscriptionRepo([])  # nobody subscribed to acme/app
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json()["reason"] == "no_active_subscription"
    assert runs.enqueued == []        # nothing queued
    assert subs.claims == []          # nothing claimed/stamped


def _push_with_last_monitored(monkeypatch, hours_ago: float):
    """One push against a subscription last monitored `hours_ago`. Returns
    (response json, FakeMonitoringRepo) so a caller can assert both the reason
    and whether anything was actually queued."""
    enable_monitoring(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    then = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=hours_ago))
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": then},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()
    return resp.json(), runs


def test_push_scenario_b_inside_the_interval_no_enqueue(monkeypatch):
    body, runs = _push_with_last_monitored(monkeypatch, hours_ago=1)

    assert body["reason"] == "within_interval"
    assert runs.enqueued == []    # the interval gate blocked the enqueue


def test_a_push_two_days_after_the_last_run_is_still_blocked(monkeypatch):
    """The behaviour the widening to 72h actually buys, stated as a number.

    Under the old `interval '24 hours'` a push 48 hours after the last run was
    eligible and cost another full-repository audit -- a monitoring run is
    run_repo_audit with run_scan's defaults, one pass over all four rubrics,
    median $0.96 across the 21 measured production runs of the four-call era.
    This is the case that now costs nothing.

    Written against the constant rather than a bare 48 so it keeps testing the
    boundary if the interval moves again -- a hardcoded 48 would silently stop
    meaning "inside the window" the moment somebody set 24 back.
    """
    inside = MONITORING_INTERVAL_HOURS - 24
    assert inside > 24, (
        "this test only says something while the interval is wider than a day")

    body, runs = _push_with_last_monitored(monkeypatch, hours_ago=inside)

    assert body["reason"] == "within_interval"
    assert runs.enqueued == []


def test_a_push_past_the_interval_is_eligible_again(monkeypatch):
    """The other side of the same boundary: the gate delays runs, it does not
    stop them. Without this, setting the interval to a century would pass."""
    body, runs = _push_with_last_monitored(
        monkeypatch, hours_ago=MONITORING_INTERVAL_HOURS + 1)

    assert body["queued"] is True
    assert runs.enqueued == ["acme/app"]


def test_push_eligible_enqueues_and_acks_fast(monkeypatch):
    """The core async change: an eligible push claims the repo and enqueues a
    single 'pending' run, then ACKs 200 immediately -- no audit, no diff, no DM
    on the HTTP path (run_repo_audit is booby-trapped to fail if called). The
    real work is drained later by /internal/monitoring/process-pending."""
    enable_monitoring(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    # Past the interval, derived rather than written out: this fixture was a
    # bare `days=2`, which stopped meaning "eligible" the moment the interval
    # went past 48 hours.
    old = (datetime.datetime.now(datetime.timezone.utc)
           - datetime.timedelta(hours=MONITORING_INTERVAL_HOURS + 1))
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": old},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    body = resp.json()
    assert body["queued"] is True
    assert body["repo_full_name"] == "acme/app"
    assert body["run_id"] == "run-1"
    assert runs.enqueued == ["acme/app"]         # exactly one run queued
    assert len(subs.claims) == 1 and subs.claims[0][0] == "acme/app"


def test_push_does_not_enqueue_while_monitoring_is_withdrawn(monkeypatch):
    """The test that makes #184 actually closed. Note what this fixture is: an
    ACTIVE subscription, last monitored past the interval, on a default-branch
    push -- the exact shape that enqueues in
    test_push_eligible_enqueues_and_acks_fast above. Gating only the sale
    surfaces would leave this row auditing on every push, at full LLM cost,
    attributed to the anonymous bucket. So the check sits before the
    subscription lookup and nothing is queued or claimed.

    Deliberately no enable_monitoring(): this test asserts the shipped default.
    """
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    old = (datetime.datetime.now(datetime.timezone.utc)
           - datetime.timedelta(hours=MONITORING_INTERVAL_HOURS + 1))
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": old},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    assert resp.status_code == 200          # still ACK, GitHub must not retry
    body = resp.json()
    assert body["ignored"] is True
    assert body["reason"] == "monitoring_not_for_sale"
    assert runs.enqueued == []              # no run, so no LLM spend
    assert subs.claims == []                # and the 24h claim is untouched


def test_push_non_default_branch_ignored(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": None},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        resp = _post_push(_push_payload(ref="refs/heads/feature-x"))
    finally:
        _clear()

    assert resp.json()["reason"] == "not_default_branch"
    assert runs.enqueued == []
    assert subs.claims == []


def test_push_repo_matched_case_insensitively(monkeypatch):
    """The founder's concern, exercised end-to-end: a push whose repository name
    is differently-cased than the stored subscription still matches and enqueues
    under the canonical name. (list_active_for_repo is keyed on the normalized
    name, so the push side must normalize identically.)"""
    enable_monitoring(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": None},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        # Push payload carries mixed-case owner/repo.
        resp = _post_push(_push_payload(full_name="Acme/App"))
    finally:
        _clear()

    body = resp.json()
    assert body["queued"] is True
    assert runs.enqueued == ["acme/app"]         # canonical, not "Acme/App"


def test_push_second_push_inside_the_interval_is_claimed_out(monkeypatch):
    """The atomic-claim guard, end-to-end: two back-to-back pushes (no time
    passes between them, as with two near-simultaneous pushes racing on the same
    UPDATE). The first wins the claim and enqueues one run; the second finds the
    row already stamped and no-ops -- exactly one queued run per repo per
    interval, no
    double-audit and no double-notify downstream."""
    enable_monitoring(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _fail_if_audited(monkeypatch)

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": None},
    ])
    runs = FakeMonitoringRepo()
    _override(subscription_repo=subs, monitoring_repo=runs)
    try:
        first = _post_push(_push_payload())
        second = _post_push(_push_payload())
    finally:
        _clear()

    assert first.json()["queued"] is True
    assert second.json()["reason"] == "within_interval"
    assert len(subs.claims) == 1        # only the first push claimed the run
    assert runs.enqueued == ["acme/app"]  # exactly one run queued
