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
  3. POST /v1/webhooks/github `push` event -- the four end-to-end scenarios:
     (a) no active subscription -> no re-audit; (b) within 24h -> no re-audit;
     (c) >=24h + a new critical -> subscriber notified; (d) >=24h + nothing new
     -> silent. Re-uses the same TestClient + dependency-override pattern as
     tests/test_fix_outcomes.py.
"""

import datetime
import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import app.main as main_mod
from app.ingest.stack_detect import Stack
from app.monitor import normalize_repo_full_name, repo_url_from_full_name
from app.monitor.diff import new_high_severity_findings
from app.main import (
    app,
    get_audit_repo,
    get_billing_transport,
    get_llm_client,
    get_repo_fetcher,
    get_subscription_repo,
)

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
        self.marked: list[tuple[str, datetime.datetime]] = []

    async def list_active_for_repo(self, repo_full_name):
        return [s for s in self._subs if s.get("repo_full_name") == repo_full_name]

    async def mark_monitored(self, repo_full_name, at):
        self.marked.append((repo_full_name, at))


class FakeAuditRepo:
    def __init__(self, previous=None):
        self._previous = previous
        self.created: list[dict] = []

    async def get_latest_by_repo_url(self, repo_full_name):
        return self._previous

    async def get_by_content_hash(self, digest, engine_version):
        return None  # always a cache miss -> run the (faked) scan

    async def create(self, **kwargs):
        row = {"id": "audit-new", **kwargs}
        self.created.append(row)
        return row


class FakeTransport:
    pass


def _install_fakes(monkeypatch, *, findings):
    """Make run_repo_audit deterministic without a real zip/scan/LLM."""
    monkeypatch.setattr(main_mod, "validate_zip",
                        lambda buf, size_bytes: type("R", (), {"file_count": 1})())
    monkeypatch.setattr(main_mod, "detect_stack", lambda buf: Stack.FASTAPI)
    monkeypatch.setattr(
        main_mod, "run_scan",
        lambda raw, llm: {"findings": findings,
                          "score": {"total": 50, "categories": {}}})


def _override(*, subscription_repo, audit_repo):
    app.dependency_overrides[get_subscription_repo] = lambda: subscription_repo
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    app.dependency_overrides[get_repo_fetcher] = lambda: (lambda o, r: b"zipbytes")
    app.dependency_overrides[get_llm_client] = lambda: object()
    app.dependency_overrides[get_billing_transport] = lambda: FakeTransport()


def _clear():
    for dep in (get_subscription_repo, get_audit_repo, get_repo_fetcher,
                get_llm_client, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def _capture_dms(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def fake_send(chat_id, text, *, token, transport=None, reply_markup=None):
        sent.append((str(chat_id), text))
        return {"ok": True}

    monkeypatch.setattr(main_mod.telegram_stars, "send_message", fake_send)
    monkeypatch.setattr(main_mod.telegram_stars, "bot_token_from_env",
                        lambda: "bot-token")
    return sent


def test_push_scenario_a_no_subscription_no_reaudit(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _capture_dms(monkeypatch)
    _install_fakes(monkeypatch, findings=[_f("r1", "a.py", "critical")])

    subs = FakeSubscriptionRepo([])  # nobody subscribed to acme/app
    audits = FakeAuditRepo(previous=None)
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json()["reason"] == "no_active_subscription"
    assert audits.created == []       # no re-audit ran
    assert subs.marked == []          # nothing stamped


def test_push_scenario_b_within_24h_no_reaudit(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    sent = _capture_dms(monkeypatch)
    _install_fakes(monkeypatch, findings=[_f("r1", "a.py", "critical")])

    recent = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": recent},
    ])
    audits = FakeAuditRepo(previous=None)
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    assert resp.json()["reason"] == "within_interval"
    assert audits.created == []   # the 24h gate blocked the re-audit
    assert sent == []


def test_push_scenario_c_new_critical_notifies(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    sent = _capture_dms(monkeypatch)
    # Previous audit had r1; the re-audit surfaces a brand-new critical r2.
    _install_fakes(monkeypatch, findings=[
        _f("r1", "a.py", "critical"), _f("r2", "b.py", "critical")])

    old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": old},
        {"repo_full_name": "acme/app", "telegram_chat_id": "222",
         "telegram_user_id": "222", "last_monitored_at": None},
    ])
    audits = FakeAuditRepo(previous={"findings_json": [_f("r1", "a.py", "critical")]})
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    body = resp.json()
    assert body["monitored"] is True
    assert body["new_findings"] == 1
    assert body["notified"] == 2                 # both subscribers DM'd
    assert len(audits.created) == 1              # a fresh audit ran
    assert len(subs.marked) == 1 and subs.marked[0][0] == "acme/app"
    assert len(sent) == 2
    assert "b.py" in sent[0][1] and "r2" in sent[0][1]


def test_push_scenario_d_no_new_findings_is_silent(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    sent = _capture_dms(monkeypatch)
    # Re-audit surfaces the SAME findings as before (only line drifted) -> nothing new.
    _install_fakes(monkeypatch, findings=[_f("r1", "a.py", "critical", line=99)])

    old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": old},
    ])
    audits = FakeAuditRepo(previous={"findings_json": [_f("r1", "a.py", "critical", line=1)]})
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        resp = _post_push(_push_payload())
    finally:
        _clear()

    body = resp.json()
    assert body["monitored"] is True
    assert body["new_findings"] == 0
    assert body["notified"] == 0
    assert sent == []                    # silent
    assert len(subs.marked) == 1         # but the run is still stamped (cost cap)


def test_push_non_default_branch_ignored(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    _capture_dms(monkeypatch)
    _install_fakes(monkeypatch, findings=[])

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": None},
    ])
    audits = FakeAuditRepo(previous=None)
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        resp = _post_push(_push_payload(ref="refs/heads/feature-x"))
    finally:
        _clear()

    assert resp.json()["reason"] == "not_default_branch"
    assert audits.created == []
    assert subs.marked == []


def test_push_repo_matched_case_insensitively(monkeypatch):
    """The founder's concern, exercised end-to-end: a push whose repository name
    is differently-cased than the stored subscription still matches, re-audits,
    and notifies. (list_active_for_repo is keyed on the normalized name, so the
    push side must normalize identically.)"""
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    sent = _capture_dms(monkeypatch)
    _install_fakes(monkeypatch, findings=[_f("r2", "b.py", "critical")])

    subs = FakeSubscriptionRepo([
        {"repo_full_name": "acme/app", "telegram_chat_id": "111",
         "telegram_user_id": "111", "last_monitored_at": None},
    ])
    audits = FakeAuditRepo(previous=None)
    _override(subscription_repo=subs, audit_repo=audits)
    try:
        # Push payload carries mixed-case owner/repo.
        resp = _post_push(_push_payload(full_name="Acme/App"))
    finally:
        _clear()

    body = resp.json()
    assert body["monitored"] is True
    assert body["notified"] == 1
    assert len(sent) == 1
