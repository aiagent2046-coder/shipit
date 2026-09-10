from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import io
import json
import logging
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import zipfile

import httpx
import pytest

from app.scan.pipeline import AUDIT_ENGINE_VERSION, content_digest
from scripts import recover_fixpack_review as recovery

REQUEST = recovery.ReviewRequest("a" * 40, "11111111-1111-4111-8111-111111111111",
                                 "22222222-2222-4222-8222-222222222222",
                                 "33333333-3333-4333-8333-333333333333", "b" * 40)
REPO_URL = "https://github.com/example/project"
REVIEW_ID = "44444444-4444-4444-8444-444444444444"
PRIVATE_TOKEN = "private-test-ownership-value"


def archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipped:
        zipped.writestr("example-project-bbbbbbb/app.py", "print('example')\n")
        zipped.writestr("example-project-bbbbbbb/requirements.txt", "httpx==0.28.1\n")
    return output.getvalue()


@pytest.fixture
def data():
    raw = archive()
    job = {"id": REQUEST.job_id, "audit_id": REQUEST.audit_id, "pack": "fixpack",
           "status": "delivered", "pr_delivered": True, "pr_url": REPO_URL + "/pull/1",
           "attempts": 2, "repo_url": REPO_URL, "started_at": "2026-01-01T00:00:00Z",
           "proof_json": {"verified": True, "before": {"evidence": {
               "samples": [{"file": "example-project-bbbbbbb/app.py"}]}}}}
    payment = {"id": REQUEST.payment_id, "audit_id": REQUEST.audit_id,
               "fixpack_job_id": REQUEST.job_id, "product": "fixpack", "status": "completed",
               "refunded_at": None}
    pr = {"number": 1, "base": {"repo": {"full_name": "example/project"}},
          "head": {"ref": "drydock/fix-pack-" + REQUEST.job_id, "repo": {"full_name": "example/project"}},
          "body": "Verified fix. 4 findings before, 0 after."}
    return SimpleNamespace(raw=raw, job=job, payment=payment, pr=pr)


class Store:
    def __init__(self, data):
        self.data = data
        self.saved = {}
        self.matching_incomplete = False
        self.snapshots = 0

    def snapshot(self, request):
        assert request == REQUEST
        self.snapshots += 1
        return deepcopy(self.data.job), deepcopy(self.data.payment)

    def incomplete_source(self, job, digest):
        assert job == self.data.job and digest == content_digest(self.data.raw)
        return self.matching_incomplete

    def audit(self, audit_id):
        return self.saved.get(audit_id)


class AuditRepo:
    def __init__(self, store):
        self.store = store
        self.creates = 0

    async def get_by_content_hash(self, digest, engine, basis):
        return next((deepcopy(row) for row in self.store.saved.values()
                     if row["content_hash"] == digest and row["engine_version"] == engine
                     and row["score_json"]["basis"] == basis), None)

    async def create(self, **values):
        self.creates += 1
        row = {**values, "id": REVIEW_ID, "access_token": PRIVATE_TOKEN, "status": "completed"}
        self.store.saved[REVIEW_ID] = row
        return deepcopy(row)


def saved_review(data, *, basis="static+llm", baseline="completed"):
    return {"id": REVIEW_ID, "status": "completed", "content_hash": content_digest(data.raw),
            "repo_url": REPO_URL, "engine_version": AUDIT_ENGINE_VERSION, "access_token": PRIVATE_TOKEN,
            "score_json": {"total": 9.0, "basis": basis, "free_baseline": {"status": baseline},
                           "scan_manifest": {"limitations": [] if basis == "static+llm" else ["billing"]}},
            "findings_json": [], "stack": "python", "file_count": 2, "score_total": 9.0}


class Pipeline:
    """A pipeline double with no job/payment/PR methods and explicit audit writes."""

    def __init__(self, store, *, basis="static+llm", baseline="completed"):
        self.store = store
        self.basis = basis
        self.baseline = baseline
        self.calls = 0

    async def __call__(self, repo_url, **kwargs):
        self.calls += 1
        assert repo_url == REPO_URL
        assert kwargs["zip_bytes"] == self.store.data.raw
        assert kwargs["job_type"] == "fixpack_review"
        assert kwargs["llm_usage_repo"] is USAGE
        row = saved_review(self.store.data, basis=self.basis, baseline=self.baseline)
        self.store.saved[REVIEW_ID] = row
        return {"audit_id": REVIEW_ID, "access_token": PRIVATE_TOKEN, "basis": self.basis, "reused": False}


USAGE = object()


async def run(data, tmp_path, *, apply=True, store=None, runner=None, **overrides):
    store = store or Store(data)
    runner = runner or Pipeline(store)
    args = dict(apply=apply, directory=tmp_path, store=store, runner=runner,
                llm_client=SimpleNamespace(providers=["configured"]), audit_repo=AuditRepo(store),
                llm_usage_repo=USAGE, repo_fetcher=lambda *_: pytest.fail("must use pinned supplied ZIP"),
                engine=AUDIT_ENGINE_VERSION, pr_loader=lambda *_: data.pr, downloader=lambda *_: data.raw)
    args.update(overrides)
    return await recovery.recover_review(REQUEST, **args)


@pytest.mark.asyncio
@pytest.mark.parametrize("target,field,value", [
    ("job", "id", "wrong"), ("job", "audit_id", "wrong"), ("job", "pack", "deploypack"),
    ("job", "status", "running"), ("job", "status", "paid"), ("job", "status", "blocked"),
    ("job", "pr_delivered", False), ("job", "pr_url", "https://github.com/other/project/pull/1"),
    ("payment", "id", "wrong"), ("payment", "audit_id", "wrong"),
    ("payment", "fixpack_job_id", "wrong"), ("payment", "product", "subscription"),
    ("payment", "status", "pending"), ("payment", "refunded_at", "2026-01-02"),
])
async def test_changed_entitlement_stops_before_network_or_pipeline(data, tmp_path, target, field, value):
    getattr(data, target)[field] = value
    with pytest.raises(recovery.guards.RecoveryRefused):
        await run(data, tmp_path, pr_loader=lambda *_: pytest.fail("GitHub reached before guard"),
                  runner=lambda *_: pytest.fail("pipeline reached before guard"))


@pytest.mark.asyncio
@pytest.mark.parametrize("alteration", ["other_job", "existing_review", "unreadable_body"])
async def test_pr_must_belong_to_job_and_owe_review(data, tmp_path, alteration):
    if alteration == "other_job":
        data.pr["head"]["ref"] = "drydock/fix-pack-different"
    elif alteration == "existing_review":
        data.pr["body"] += "\n### Your full review\nPrivate link omitted."
    else:
        data.pr["body"] = None
    with pytest.raises(recovery.guards.RecoveryRefused):
        await run(data, tmp_path, downloader=lambda *_: pytest.fail("archive should not be downloaded"))


@pytest.mark.asyncio
async def test_dry_run_reads_but_never_runs_pipeline_or_writes_result(data, tmp_path):
    store = Store(data)
    pipeline = Pipeline(store)
    before = deepcopy((data.job, data.payment))
    result = await run(data, tmp_path, store=store, runner=pipeline, apply=False)
    assert result["state"] == "eligible" and result["applied"] is False
    assert pipeline.calls == 0 and store.saved == {} and list(tmp_path.iterdir()) == []
    assert (data.job, data.payment) == before


@pytest.mark.asyncio
async def test_wrong_source_requires_matching_incomplete_audit(data, tmp_path):
    data.job["proof_json"] = {}
    store = Store(data)
    pipeline = Pipeline(store)
    with pytest.raises(recovery.guards.RecoveryRefused, match="source revision"):
        await run(data, tmp_path, store=store, runner=pipeline)
    assert pipeline.calls == 0
    store.matching_incomplete = True
    assert (await run(data, tmp_path, store=store, runner=pipeline))["state"] == "full_review_ready"


@pytest.mark.asyncio
async def test_entitlement_rechecked_after_slow_public_download(data, tmp_path):
    store = Store(data)
    pipeline = Pipeline(store)
    def download(*_):
        data.payment["refunded_at"] = "2026-01-02"
        return data.raw
    with pytest.raises(recovery.guards.RecoveryRefused, match="unrefunded"):
        await run(data, tmp_path, store=store, runner=pipeline, downloader=download)
    assert pipeline.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("basis,baseline,expected", [
    ("static+llm", "completed", "full_review_ready"),
    ("static_only", "incomplete", "review_incomplete"),
    ("static+partial", "completed", "review_incomplete"),
    ("static+llm", "unavailable", "review_incomplete"),
])
async def test_only_complete_review_and_baseline_are_ready(data, tmp_path, basis, baseline, expected):
    store = Store(data)
    before = deepcopy((data.job, data.payment))
    result = await run(data, tmp_path, store=store, runner=Pipeline(store, basis=basis, baseline=baseline))
    assert result["state"] == expected and result["basis"] == basis
    assert result["free_baseline_status"] == baseline
    assert (data.job, data.payment) == before
    assert PRIVATE_TOKEN not in json.dumps(result)
    private_file = Path(result["private_result_file"])
    assert stat.S_IMODE(private_file.stat().st_mode) == 0o600
    private = json.loads(private_file.read_text())
    assert private["state"] == expected
    assert private["report_url"].endswith("?token=" + PRIVATE_TOKEN)


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("content_hash", "other"), ("access_token", "other"),
                                         ("engine_version", "other"), ("status", "failed"),
                                         ("repo_url", "https://github.com/other/project")])
async def test_returned_result_must_match_actual_persisted_audit(data, tmp_path, field, value):
    store = Store(data)
    pipeline = Pipeline(store)
    async def corrupt(*args, **kwargs):
        result = await pipeline(*args, **kwargs)
        store.saved[REVIEW_ID][field] = value
        return result
    with pytest.raises(recovery.guards.RecoveryRefused, match="stored audit"):
        await run(data, tmp_path, store=store, runner=corrupt)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_real_pipeline_reuses_matching_full_audit_without_a_second_llm_call(data, tmp_path, monkeypatch):
    from app import main

    store = Store(data)
    store.saved[REVIEW_ID] = saved_review(data)
    monkeypatch.setattr(main, "_run_scan_offthread", lambda *_: pytest.fail("cached full review called LLM"))
    first = await run(data, tmp_path, store=store, runner=main.run_repo_audit)
    second = await run(data, tmp_path, store=store, runner=main.run_repo_audit)
    assert first["analysis_reused"] is True and second["analysis_reused"] is True
    assert first["review_audit_id"] == second["review_audit_id"] == REVIEW_ID
    assert len(store.saved) == 1 and data.job["attempts"] == 2


@pytest.mark.asyncio
async def test_full_analysis_is_kept_while_failed_included_preview_is_retried(data, tmp_path, monkeypatch):
    from app import main
    from app.scan.pipeline import BASIS_PREVIEW

    store = Store(data)
    store.saved[REVIEW_ID] = saved_review(data, baseline="unavailable")
    calls = []
    async def preview_only(raw, client, **kwargs):
        assert raw == data.raw and kwargs["depth"] == BASIS_PREVIEW
        calls.append(kwargs)
        return {"score": {"total": None, "basis": BASIS_PREVIEW}, "findings": [],
                "llm": {}, "llm_usage": {"calls": 0}}
    monkeypatch.setattr(main, "_run_scan_offthread", preview_only)
    client = SimpleNamespace(providers=["configured"], with_model=lambda *_, **__: "preview-model")
    result = await run(data, tmp_path, store=store, runner=main.run_repo_audit, llm_client=client)
    assert result["state"] == "full_review_ready" and len(calls) == 1
    assert result["basis"] == "static+llm" and result["free_baseline_status"] == "completed"


def test_public_zip_fetch_pins_sha_and_sends_no_credentials(data):
    requests = []
    def respond(request):
        requests.append(request)
        assert "authorization" not in request.headers
        if request.url.host == "api.github.com":
            assert request.url.path == "/repos/example/project/zipball/" + REQUEST.source_revision
            return httpx.Response(302, headers={"location": "https://codeload.github.com/example/project/legacy.zip/"
                                               + REQUEST.source_revision})
        return httpx.Response(200, content=data.raw)
    assert recovery.fetch_source_zip("example", "project", REQUEST.source_revision,
                                      transport=httpx.MockTransport(respond)) == data.raw
    assert len(requests) == 2


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"location": "https://attacker.invalid/archive.zip"}),
    httpx.Response(200, headers={"content-length": "1000"}, content=b"example"),
    httpx.Response(200, content=b"more than five bytes"),
])
def test_download_blocks_foreign_redirects_and_oversized_responses(response):
    with pytest.raises(recovery.guards.RecoveryRefused):
        recovery._public_bytes("https://api.github.com/repos/example/project/zipball/" + REQUEST.source_revision,
                               limit=5, redirects=True, transport=httpx.MockTransport(lambda _: response))


def test_same_job_serialized_but_other_jobs_can_run(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, "STATE_DIR", tmp_path / "protected")
    real_lstat, real_fstat = Path.lstat, os.fstat
    monkeypatch.setattr(Path, "lstat", lambda p: SimpleNamespace(st_mode=real_lstat(p).st_mode, st_uid=0))
    monkeypatch.setattr(os, "fstat", lambda fd: SimpleNamespace(st_mode=real_fstat(fd).st_mode, st_uid=0))
    with recovery.review_lock(REQUEST):
        with pytest.raises(recovery.guards.RecoveryRefused, match="already running"):
            with recovery.review_lock(REQUEST):
                pytest.fail("same job entered twice")
        with recovery.review_lock(replace(REQUEST, job_id=REVIEW_ID)):
            pass


def test_recovery_does_not_follow_a_log_symlink(tmp_path):
    destination = tmp_path / "operator-file"
    destination.write_text("keep unchanged")
    link = tmp_path / "recovery.log"
    link.symlink_to(destination)
    with pytest.raises(OSError):
        recovery._protected_fd(link)
    assert destination.read_text() == "keep unchanged"


def test_private_log_is_redacted_protected_and_not_sent_to_stdout(tmp_path, monkeypatch, capsys):
    real_fstat = os.fstat
    monkeypatch.setattr(os, "fstat", lambda fd: SimpleNamespace(st_mode=real_fstat(fd).st_mode, st_uid=0))
    logfile = tmp_path / "review.log"
    with recovery.configure_private_log(logfile):
        logging.getLogger("review-recovery-test").warning("Provider password=%s", PRIVATE_TOKEN)
    assert PRIVATE_TOKEN not in logfile.read_text()
    assert "[REDACTED]" in logfile.read_text()
    assert stat.S_IMODE(logfile.stat().st_mode) == 0o600
    assert PRIVATE_TOKEN not in capsys.readouterr().err


def test_environment_uses_deployment_parser_and_overrides_stale_shell_values(tmp_path, monkeypatch):
    from scripts import env_file

    monkeypatch.setattr(recovery.guards, "CURRENT", tmp_path)
    monkeypatch.setattr(sys, "path", sys.path.copy())
    monkeypatch.setenv("DATABASE_URL", "stale-shell-value")
    monkeypatch.setenv("RECOVERY_TEST_SETTING", "stale-shell-value")
    monkeypatch.setattr(env_file, "read_values", lambda path: {
        "DATABASE_URL": "deployment-database-value", "RECOVERY_TEST_SETTING": "keep $literal and spaces"})
    recovery.load_environment()
    assert os.environ["DATABASE_URL"] == "deployment-database-value"
    assert os.environ["RECOVERY_TEST_SETTING"] == "keep $literal and spaces"


def test_cli_runtime_guard_precedes_environment_and_application_imports(monkeypatch, tmp_path):
    @contextmanager
    def directory(*_):
        yield tmp_path
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery, "review_lock", directory)
    class LockFile(io.StringIO):
        def fileno(self):
            return 123
    monkeypatch.setattr(recovery, "open", lambda *_: LockFile(), raising=False)
    monkeypatch.setattr(recovery.fcntl, "flock", lambda *_: None)
    def refusal(_):
        raise recovery.guards.RecoveryRefused("runtime mismatch")
    monkeypatch.setattr(recovery.guards, "check_runtime", refusal)
    monkeypatch.setattr(recovery, "load_environment", lambda: pytest.fail("loaded credentials before runtime check"))
    args = ["--expected-release", REQUEST.expected_release, "--job-id", REQUEST.job_id,
            "--audit-id", REQUEST.audit_id, "--payment-id", REQUEST.payment_id,
            "--source-revision", REQUEST.source_revision, "--apply"]
    assert recovery.main(args) == 1
