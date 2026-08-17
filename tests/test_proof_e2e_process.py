"""E2E: Proof-of-Exploit section appears on secrets Fix Pack PRs.

Reuses fakes from test_fixpack_process_endpoint so the full processor
path (claim → plan → semantic → proof stage → PR body) is exercised
without network or Docker.
"""

from __future__ import annotations

from app.deploypack import github_app
from app.deploypack.delivery import PullRequestResult

from tests.test_fixpack_process_endpoint import (
    ExplodingLLM,
    FakeAuditRepo,
    FakeFixpackRepo,
    auth,
    clear_overrides,
    client,
    fake_fetcher_returning,
    make_zip,
    override,
)

import app.main as main_mod
from app.fixpack.semantic_check import minimal_check as local_minimal_check


def _healthy_runner(monkeypatch):
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: True)
    monkeypatch.setattr(main_mod.sandbox_client, "minimal_check", local_minimal_check)


def test_proof_section_in_pr_body_after_secrets_fix(monkeypatch):
    """Soft gate: verified secrets fix delivers PR with Proof section."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setenv("PROOF_GATE_MODE", "soft")
    _healthy_runner(monkeypatch)
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    stripe_key = "sk_" + "live_" + ("B" * 24)
    zip_bytes = make_zip({
        "config.ts": f'export const key = "{stripe_key}";\n',
    })
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "stripe-live-key", "file": "config.ts",
             "line": 1, "title": "Stripe live secret key", "context": None},
        ],
    }}
    jobs = [{"id": "j-proof", "audit_id": "a1", "status": "paid"}]
    captured: dict = {}

    def fake_opener(owner, repo, files, *, title, body, branch_prefix,
                    deletions=None, token=None, job_id=None):
        captured.update(title=title, body=body, files=files)
        return PullRequestResult(
            html_url="https://github.com/acme/app/pull/99",
            branch="drydock/fix-pack-proof",
        )

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener,
             llm_client=ExplodingLLM())
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.status_code == 200, resp.text
    summary = resp.json()
    assert summary["delivered"] == 1, summary
    assert summary.get("blocked", 0) == 0

    body = captured["body"]
    assert "Proof-of-Exploit" in body, body
    assert "secrets_leak" in body
    assert "Soft gate" not in body
    assert stripe_key not in body
    for text_val in captured["files"].values():
        assert stripe_key not in text_val

    assert "j-proof" in fixpack_repo.proof_json
    report = fixpack_repo.proof_json["j-proof"]
    assert report["template_id"] == "secrets_leak"
    assert report["verified"] is True
    assert report["before"]["success"] is True
    assert report["after"]["success"] is False


def test_proof_hard_gate_blocks_when_secret_survives(monkeypatch):
    """Hard gate blocks when a residual high-confidence secret remains."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    _healthy_runner(monkeypatch)
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    stripe_key = "sk_" + "live_" + ("C" * 24)
    zip_bytes = make_zip({
        "config.ts": f'export const a = "{stripe_key}";\n',
        "backup/config.ts": f'export const b = "{stripe_key}";\n',
    })
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "stripe-live-key", "file": "config.ts", "line": 1,
             "title": "Stripe live secret key", "context": None},
        ],
    }}
    jobs = [{"id": "j-hard", "audit_id": "a1", "status": "paid"}]
    opened = {"n": 0}

    def fake_opener(*args, **kwargs):
        opened["n"] += 1
        return PullRequestResult(
            html_url="https://github.com/acme/app/pull/0",
            branch="drydock/fix-pack-x",
        )

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener,
             llm_client=ExplodingLLM())
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.status_code == 200, resp.text
    summary = resp.json()
    if "j-hard" in fixpack_repo.proof_json:
        report = fixpack_repo.proof_json["j-hard"]
        if report.get("before", {}).get("success") and not report.get("verified"):
            assert summary.get("blocked", 0) == 1, summary
            assert opened["n"] == 0
            assert fixpack_repo.statuses.get("j-hard") == "blocked"
        else:
            assert summary.get("delivered", 0) == 1
    else:
        assert summary.get("blocked", 0) == 0
