"""Reproducibility of /v1/audits: identical content -> identical result.

Prod symptom: three audits of the same repo at the same commit (identical
file_count) scored 8.9, 9.9, 9.9 within an hour. The score math is
deterministic (see tests/test_checks_scoring.py); the variance came from the
LLM scan returning a different findings set run to run even at temperature=0.
The fix is content-hash caching: a byte-identical re-audit reuses the stored
result instead of re-running the non-deterministic scan.

No real DB and no real LLM: get_audit_repo is overridden with an in-memory
fake keyed by content_hash (same pattern as the billing tests' Fake*Repo),
and the LLM is a fake that deliberately returns DIFFERENT findings on the
second audit -- so a re-scan WOULD score differently, proving the cache is
what pins the result.

Since the queue cutover an audit takes two steps -- POST enqueues, the worker
scans -- so each "audit" below is a _post followed by drain_audit_queue. The
property under test is unchanged: the SECOND identical submission must never
reach a scan at all, and must answer with the stored result inline.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile

from fastapi.testclient import TestClient

from app.llm.client import LLMClient, LLMUsage, Provider
from app.main import app, get_audit_repo, get_llm_client
from app.scan.pipeline import content_digest
from tests.conftest import drain_audit_queue, force_pro_account

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


# --- content_digest: stable across packaging, sensitive to content ---

def test_content_digest_is_stable_across_zip_packaging():
    entries = {"a.py": b"print(1)\n", "b/c.ts": b"const x = 1\n"}
    d1 = content_digest(make_zip(entries).getvalue())

    # Repack with reversed member order and no compression -> same digest,
    # because the digest is over sorted (path, content-hash), not the bytes.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name in reversed(list(entries)):
            zf.writestr(name, entries[name])
    assert content_digest(buf.getvalue()) == d1


def test_content_digest_changes_when_a_file_changes():
    d1 = content_digest(make_zip({"a.py": b"print(1)\n"}).getvalue())
    d2 = content_digest(make_zip({"a.py": b"print(2)\n"}).getvalue())
    assert d1 != d2


# --- endpoint caching: identical content -> identical result ---

class FakeAuditRepo:
    """In-memory AuditRepository keyed by content_hash."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, *, stack, file_count, score_total, score_json,
                     findings_json, repo_url=None, content_hash=None,
                     engine_version=None):
        row = {
            "id": str(uuid.uuid4()), "stack": stack, "status": "completed",
            "file_count": file_count, "score_total": score_total,
            "score_json": score_json, "findings_json": findings_json,
            "repo_url": repo_url, "content_hash": content_hash,
            "engine_version": engine_version,
        }
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        matches = [r for r in self.rows
                   if r["content_hash"] == content_hash
                   and r["engine_version"] == engine_version
                   and r["status"] == "completed"]
        return matches[-1] if matches else None

    async def get(self, audit_id):
        return next((r for r in self.rows if r["id"] == audit_id), None)


class ScriptedLLM(LLMClient):
    """Returns a different response on each successive complete() call, to
    mimic the LLM's real run-to-run variance. `providers` is non-empty so
    the scan pipeline actually runs the LLM stage."""

    def __init__(self, responses: list[str]):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._responses = responses
        self._i = 0

    def complete(self, system, user, max_tokens=4096):
        resp = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return resp, LLMUsage(model="m", input_tokens=100, output_tokens=20)


_AUTH_FINDING = json.dumps([{
    "file": "app/auth.ts", "line_start": 1, "line_end": 1,
    "evidence": "const password = 'x'", "severity": "high",
    "confidence": 0.8, "title": "Hardcoded credential",
    "explanation": "...", "fix_hint": "use env var",
}])


def _post(archive: io.BytesIO):
    archive.seek(0)
    return client.post(
        "/v1/audits",
        files={"archive": ("app.zip", archive, "application/zip")},
    )


async def test_identical_content_returns_identical_score_via_cache(
    audit_queue, monkeypatch
):
    repo = FakeAuditRepo()
    # As a payer. The determinism this test guards is a property of the LLM
    # stage -- it returns a different findings set per run -- and that stage now
    # runs only for a paying account. Anonymously the scan is static-only and
    # therefore deterministic on its own, so the test would prove nothing.
    force_pro_account(monkeypatch)
    # First audit finds a high issue; every later call finds nothing. So a
    # *re-scan* of the same code would score HIGHER -> without caching the
    # second request would differ, exactly the prod bug.
    llm = ScriptedLLM([_AUTH_FINDING, "[]", "[]", "[]"])
    app.dependency_overrides[get_audit_repo] = lambda: repo
    entries = {
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    }
    try:
        first = _post(make_zip(entries))
        await drain_audit_queue(audit_queue, audit_repo=repo, llm_client=llm)
        second = _post(make_zip(entries))  # byte-for-byte identical content
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert first.status_code == 202 and second.status_code == 202
    # The first submission was work to do; the second was already done.
    assert "job_id" in first.json()
    b2 = second.json()
    scanned = repo.rows[0]

    assert b2["reused"] is True
    assert b2["audit_id"] == scanned["id"]
    assert b2["score"] == scanned["score_json"]
    assert b2["findings"] == scanned["findings_json"]

    # Only one row was ever persisted, and the second submission queued no
    # second job -- the cache is checked before the enqueue, so a repeat costs
    # neither a scan nor a queue slot.
    assert len(repo.rows) == 1
    assert len(audit_queue.rows) == 1
    # And the first audit's LLM finding really did lower the score, so this
    # isn't a trivial "both empty" pass.
    assert any(f["rule_id"] == "llm-auth" for f in scanned["findings_json"])


async def test_different_content_is_not_served_from_cache(audit_queue):
    repo = FakeAuditRepo()
    llm = ScriptedLLM(["[]"])
    app.dependency_overrides[get_audit_repo] = lambda: repo
    try:
        first = _post(make_zip({"package.json": NEXT_PKG, "a.ts": b"const x=1\n"}))
        await drain_audit_queue(audit_queue, audit_repo=repo, llm_client=llm)
        second = _post(make_zip({"package.json": NEXT_PKG, "a.ts": b"const x=2\n"}))
        await drain_audit_queue(audit_queue, audit_repo=repo, llm_client=llm)
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert first.json().get("reused") is not True
    assert second.json().get("reused") is not True
    assert len(repo.rows) == 2


async def test_engine_version_bump_invalidates_cache(monkeypatch, audit_queue):
    """Same content, but the audit engine changed: a row cached under the old
    AUDIT_ENGINE_VERSION must NOT be reused -- the audit recomputes under the
    new version. This is the complement to reproducibility: PR #31 pins the
    result for a FIXED engine; this keeps a stale result from being frozen in
    across an engine change (migration 0013)."""
    import app.main as main_mod
    import app.worker.main as worker_mod

    def set_engine(version):
        # Both processes stamp the row and read the cache, so both have to move
        # together for the bump to mean anything.
        monkeypatch.setattr(main_mod, "AUDIT_ENGINE_VERSION", version)
        monkeypatch.setattr(worker_mod, "AUDIT_ENGINE_VERSION", version)

    repo = FakeAuditRepo()
    # LLM returns nothing on both runs, so any score difference here comes from
    # the engine-version gate, not LLM variance.
    llm = ScriptedLLM(["[]", "[]"])
    app.dependency_overrides[get_audit_repo] = lambda: repo
    entries = {"package.json": NEXT_PKG, "a.ts": b"const x=1\n"}
    try:
        set_engine("v-old")
        first = _post(make_zip(entries))
        await drain_audit_queue(audit_queue, audit_repo=repo, llm_client=llm)
        # Engine changed between the two identical-content requests.
        set_engine("v-new")
        second = _post(make_zip(entries))  # byte-for-byte identical content
        await drain_audit_queue(audit_queue, audit_repo=repo, llm_client=llm)
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert first.status_code == 202 and second.status_code == 202
    # The second request is a cache MISS despite identical content: it recomputed
    # and persisted a fresh row stamped with the new engine version.
    assert first.json().get("reused") is not True
    assert second.json().get("reused") is not True
    assert len(repo.rows) == 2
    assert repo.rows[0]["engine_version"] == "v-old"
    assert repo.rows[1]["engine_version"] == "v-new"
