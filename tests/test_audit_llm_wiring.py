"""LLM stage wired into /v1/audits — skip / success / graceful failure."""

import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.main import app, get_llm_client

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


class FakeLLM(LLMClient):
    """Stands in for a real provider chain; `providers` stays non-empty
    so the scan pipeline actually attempts the LLM stage."""

    def __init__(self, response: str | None = None, error: Exception | None = None):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._response = response
        self._error = error

    def complete(self, system: str, user: str,
                 max_tokens: int = 4096) -> tuple[str, LLMUsage]:
        if self._error:
            raise self._error
        return self._response, LLMUsage(
            model="fake-model", input_tokens=100, output_tokens=20)


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def post_audit():
    buf = make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    })
    return client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )


def test_llm_skipped_when_no_providers_configured():
    # Default get_llm_client() reads real env; CI/test env has no keys set.
    resp = post_audit()
    assert resp.status_code == 202
    llm = resp.json()["llm"]
    # didn't-run: stats-shaped dict with an explicit machine-readable reason
    assert llm["skipped_reason"] == "no_providers_configured"
    assert llm["prompts"] == 0


def test_llm_ran_with_no_relevant_files_has_null_skipped_reason():
    # A real run that simply matched no rubric-relevant files: prompts=0 as
    # before, but skipped_reason is None -- distinguishable from "didn't run".
    fake = FakeLLM(response="[]")
    app.dependency_overrides[get_llm_client] = lambda: fake
    try:
        # a zip with no auth/security-relevant code -> no rubric matches
        buf = make_zip({"package.json": NEXT_PKG, "README.md": b"# hi\n"})
        resp = client.post(
            "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
        )
    finally:
        app.dependency_overrides.pop(get_llm_client, None)

    assert resp.status_code == 202
    llm = resp.json()["llm"]
    assert llm["prompts"] == 0
    assert llm["skipped_reason"] is None


def test_llm_findings_merged_when_providers_configured():
    finding = {
        "file": "app/auth.ts", "line_start": 1, "line_end": 1,
        "evidence": "const password = 'x'", "severity": "high",
        "confidence": 0.8, "title": "Hardcoded credential",
        "explanation": "...", "fix_hint": "use env var",
    }
    fake = FakeLLM(response=json.dumps([finding]))
    app.dependency_overrides[get_llm_client] = lambda: fake
    try:
        resp = post_audit()
    finally:
        app.dependency_overrides.pop(get_llm_client, None)

    assert resp.status_code == 202
    body = resp.json()
    assert body["llm"]["prompts"] >= 1
    assert body["llm"]["verified"] == 1
    assert any(f["rule_id"] == "llm-auth" for f in body["findings"])


def test_llm_failure_degrades_to_static_only_not_500():
    fake = FakeLLM(error=LLMError("all providers unreachable"))
    app.dependency_overrides[get_llm_client] = lambda: fake
    try:
        resp = post_audit()
    finally:
        app.dependency_overrides.pop(get_llm_client, None)

    assert resp.status_code == 202
    body = resp.json()
    assert body["llm"].startswith("failed:")
    # static findings (e.g. no-tests) still present despite the LLM failure
    assert any(f["rule_id"] == "no-tests" for f in body["findings"])


def test_score_basis_static_only_when_no_providers():
    import io
    import zipfile

    from app.llm.client import LLMClient
    from app.scan.pipeline import run_scan
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "fastapi\n")
        zf.writestr("app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    scan = run_scan(buf.getvalue(), LLMClient(providers=[]))
    assert scan["score"]["basis"] == "static_only"


def test_score_basis_static_only_when_llm_fails(monkeypatch):
    import io
    import zipfile

    from app.llm.client import LLMClient, LLMError
    from app.scan import pipeline as pipeline_mod
    from app.scan.pipeline import run_scan

    def boom(*a, **k):
        raise LLMError("provider down")
    monkeypatch.setattr(pipeline_mod, "run_llm_scan", boom)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "fastapi\n")
        zf.writestr("app/auth.py", "token = request.headers['authorization']\n")
    fake = LLMClient(providers=[])
    fake.providers = [object()]  # non-empty chain so the stage is attempted
    scan = run_scan(buf.getvalue(), fake)
    assert scan["score"]["basis"] == "static_only"
    assert scan["llm"].startswith("failed:")


def test_score_basis_static_plus_llm_when_stage_ran(monkeypatch):
    import io
    import zipfile

    from app.llm.client import LLMClient
    from app.scan import pipeline as pipeline_mod
    from app.scan.llm_scan import LLMScanStats
    from app.scan.pipeline import run_scan

    monkeypatch.setattr(pipeline_mod, "run_llm_scan",
                        lambda *a, **k: ([], LLMScanStats(prompts=1)))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "fastapi\n")
        zf.writestr("app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    fake = LLMClient(providers=[])
    fake.providers = [object()]
    scan = run_scan(buf.getvalue(), fake)
    assert scan["score"]["basis"] == "static+llm"
