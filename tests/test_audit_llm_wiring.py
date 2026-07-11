"""LLM stage wired into /v1/audits — skip / success / graceful failure."""

import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.llm.client import LLMClient, LLMError, Provider
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

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        if self._error:
            raise self._error
        return self._response


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
    assert resp.json()["llm"] == "skipped (no providers configured)"


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
