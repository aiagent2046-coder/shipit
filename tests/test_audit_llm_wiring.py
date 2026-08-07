"""LLM stage wired into an audit — skip / success / graceful failure.

Driven through the worker rather than through POST /v1/audits: since the queue
cutover the endpoint no longer scans, so the client it is handed is not the one
that reaches run_scan. The wiring worth testing is the worker's, and these
tests run the real _execute_job so the assertions still cover the path that
produces a user's findings.

The two stats-shaped assertions (skipped_reason, prompts) sit at the run_scan
level, alongside the score-basis tests at the bottom of this file: llm stats are
a property of the scan, and since the cutover they are no longer echoed in any
HTTP response -- only llm_usage rows survive the job (tests/test_llm_usage_accounting.py).
"""

import io
import json
import zipfile

from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.scan.pipeline import run_scan
from tests.conftest import run_audit_job

# The LLM stage only runs for a paying account now (free tier is
# static-only), so these tests must supply one to have a stage to observe.
_ACCOUNT_ID = "44444444-4444-4444-4444-444444444444"

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


AUTH_ZIP = {
    "package.json": NEXT_PKG,
    "app/auth.ts": b"const password = 'x'  // check auth token",
}


def test_llm_skipped_when_no_providers_configured():
    # No keys configured -> the stage does not run, and says so in a
    # machine-readable way rather than looking like a run that found nothing.
    scan = run_scan(make_zip(AUTH_ZIP).getvalue(), LLMClient(providers=[]))
    assert scan["llm"]["skipped_reason"] == "no_providers_configured"
    assert scan["llm"]["prompts"] == 0


def test_llm_ran_with_no_relevant_files_has_null_skipped_reason():
    # A real run that simply matched no rubric-relevant files: prompts=0 as
    # before, but skipped_reason is None -- distinguishable from "didn't run".
    buf = make_zip({"package.json": NEXT_PKG, "README.md": b"# hi\n"})
    scan = run_scan(buf.getvalue(), FakeLLM(response="[]"))
    assert scan["llm"]["prompts"] == 0
    assert scan["llm"]["skipped_reason"] is None


async def test_llm_findings_merged_when_providers_configured():
    finding = {
        "file": "app/auth.ts", "line_start": 1, "line_end": 1,
        "evidence": "const password = 'x'", "severity": "high",
        "confidence": 0.8, "title": "Hardcoded credential",
        "explanation": "...", "fix_hint": "use env var",
    }
    row = await run_audit_job(
        make_zip(AUTH_ZIP).getvalue(),
        llm_client=FakeLLM(response=json.dumps([finding])),
        account_id=_ACCOUNT_ID,
    )
    # The provider chain the worker was handed reached the merge, and the
    # merged finding is in the row a user will read -- not just in scan output.
    assert any(f["rule_id"] == "llm-auth" for f in row["findings_json"])


async def test_llm_failure_degrades_to_static_only_not_500():
    row = await run_audit_job(
        make_zip(AUTH_ZIP).getvalue(),
        llm_client=FakeLLM(error=LLMError("all providers unreachable")),
        account_id=_ACCOUNT_ID,
    )
    # An unreachable provider must not fail the job: the audit still lands,
    # with its static findings, scored as static_only.
    assert row["score_json"]["basis"] == "static_only"
    assert any(f["rule_id"] == "no-tests" for f in row["findings_json"])


def test_score_basis_static_only_when_no_providers():
    from app.llm.client import LLMClient
    from app.scan.pipeline import run_scan
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "fastapi\n")
        zf.writestr("app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    scan = run_scan(buf.getvalue(), LLMClient(providers=[]))
    assert scan["score"]["basis"] == "static_only"


def test_score_basis_static_only_when_llm_fails(monkeypatch):
    from app.llm.client import LLMClient, LLMError
    from app.scan import pipeline as pipeline_mod
    from app.scan.pipeline import run_scan
    import io
    import zipfile

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
    from app.llm.client import LLMClient
    from app.scan import pipeline as pipeline_mod
    from app.scan.llm_scan import LLMScanStats
    from app.scan.pipeline import run_scan
    import io
    import zipfile

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
