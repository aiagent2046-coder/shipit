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
    finding = next(f for f in row["findings_json"] if f["rule_id"] == "llm-auth")
    assert finding["source"] == "llm"
    assert finding["verification_status"] == "unverified"
    assert finding["verification_method"] == "model_review"


async def test_a_paid_audit_runs_two_passes_and_the_preview_runs_one():
    """PAID_AUDIT_PASSES is wired, not narrated. The docstring that claimed
    passes=2 while every caller passed 1 was quoted as fact twice before
    anyone checked (task #13); this pins the claim to the call count, so the
    next regression is a red test instead of a discovered sentence.

    Measured reason for 2 (2026-08-18, four same-engine runs): one pass
    surfaces 23-27 of a 34-key union -- a paid single pass was a sample sold
    as a census."""

    class CountingLLM(FakeLLM):
        """The counter is a shared list, not an int: the preview path clones
        the client via with_model (copy.copy), and an int bumped on the clone
        would leave the original's attribute at 0."""

        def __init__(self, counter):
            super().__init__(response="[]")
            self._counter = counter

        def complete(self, system, user, max_tokens=4096):
            self._counter.append(1)
            return super().complete(system, user, max_tokens)

    # Matches the auth rubric ("password", "token") AND the preview's
    # security rubric ("query", "input"), so the anon leg below has a prompt
    # to count rather than passing on an empty rubric match.
    fixture = {
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // auth token, sql query input",
    }

    baseline: list = []
    run_scan(make_zip(fixture).getvalue(), CountingLLM(baseline),
             llm_passes=1)
    assert baseline, "the fixture must reach at least one rubric"

    paid: list = []
    await run_audit_job(make_zip(fixture).getvalue(),
                        llm_client=CountingLLM(paid), account_id=_ACCOUNT_ID)
    assert len(paid) == 2 * len(baseline)

    # The preview stays a single pass of its narrowed rubric set -- fewer
    # calls than even one full pass, and certainly no doubling.
    anon: list = []
    await run_audit_job(make_zip(fixture).getvalue(),
                        llm_client=CountingLLM(anon), account_id=None)
    assert 0 < len(anon) <= len(baseline)


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


# --- an unrecognised stack goes through the worker, not into a dead letter ---

SVELTE_ZIP = {
    "svelte.config.js": b"export default {}",
    "src/routes/+page.svelte": b"<h1>hi</h1>",
    ".gitignore": b"node_modules\n",
    ".env": b"DATABASE_URL=postgres://user:hunter2@db/app\n",  # scan-allow: fixture URL, invented credentials
    "src/lib/db.ts": b"const token = process.env.SESSION_TOKEN  // auth session",
}


async def test_worker_audits_a_stack_the_detector_does_not_recognise():
    """The queue path must not dead-letter an unknown stack.

    `POST /v1/audits` returns 202 and the worker does the scan, so accepting
    the upload at intake buys nothing if _execute_job then fails the job
    permanently -- the visitor would wait and be told their project is not
    supported, one step later. This drives the real _execute_job.

    Written after a mutation showed the worker branch had no coverage:
    restoring its refusal broke no test, because every other worker test
    feeds it a Next.js fixture.
    """
    row = await run_audit_job(
        make_zip(SVELTE_ZIP).getvalue(),
        llm_client=FakeLLM(response="[]"),
        account_id=_ACCOUNT_ID,
    )

    ids = {f["rule_id"] for f in row["findings_json"]}
    assert "env-file-committed" in ids
    assert row["stack"] == "unsupported"       # recorded, not refused
