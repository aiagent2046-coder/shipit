"""Tests for the LLM scan stage. All LLM calls are mocked.

The verification tests are the heart of this stage: a hallucinated
finding must never reach the user.
"""

import io
import json
import zipfile

import httpx

from app.llm.client import LLMClient, Provider
from app.scan.llm_scan import (
    LLMScanStats,
    build_prompt,
    parse_findings,
    run_llm_scan,
    select_files,
    verify_finding,
)

VULN_TS = (
    "import jwt from 'jsonwebtoken'\n"
    "export function decode(token: string) {\n"
    "  return jwt.decode(token) // no signature verification\n"
    "}\n"
)


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


class FakeLLM(LLMClient):
    """Returns a canned response; records the prompts it received."""

    def __init__(self, response: str):
        super().__init__(providers=[])
        self.response = response
        self.prompts: list[str] = []

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        self.prompts.append(user)
        return self.response


# --- file selection & prompt ---

def test_select_files_matches_rubric_and_respects_budget():
    files = [
        ("src/auth/session.ts", "export const session = 1"),
        ("src/ui/button.tsx", "export const Button = () => null"),
        ("src/api/login.ts", "const password = check()"),
    ]
    names = [n for n, _ in select_files(files, "auth")]
    assert "src/auth/session.ts" in names
    assert "src/api/login.ts" in names       # matched by content keyword
    assert "src/ui/button.tsx" not in names


def test_prompt_wraps_content_as_data_with_line_numbers():
    prompt = build_prompt([("a.ts", "line one\nline two")], "auth")
    assert '<file path="a.ts">' in prompt
    assert "1\tline one" in prompt and "2\tline two" in prompt


# --- parsing ---

def test_parse_tolerates_fences_and_prose():
    raw = 'Here you go:\n```json\n[{"file":"a.ts"}]\n```\nDone.'
    assert parse_findings(raw) == [{"file": "a.ts"}]


def test_parse_garbage_returns_empty():
    assert parse_findings("I could not analyze this.") == []
    assert parse_findings("[{broken json") == []


# --- verification (anti-hallucination gate) ---

FILES = {"src/auth.ts": VULN_TS}


def valid_finding(**overrides) -> dict:
    f = {
        "file": "src/auth.ts",
        "line_start": 3,
        "line_end": 3,
        "evidence": "jwt.decode(token)",
        "severity": "critical",
        "confidence": 0.9,
        "title": "JWT decoded without verification",
        "explanation": "...",
        "fix_hint": "use jwt.verify",
    }
    f.update(overrides)
    return f


def test_verify_accepts_real_finding():
    assert verify_finding(valid_finding(), FILES)


def test_verify_rejects_nonexistent_file():
    assert not verify_finding(valid_finding(file="src/ghost.ts"), FILES)


def test_verify_rejects_out_of_range_lines():
    assert not verify_finding(valid_finding(line_start=90, line_end=95), FILES)


def test_verify_rejects_fabricated_evidence():
    assert not verify_finding(
        valid_finding(evidence="eval(userInput)"), FILES
    )


def test_verify_accepts_evidence_spanning_multiple_real_lines():
    # The prompt asks for a single-line evidence string, but models
    # sometimes return a real multi-line snippet anyway (e.g. a call
    # split across two lines). That's still real code, not a
    # hallucination — confirmed against a real repo during manual
    # testing (dgero22/digital-rolecraft: a real save-to-localStorage
    # finding was wrongly discarded for exactly this reason).
    assert verify_finding(
        valid_finding(
            line_start=2, line_end=3,
            evidence="export function decode(token: string) {\n  return jwt.decode(token)",
        ),
        FILES,
    )


def test_verify_rejects_fabricated_multiline_evidence():
    # Joining the window shouldn't make the check any less strict for
    # genuinely invented content spanning multiple "lines".
    assert not verify_finding(
        valid_finding(
            line_start=2, line_end=3,
            evidence="export function decode(token: string) {\n  eval(userInput)",
        ),
        FILES,
    )


def test_verify_rejects_missing_keys_and_bad_severity():
    bad = valid_finding()
    del bad["evidence"]
    assert not verify_finding(bad, FILES)
    assert not verify_finding(valid_finding(severity="catastrophic"), FILES)


# --- end to end with mocked LLM ---

def test_run_llm_scan_keeps_verified_drops_hallucinated():
    response = json.dumps([
        valid_finding(),
        valid_finding(file="src/invented.ts", title="hallucination"),
    ])
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})
    findings, stats = run_llm_scan(buf, FakeLLM(response), rubrics=("auth",))

    assert stats == LLMScanStats(prompts=1, raw_findings=2, verified=1, discarded=1)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "llm-auth" and f.category == "Auth"
    assert f.file == "src/auth.ts" and f.line == 3


def test_run_llm_scan_skips_rubric_with_no_matching_files():
    buf = make_zip({"README.md": b"# hi"})  # not a code file at all
    findings, stats = run_llm_scan(buf, FakeLLM("[]"))
    assert findings == [] and stats.prompts == 0


# --- client fallback chain ---

def test_client_falls_back_to_second_provider(monkeypatch):
    # 500 on the primary is now retried (TRANSIENT_RETRIES times)
    # before falling back — the extra calls are the new contract.
    from app.llm import client as client_mod
    monkeypatch.setattr(client_mod, "RETRY_BACKOFF_S", 0.0)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "primary.example":
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={
            "content": [{"type": "text", "text": "[]"}]
        })

    client = LLMClient(
        providers=[
            Provider("openai_compat", "https://primary.example/v1", "k1", "m"),
            Provider("anthropic", "https://api.anthropic.com", "k2", "m"),
        ],
        transport=httpx.MockTransport(handler),
    )
    assert client.complete("s", "u") == "[]"
    assert calls == ["primary.example"] * 3 + ["api.anthropic.com"]


def test_cross_rubric_dedup_keeps_most_severe():
    from app.scan.cross_rubric_dedup import dedup_cross_rubric
    from app.scan.scoring import ScoredFinding

    def f(rubric, sev, conf):
        return ScoredFinding(rule_id=f"llm-{rubric}", title="cron secret",
                             severity=sev, confidence=conf,
                             category="Auth", file="m/0001.sql", line=6)

    out = dedup_cross_rubric([f("auth", "high", 0.98),
                              f("security", "medium", 0.9)])
    assert len(out) == 1
    assert out[0].severity == "high"

    # lines far apart (beyond the nearby-line window) are different
    # findings — not collapsed. (Adjacent same-issue lines now DO merge;
    # see tests/test_cross_rubric_dedup.py.)
    from dataclasses import replace
    out2 = dedup_cross_rubric([f("auth", "high", 0.9),
                               replace(f("security", "high", 0.9), line=40)])
    assert len(out2) == 2


def test_transient_5xx_retried_then_succeeds(monkeypatch):
    from app.llm import client as client_mod
    from app.llm.client import LLMClient, Provider

    monkeypatch.setattr(client_mod, "RETRY_BACKOFF_S", 0.0)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(500, text="upstream hiccup")
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "[]"}}]})

    c = LLMClient(
        providers=[Provider("openai_compat", "https://fake", "k", "m")],
        transport=httpx.MockTransport(handler))
    assert c.complete("s", "u") == "[]"
    assert calls["n"] == 3  # 500, 500, 200


def test_4xx_not_retried(monkeypatch):
    import pytest as _pytest
    from app.llm import client as client_mod
    from app.llm.client import LLMClient, LLMError, Provider

    monkeypatch.setattr(client_mod, "RETRY_BACKOFF_S", 0.0)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(400, text="bad model name")

    c = LLMClient(
        providers=[Provider("openai_compat", "https://fake", "k", "m")],
        transport=httpx.MockTransport(handler))
    with _pytest.raises(LLMError):
        c.complete("s", "u")
    assert calls["n"] == 1  # our request is wrong; retrying is spam


def test_union_of_two_passes_merges_and_dedups(monkeypatch):
    """passes=2 doubles the prompts and unions the findings: stable
    findings collapse via (file, line) dedup, pass-unique ones are
    kept — the paid Fix Pack completeness mode."""
    import io
    import zipfile as _zipfile
    from app.scan.llm_scan import run_llm_scan

    buf = io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        # содержимое матчит ОБЕ рубрики: auth (token) и security (env, fetch)
        zf.writestr("src/auth.ts",
                    "const token = await fetch(process.env.API_URL)\n")
    buf.seek(0)

    responses = iter([
        # pass 1: auth, security
        '[{"file":"src/auth.ts","line_start":1,"line_end":1,'
        '"evidence":"const token = await fetch","severity":"high",'
        '"confidence":0.9,"title":"stable finding","explanation":"","fix_hint":""}]',
        '[]',
        # pass 2: та же stable + уникальная для второго прохода
        '[{"file":"src/auth.ts","line_start":1,"line_end":1,'
        '"evidence":"const token = await fetch","severity":"high",'
        '"confidence":0.9,"title":"stable finding","explanation":"","fix_hint":""}]',
        '[{"file":"src/auth.ts","line_start":1,"line_end":1,'
        '"evidence":"const token = await fetch","severity":"low",'
        '"confidence":0.5,"title":"pass-2-only finding","explanation":"","fix_hint":""}]',
    ])

    class FakeClient:
        providers = [object()]
        def complete(self, system, user, max_tokens=4096):
            return next(responses)

    findings, stats = run_llm_scan(io.BytesIO(buf.getvalue()), FakeClient(),
                                   passes=2)
    assert stats.prompts == 4          # 2 рубрики × 2 прохода
    # оба ответа указывают на одну (file, line): дедуп оставил тяжёлую
    assert len(findings) == 1
    assert findings[0].severity == "high"
