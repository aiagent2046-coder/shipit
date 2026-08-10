"""Tests for the LLM scan stage. All LLM calls are mocked.

The verification tests are the heart of this stage: a hallucinated
finding must never reach the user.
"""

import hashlib
import io
import json
import re
import zipfile

import httpx
import pytest

from app.llm.client import LLMClient, LLMUsage, Provider
from app.scan.llm_scan import (
    RUBRICS,
    SYSTEM_PROMPT,
    LLMScanStats,
    build_prompt,
    clip,
    parse_findings,
    run_llm_scan,
    select_files,
    verify_finding,
)
from app.scan.pipeline import AUDIT_ENGINE_VERSION
from app.scan.scoring import CATEGORIES

# sha256 of the LLM-visible prompt surface, first 16 hex characters. Paired
# with AUDIT_ENGINE_VERSION by test_changing_the_prompt_forces_an_engine_
# version_bump at the bottom of this file, which explains what to do when it
# fails.
PROMPT_FINGERPRINT = "60758795318d2fd8"

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
    """Returns a canned response; records the prompts it received. Reports a
    fixed usage per call so the scan's cost-accounting aggregation is
    exercised."""

    def __init__(self, response: str):
        super().__init__(providers=[])
        self.response = response
        self.prompts: list[str] = []

    def complete(self, system: str, user: str,
                 max_tokens: int = 4096) -> tuple[str, LLMUsage]:
        self.prompts.append(user)
        return self.response, LLMUsage(
            model="fake-model", input_tokens=100, output_tokens=20)


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


@pytest.mark.parametrize("bad_confidence", ["very-high", None, [0.9], {"v": 0.9}])
def test_verify_rejects_non_numeric_confidence(bad_confidence):
    # Regression: verify_finding used to accept any type here and let
    # float(f["confidence"]) crash downstream in run_llm_scan, turning one
    # malformed field from the model into a 500 for the whole scan instead
    # of a discarded finding -- after the LLM call had already been paid for.
    assert not verify_finding(valid_finding(confidence=bad_confidence), FILES)


def test_verify_rejects_unhashable_file():
    # Regression: files.get(f["file"]) raises TypeError, not returns None,
    # when f["file"] is a list/dict -- that crashed verify_finding itself
    # rather than returning False.
    assert not verify_finding(valid_finding(file=["src/auth.ts"]), FILES)


# --- rubric -> score category wiring ---

def test_every_rubric_scores_into_a_category_the_scorer_knows():
    # A rubric whose category is not in CATEGORIES contributes to no subscore:
    # compute_scores iterates CATEGORIES, so those findings are displayed but
    # score as free. Asserted at import in llm_scan; pinned here so the reason
    # is written down where a future rubric author will look.
    for name, rubric in RUBRICS.items():
        assert rubric["category"] in CATEGORIES, f"{name} scores nowhere"


def test_findings_take_the_category_their_rubric_declares(monkeypatch):
    """A third rubric must land in its own category, not be inferred into Auth.

    The call site used to read `"Security" if rubric == "security" else
    "Auth"`. With only the two shipped rubrics that binary is indistinguishable
    from the declared mapping, so no existing test can tell them apart -- the
    bug only appears the moment a third rubric exists, silently filing every
    one of its findings under Auth. This test supplies that third rubric.
    """
    monkeypatch.setitem(RUBRICS, "cost", {
        "category": "Deploy",
        "keywords": re.compile(r"jwt|token", re.I),
        "instructions": "irrelevant, the LLM is stubbed",
    })
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})

    findings, _ = run_llm_scan(
        buf, FakeLLM(json.dumps([valid_finding()])), rubrics=("cost",))

    assert [f.category for f in findings] == ["Deploy"]
    assert findings[0].rule_id == "llm-cost"


# --- end to end with mocked LLM ---

def test_run_llm_scan_keeps_verified_drops_hallucinated():
    response = json.dumps([
        valid_finding(),
        valid_finding(file="src/invented.ts", title="hallucination"),
    ])
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})
    findings, stats = run_llm_scan(buf, FakeLLM(response), rubrics=("auth",))

    assert stats == LLMScanStats(
        prompts=1, raw_findings=2, verified=1, discarded=1,
        calls=1, input_tokens=100, output_tokens=20, model="fake-model")
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
    text, _usage = client.complete("s", "u")
    assert text == "[]"
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
    text, _usage = c.complete("s", "u")
    assert text == "[]"
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
            return next(responses), LLMUsage(model="fake-model")

    findings, stats = run_llm_scan(io.BytesIO(buf.getvalue()), FakeClient(),
                                   passes=2)
    assert stats.prompts == 4          # 2 рубрики × 2 прохода
    # оба ответа указывают на одну (file, line): дедуп оставил тяжёлую
    assert len(findings) == 1
    assert findings[0].severity == "high"


# --- non-production context damping ---
#
# The static rules damp a credential found in tests/ to medium; the LLM pass
# used to rate the identical line critical at full weight, and both reached
# the report because dedup_cross_rubric never merges across producers.

def _scan_one(path: str, **overrides):
    """Run one verified finding at `path` through the scan, return it."""
    response = json.dumps([valid_finding(file=path, **overrides)])
    buf = make_zip({path: VULN_TS.encode()})
    findings, _ = run_llm_scan(buf, FakeLLM(response), rubrics=("auth",))
    assert len(findings) == 1, f"expected one finding for {path}"
    return findings[0]


def test_llm_finding_in_test_path_is_damped_not_dropped():
    f = _scan_one("tests/auth.test.ts")
    assert f.severity == "medium"          # capped, exactly like the static rules
    assert f.confidence == 0.32            # 0.9 * 0.35
    assert f.context == "test_file"        # so the report groups it explicitly


def test_llm_finding_in_docs_is_damped():
    f = _scan_one("docs/auth.ts")
    assert f.severity == "medium"
    assert f.context == "doc_example"


def test_llm_finding_in_production_path_is_untouched():
    f = _scan_one("src/auth.ts")
    assert f.severity == "critical"
    assert f.confidence == 0.9
    assert f.context is None


def test_llm_finding_in_migration_keeps_full_severity():
    """A migration is applied state. is_non_production_path excludes it, and
    the damper must make the same exception or the two disagree."""
    f = _scan_one("migrations/0001_init.ts")
    assert f.severity == "critical"
    assert f.context is None


def test_damping_agrees_with_path_predicate():
    """The damper and is_non_production_path are two answers to one question.
    They are separate functions, so pin that they never disagree."""
    from app.scan.secrets import (
        damp_for_non_production_path, is_non_production_path,
    )
    paths = [
        "tests/test_x.py", "src/app.py", "docs/guide.md", "migrations/0001.sql",
        "examples/demo.js", "__tests__/a.js", "app/main.py", "README.md",
        "test/helper.rb", "supabase/migrations/0002.sql", "fixtures/data.json",
    ]
    for p in paths:
        _, _, context = damp_for_non_production_path(p, "critical", 1.0)
        assert (context is not None) == is_non_production_path(p), p


def test_fixtures_alone_no_longer_zero_the_security_score():
    """The reason this exists. 14 undamped criticals cost 2.0 * confidence
    each against a category budget of 10, so a repo whose only findings were
    its own test fixtures scored Security 0.0 -- measured on this repository,
    where every one of them was a fixture and seven would have been enough."""
    from app.scan.scoring import ScoredFinding, compute_scores
    from app.scan.secrets import damp_for_non_production_path

    paths = [f"tests/test_{i}.py" for i in range(14)]

    undamped = [ScoredFinding(rule_id="llm-security", title="Hardcoded credential",
                              severity="critical", confidence=0.8,
                              category="Security", file=p, line=1) for p in paths]
    assert compute_scores(undamped)["categories"]["Security"] == 0.0

    damped = []
    for p in paths:
        sev, conf, ctx = damp_for_non_production_path(p, "critical", 0.8)
        damped.append(ScoredFinding(rule_id="llm-security", title="Hardcoded credential",
                                    severity=sev, confidence=conf,
                                    category="Security", file=p, line=1, context=ctx))
    assert compute_scores(damped)["categories"]["Security"] > 8.0


# --- the money rubric, calibrated against its first real run ---------------
#
# Run on two repositories with known answers before this change. It found both
# ground-truth bugs, and two things it got wrong are pinned below so a later
# prompt edit cannot quietly undo them.

def test_the_money_rubric_calls_a_missing_idempotency_guard_critical():
    """It rated it `high`, and the score said the repo was fine.

    vercel/nextjs-subscription-payments has a webhook that re-provisions a
    subscription on Stripe's own retry. The rubric found it -- correctly, with
    the mechanism -- and graded it high, which put Money & Data at 7.1: one
    tenth above the gate. A repository that double-charges on a routine
    provider retry presented a passing headline.

    The provider's retry is not a risk, it is a scheduled event, so the
    duplicate is certain rather than possible. That is what critical means
    here, and saying so in the prompt is what moves the verdict.
    """
    instructions = RUBRICS["money"]["instructions"]

    assert "idempotency guard is CRITICAL" in instructions
    assert "not high" in instructions


def test_the_money_rubric_excludes_costs_that_land_in_the_browser():
    """It reported a 16-minute setTimeout in a toast component.

    A real bug, and not this rubric: the owner loses no money, no data, and
    pays no bill for it. The rubric is read by someone deciding what to fix
    before launch, and a finding they will not act on costs the attention of
    the one above it.
    """
    instructions = RUBRICS["money"]["instructions"]

    assert "browser" in instructions
    assert "Do NOT report anything whose whole cost lands" in instructions


def test_the_money_rubric_still_refuses_attacker_findings():
    """The older exclusion, kept: the auth and security rubrics cover those,
    and a duplicate here spends a finding slot twice."""
    instructions = RUBRICS["money"]["instructions"]

    assert "Do NOT report attacker-driven vulnerabilities" in instructions


def test_the_money_rubric_grades_low_by_size_not_by_how_long_it_takes():
    """The first wording cost a real finding its severity.

    "Reserve low for something that costs the owner real money only after a
    year of growth" reads as "anything that accrues over a year is low" --
    and the model applied it exactly: blitz-blueprint's match_events, an
    append-only table taking every shot and kill in every match, fell from
    high to low. It gathers millions of rows a MONTH; the bill is real, it
    just arrives gradually.

    Low is for a cost that stays small even after that year, not for one
    that merely takes a year to add up.
    """
    instructions = RUBRICS["money"]["instructions"]

    assert "stays SMALL even after a year" in instructions
    assert "not when it merely takes a year to add up" in instructions


# --- clipping long model output ---
#
# The caps are not new; the honest cut is. A plain `[:600]` ended the CRITICAL
# finding of a real paid audit on dubinc/dub mid-word, and that finding is the
# one that gated the whole score.

# Exactly 600 characters, as it reached the customer's report.
DUB_CRITICAL_EXPLANATION = (
    "The function sends money to partners via PayPal using the invoice ID as "
    "the sender_batch_id (which PayPal uses for idempotency), but the calling "
    "code does not check whether the invoice has already been paid before "
    "invoking this function. If the cron job or webhook that triggers payouts "
    "fires twice (normal for any queued job), PayPal will reject the second "
    "call with a duplicate error — but only if the batch_id is truly unique "
    "per attempt. More critically, nothing in the visible code marks the "
    "invoice as 'sent' before or atomically with the API call, so a retry "
    "after a partial failure can re-send"
)


def test_clip_leaves_text_within_the_limit_alone():
    assert clip("short", 600) == "short"
    assert clip("x" * 600, 600) == "x" * 600


def test_clip_cuts_on_a_word_boundary_and_marks_the_cut():
    assert clip("alpha beta gamma delta", 16) == "alpha beta…"


def test_clip_never_exceeds_the_limit_it_was_given():
    """The ellipsis comes out of the budget, not on top of it. Otherwise a
    field clipped to a column width overflows it by one character."""
    for limit in range(2, 40):
        assert len(clip("alpha beta gamma delta epsilon", limit)) <= limit


def test_clip_falls_back_to_a_hard_cut_on_an_unbroken_run():
    """A base64 blob or a minified line has no boundary to fall back to.
    Mid-token beats returning nothing."""
    assert clip("x" * 50, 10) == "x" * 9 + "…"


def test_clip_does_not_leave_dangling_punctuation():
    """"...the call, ..." reads as a transcription error rather than a cut."""
    assert clip("we call the thing, and then we wait", 20) == "we call the thing…"


def test_the_real_critical_explanation_now_reads_as_cut():
    """The regression case, verbatim. Before this it ended `can re-sen`, and
    a reader could not tell truncation from a model that lost the thread."""
    clipped = clip(DUB_CRITICAL_EXPLANATION + " to the partner a second time.",
                   600)

    assert clipped.endswith("…")
    assert not clipped.endswith("re-sen…")
    assert len(clipped) <= 600


def test_a_long_explanation_is_already_clipped_on_the_finding(monkeypatch):
    """End to end: the clip has to happen where the ScoredFinding is built, or
    every consumer downstream -- report, HTML, database -- gets the raw cut."""
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})
    response = json.dumps([valid_finding(
        explanation="word " * 400, fix_hint="fix " * 200, title="head " * 100)])

    findings, _ = run_llm_scan(buf, FakeLLM(response), rubrics=("auth",))

    f = findings[0]
    assert len(f.explanation) <= 600 and f.explanation.endswith("…")
    assert len(f.fix_hint) <= 300 and f.fix_hint.endswith("…")
    assert len(f.title) <= 200 and f.title.endswith("…")


# --- the money rubric must not state inferences as facts ---


def test_the_money_rubric_demands_the_line_that_proves_the_claim():
    """Three findings in a row on dubinc/dub read as statements of fact and
    were inferences. Two happened to be right; the third was wrong, and a
    reader had to open the repository to find that out."""
    instructions = RUBRICS["money"]["instructions"]

    assert "PROVES the claim" in instructions
    assert "confidence 0.5 or lower" in instructions
    assert "Never write an assumption in the voice of something you read" in (
        instructions)


def test_the_money_rubric_names_the_wrapper_trap():
    """The one that was actually wrong: getWebhookEvents passes no limit, so
    the model reported an unbounded query. The `limit 100` was in the Tinybird
    pipe file, which it had not been shown."""
    instructions = RUBRICS["money"]["instructions"]

    assert "does not pass an option does not prove the option is unset" in (
        instructions)
    assert "pipe file" in instructions


def test_changing_the_prompt_forces_an_engine_version_bump():
    """Nothing else catches a forgotten bump, and the cost is silent.

    AUDIT_ENGINE_VERSION is part of the audit cache key, so a prompt edit that
    ships without one keeps serving results produced by the OLD prompt for
    every repository already audited — the improvement is real, paid for, and
    invisible. The whole suite passes in that state; verified by reverting the
    bump on this very change and watching 1475 tests stay green.

    So the prompt surface is fingerprinted here. When this fails you changed
    what the model is asked, which means:

      1. bump AUDIT_ENGINE_VERSION in app/scan/pipeline.py, and
      2. paste the new fingerprint below.

    Two lines of ceremony, deliberately. Step 1 is the one that matters and
    the one nobody remembers.
    """
    surface = SYSTEM_PROMPT + "".join(
        name + RUBRICS[name]["instructions"] for name in sorted(RUBRICS)
    )
    fingerprint = hashlib.sha256(surface.encode("utf-8")).hexdigest()[:16]

    assert fingerprint == PROMPT_FINGERPRINT, (
        f"the LLM prompt changed (fingerprint {fingerprint}). Bump "
        f"AUDIT_ENGINE_VERSION in app/scan/pipeline.py -- it is currently "
        f"{AUDIT_ENGINE_VERSION!r} -- then update PROMPT_FINGERPRINT in this "
        "file. Without the bump, every repository already audited keeps "
        "receiving results from the old prompt."
    )
