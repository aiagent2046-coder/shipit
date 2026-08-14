"""Tests for the LLM scan stage. All LLM calls are mocked.

The verification tests are the heart of this stage: a hallucinated
finding must never reach the user.
"""

import dataclasses
import hashlib
import inspect
import io
import json
import re
import zipfile

import httpx
import pytest

from app.llm.client import LLMClient, LLMUsage, Provider
from app.scan import llm_scan
from app.scan.llm_scan import (
    RUBRICS,
    SYSTEM_PROMPT,
    LLMScanStats,
    BEHAVIOUR,
    PRESENTATION,
    build_prompt,
    clip,
    parse_findings,
    relevance,
    run_llm_scan,
    select_files,
    verify_finding,
)
from app.scan.pipeline import AUDIT_ENGINE_VERSION
from app.scan.scoring import CATEGORIES

# sha256 of everything that decides what the model is shown -- the prompts,
# and the file selection that fills them. First 16 hex characters. Paired with
# AUDIT_ENGINE_VERSION by the test at the bottom of this file, which explains
# what to do when it fails.
PROMPT_FINGERPRINT = "6f4df84af4982d39"

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


# --- selection order ---
#
# select_files used to sort matches by ascending size and fill the budget from
# the small end. On dubinc/dub that meant 1261 files matched the money rubric,
# 347 fitted, and the cut fell at 1804 characters -- so the entire payout
# pipeline was invisible to the model while icons and email templates were not.


def test_a_long_relevant_file_beats_a_pile_of_short_ones():
    """The regression in one assertion. Under ascending-size order the twenty
    stubs win on count and the handler never reaches the prompt; it is the
    handler that can pay a partner twice."""
    handler = ("apps/lib/payouts/send-payout.ts",
               "stripe payout invoice refund idempotency " * 200)
    stubs = [(f"apps/ui/icons/payout-{i}.tsx", "payout icon " * 5)
             for i in range(20)]

    names = [n for n, _ in select_files(stubs + [handler], "money")]

    assert names[0] == handler[0]


def test_short_files_still_reach_the_prompt():
    """The breadth reserve. retally-payouts-amount.ts is 900 characters and
    scores below the relevance cut, and it carries a real finding -- a pure
    relevance order drops it for forty large handlers."""
    handlers = [(f"apps/lib/payouts/handler-{i}.ts",
                 "stripe payout invoice refund idempotency webhook " * 400)
                for i in range(30)]
    small = ("apps/lib/payouts/retally.ts", "payout aggregate then update")

    names = [n for n, _ in select_files(handlers + [small], "money")]

    assert small[0] in names


def test_presentation_paths_lose_to_behaviour_paths():
    """Both say "payout" the same number of times. Only one sends money."""
    body = "payout invoice stripe refund " * 40
    files = [("apps/ui/partners/payout-card.tsx", body),
             ("apps/lib/payouts/pay.ts", body)]

    names = [n for n, _ in select_files(files, "money")]

    assert names.index("apps/lib/payouts/pay.ts") < names.index(
        "apps/ui/partners/payout-card.tsx")


def test_one_oversized_file_does_not_end_the_selection():
    """The old loop used `break`, which was equivalent only because the sort
    was ascending -- nothing after the first overflow could fit either. In any
    other order it silently discards every remaining file."""
    huge = ("apps/lib/payouts/huge.ts", "payout stripe " * 20_000)
    small = ("apps/lib/payouts/small.ts", "payout stripe invoice")

    names = [n for n, _ in select_files([huge, small], "money")]

    assert small[0] in names


def test_selection_does_not_depend_on_archive_order():
    """The audit cache is keyed on a content hash. Two byte-identical
    repositories whose zips list members in a different order must select the
    same files, or the same key yields two different scores."""
    files = [(f"apps/lib/payouts/f{i}.ts", f"payout invoice {'x' * (i * 30)}")
             for i in range(25)]

    forward = select_files(files, "money")
    backward = select_files(list(reversed(files)), "money")

    assert forward == backward


def test_tinybird_pipe_files_are_readable():
    """The file that disproved a false positive and could not reach the model:
    `limit 100` lives in the .pipe, not in the TypeScript that calls it."""
    buf = make_zip({"packages/tinybird/pipes/events.pipe":
                    b"SELECT * FROM events WHERE webhook_id = {{String(id)}}\nlimit 100"})

    with zipfile.ZipFile(buf) as zf:
        names = [n for n, _ in llm_scan._iter_code_files(zf)]

    assert names == ["packages/tinybird/pipes/events.pipe"]


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

    # Rubrics named explicitly, not left to the default. This is a test about
    # `passes`, and the canned responses above are positional -- so under the
    # default roster it breaks every time a rubric is added, which is what
    # happened when "web" shipped: the fixture's `fetch(` matches its keywords
    # too, so six calls met four responses and the failure pointed here
    # instead of at the roster. Pinning the two keeps the subject singular.
    findings, stats = run_llm_scan(io.BytesIO(buf.getvalue()), FakeClient(),
                                   rubrics=("auth", "security"), passes=2)
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


def test_changing_what_the_model_sees_forces_an_engine_version_bump():
    """Nothing else catches a forgotten bump, and the cost is silent.

    AUDIT_ENGINE_VERSION is part of the audit cache key, so a change that
    ships without one keeps serving results produced by the OLD engine for
    every repository already audited — the improvement is real, paid for, and
    invisible. The whole suite passes in that state; verified by reverting the
    bump and watching every test stay green.

    The fingerprint covers everything that decides what the model is asked,
    which is deliberately wider than the prompt text. It was prompt-only when
    first written, and the very next change proved that too narrow: rewriting
    file SELECTION changes the findings completely while leaving every word of
    the prompt untouched. A guard that misses the change it was written one
    commit before is not a guard.

    When this fails:

      1. bump AUDIT_ENGINE_VERSION in app/scan/pipeline.py, and
      2. paste the new fingerprint below.

    Two lines of ceremony. Step 1 is the one that matters and the one nobody
    remembers.

    Step 1 has exactly one honest exception: a change that provably cannot
    alter what any SHIPPED rubric is shown -- adding a parameter whose default
    reproduces the old behaviour, say. Then bumping would re-run the LLM
    against every cached audit to produce identical results. Take the
    exception only with a test that pins the old behaviour, and say so in the
    commit; "I thought it was equivalent" is not the same as having shown it.
    """
    surface = "|".join([
        SYSTEM_PROMPT,
        *(name + RUBRICS[name]["instructions"] for name in sorted(RUBRICS)),
        # WHICH rubrics are asked, not only what each one says. Missing here
        # until "web" shipped without being run: its text was in the surface,
        # so the fingerprint moved and the engine version was bumped, while
        # run_llm_scan's own default still named three rubrics and never
        # called it. Every guard fired and none of them was about the roster.
        repr(llm_scan.ALL_RUBRICS),
        repr(inspect.signature(run_llm_scan).parameters["rubrics"].default),
        # What reaches the prompt at all, and in what order.
        repr(llm_scan._CODE_SUFFIXES),
        repr(llm_scan._SKIP_DIRS),
        llm_scan._BEHAVIOUR_PATH.pattern,
        llm_scan._PRESENTATION_PATH.pattern,
        str(llm_scan.MAX_FILE_CHARS),
        str(llm_scan.MAX_TOTAL_CHARS),
        str(llm_scan.RELEVANCE_BUDGET_SHARE),
        inspect.getsource(llm_scan.relevance),
        inspect.getsource(llm_scan.select_files),
        # How a file that does not fit is cut, and what the cut says. Added
        # after an off-by-one in the withheld-line count changed the text the
        # model reads and this guard stayed silent: MAX_FILE_CHARS was in the
        # surface, so the cap was watched, while the function applying it was
        # not. Anything that decides the CHARACTERS in the prompt belongs here,
        # not only the constants that bound them.
        llm_scan.TRUNCATION_MARKER,
        inspect.getsource(llm_scan.truncate_at_line),
    ])
    fingerprint = hashlib.sha256(surface.encode("utf-8")).hexdigest()[:16]

    assert fingerprint == PROMPT_FINGERPRINT, (
        f"what the model is shown changed (fingerprint {fingerprint}). Bump "
        f"AUDIT_ENGINE_VERSION in app/scan/pipeline.py -- it is currently "
        f"{AUDIT_ENGINE_VERSION!r} -- then update PROMPT_FINGERPRINT in this "
        "file. Without the bump, every repository already audited keeps "
        "receiving results from the old engine."
    )


# --- path weighting is per rubric ---


def test_no_rubric_written_before_the_parameter_changes_its_path_weighting():
    """The safety assertion for making this a parameter at all.

    Every rubric that existed before `lives_in` must keep selecting the files
    it always did, or this quietly changes what a paying customer receives.
    None of the three declares the key, so all three take the BEHAVIOUR
    default, which is the weighting they were written and measured under.

    Named rather than derived: `web` shipped later and is the reason the
    parameter exists, so "every rubric" would now be false and iterating
    RUBRICS would make this test disappear the moment it mattered. A fourth
    BEHAVIOUR rubric added tomorrow is not this test's business; a change to
    one of these three is.
    """
    for name in ("auth", "security", "money"):
        assert RUBRICS[name].get("lives_in", BEHAVIOUR) == BEHAVIOUR, name

    assert RUBRICS["web"]["lives_in"] == PRESENTATION, (
        "the web rubric is the reason lives_in exists; under BEHAVIOUR it "
        "would be shown ui/ and components/ divided by four"
    )


def test_the_default_weighting_is_unchanged_by_the_parameter():
    files = [("apps/lib/payouts/pay.ts", "payout stripe invoice " * 20),
             ("apps/ui/payouts/card.tsx", "payout stripe invoice " * 20)]

    assert select_files(files, "money") == select_files(files, "money")

    kw = RUBRICS["money"]["keywords"]
    for name, text in files:
        assert relevance(name, text, kw) == relevance(name, text, kw, BEHAVIOUR)


def test_a_presentation_rubric_sees_the_frontend_first(monkeypatch):
    """The point of the whole change. A rubric about what the user sees --
    a white screen with no error boundary, a form that double-submits -- lives
    in ui/ and components/, which the single global weighting divided by four.
    It would have been shown everything except its own subject.
    """
    monkeypatch.setitem(RUBRICS, "web", {
        "category": "Deploy",
        "keywords": re.compile(r"button|form|submit|render", re.I),
        "instructions": "stubbed",
        "lives_in": PRESENTATION,
    })
    body = "submit button form render " * 30
    files = [("apps/lib/api/submit.ts", body),
             ("apps/ui/components/form.tsx", body)]

    names = [n for n, _ in select_files(files, "web")]

    assert names[0] == "apps/ui/components/form.tsx"


def test_the_same_files_under_a_behaviour_rubric_order_the_other_way(monkeypatch):
    """The mirror, so the test above cannot pass by accident on tie-breaks."""
    monkeypatch.setitem(RUBRICS, "web", {
        "category": "Deploy",
        "keywords": re.compile(r"button|form|submit|render", re.I),
        "instructions": "stubbed",
        "lives_in": BEHAVIOUR,
    })
    body = "submit button form render " * 30
    files = [("apps/ui/components/form.tsx", body),
             ("apps/lib/api/submit.ts", body)]

    names = [n for n, _ in select_files(files, "web")]

    assert names[0] == "apps/lib/api/submit.ts"


def test_the_scan_runs_every_rubric_that_exists():
    """The defect this file could not see, because it only ever checked what
    the rubrics say rather than whether they are asked.

    `run_llm_scan`'s rubric list was a literal in its own signature --
    ("auth", "security", "money") -- so adding a fourth to RUBRICS did not run
    it. The "web" rubric shipped that way and reached production: in the dict,
    mapped to the Frontend category, inside PROMPT_FINGERPRINT, counted in the
    cost cap, and never called once.

    Nothing caught it. PROMPT_FINGERPRINT moved, because the rubric's text is
    part of what the model would be shown. The category assertion passed,
    because Frontend is a category the scorer knows. LLM_ONLY_CATEGORIES did
    not help either: it marks a category unexamined when the LLM did not run,
    and the LLM did run -- for the other three. The audit reported
    `unexamined: []` beside `Frontend: 10.0`, a perfect score from a rubric
    that had not looked.
    """
    default = inspect.signature(run_llm_scan).parameters["rubrics"].default

    assert set(default) == set(RUBRICS), (
        f"run_llm_scan runs {sorted(set(default))} but RUBRICS defines "
        f"{sorted(RUBRICS)}; a rubric that is defined and not run scores its "
        f"category a silent 10.0"
    )
    assert tuple(default) == llm_scan.ALL_RUBRICS


def test_the_rubric_list_is_derived_rather_than_written_out():
    """The assertion above is satisfiable by editing a literal, which is what
    someone will do at 2am when a fifth rubric is added and this fails. The
    list has to come from the dict, so adding a rubric is one edit and not
    two."""
    source = inspect.getsource(llm_scan)

    assert "ALL_RUBRICS: tuple[str, ...] = tuple(RUBRICS)" in source
    assert '= ("auth", "security", "money")' not in source


def test_every_rubric_selects_something_from_a_frontend_repository():
    """The narrower half of the same worry: a rubric that runs but whose
    keywords match nothing contributes no findings either, and looks identical
    from the outside. digital-rolecraft is 102 files of Vite/React with no
    backend, which is where the web rubric is meant to earn its place."""
    files = [
        ("src/App.tsx",
         "const App = () => (<QueryClientProvider client={queryClient}>"
         "<BrowserRouter><Routes/></BrowserRouter></QueryClientProvider>)"),
        ("src/components/SimulatorChat.tsx",
         "const [isGenerating, setIsGenerating] = useState(false);\n"
         "await generatePersonaResponse(); setIsGenerating(false);"),
        ("src/lib/auth.ts", "const token = localStorage.getItem('session')"),
    ]

    assert [n for n, _ in select_files(files, "web")], (
        "the web rubric selected nothing from a frontend repository"
    )


# --- the three defects that survived the fifth measured run ---
#
# Two are prose, because they are about how the model reasons. The third is a
# filter, because prose had already been tried on it and reached 20 of 21.


def test_a_finding_whose_own_fix_says_nothing_to_do_is_dropped():
    """Measured once in twenty-one on dubinc/dub: "[LOW conf=0.95] setInterval
    for draft saving is correctly cleaned up ... fix: No action needed."

    The instructions already forbid this in as many words. Once per run is
    still a reader paying for a list of repairs and finding an item that needs
    none -- and it costs them more than the wasted line, because it teaches
    them to trust the rest of the list less.
    """
    for hint in (
        "No action needed — the ref guard is correct.",
        "No action needed.",
        "The existing disabled prop already prevents double-clicks. "
        "No change needed.",
        "This is actually correct; nothing to fix.",
        "No issue here.",
    ):
        assert llm_scan.self_cancelling({"fix_hint": hint}), hint


def test_a_real_fix_is_not_mistaken_for_a_withdrawal():
    """The filter's whole risk. Matched on fix_hint alone for this reason: an
    explanation may say "there is no issue with the ref guard, but the button
    ..." on its way to a real defect, while a genuine repair instruction has no
    reason to contain any of these phrases."""
    for hint in (
        "Add `await` before handleRequest(e, updateName, router).",
        "Wrap the await call in try/finally and clear the flag in finally.",
        "Pass disabled={isSubmitting} alongside loading={isSubmitting}.",
        "",
    ):
        assert not llm_scan.self_cancelling({"fix_hint": hint}), hint

    # An explanation that discusses a non-issue on the way to a real one.
    assert not llm_scan.self_cancelling({
        "fix_hint": "Add a cleanup function.",
        "explanation": "No action needed for the ref, but the timer leaks.",
    })


def test_the_withdrawn_finding_is_counted_apart_from_the_unverifiable_one():
    """`discarded` counts a claim about code the verifier could not find;
    `self_cancelled` counts a claim the model withdrew in the same breath it
    made it. One counter for both would hide whichever is rarer, and this was
    rare -- one in twenty-one -- and still reached a paying reader."""
    stats = LLMScanStats()

    assert stats.self_cancelled == 0
    assert "self_cancelled" in {f.name for f in
                                dataclasses.fields(LLMScanStats)}


def test_a_conditional_hook_needs_the_code_that_changes_the_branch():
    """Navlinks.tsx:16 and EmailSignIn.tsx:22, both reported at 0.95 as
    crashes that would blank the page for every visitor. Both really do call
    useRouter() inside a ternary. Neither crashes: the condition is computed
    once from a build-time setting, so hook order never changes.

    The previous wording let both through by naming "a prop" as qualifying --
    and `redirectMethod` IS a prop. Being a prop is not the property that
    matters; changing is.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "NAME THE CODE THAT CHANGES IT" in instructions
    assert "even though it IS a prop" in instructions
    assert "'It might change'" in instructions


def test_a_stuck_flag_finding_must_name_the_branch_that_leaks():
    """add-edit-domain-form.tsx:307, reported as "setIsSubmitting(false) is
    never called on the success path -- only on the error paths". It is called
    on the success path and in the catch; if anything leaks it is the early
    return when the response is not ok. Reporting the inverse of what the file
    says is worse than a miss, because the reader can check it in ten
    seconds."""
    instructions = RUBRICS["web"]["instructions"]

    assert "READ EVERY BRANCH" in instructions
    assert "quote the one that leaves it" in instructions
    assert "If every branch clears it, there is nothing here" in instructions


def test_the_scan_actually_applies_the_withdrawal_filter():
    """The assertion M27 exposed as missing.

    The three tests above exercise `self_cancelling` as a pure function and
    none of them notices when run_llm_scan stops calling it -- deleting the
    two lines from the loop left the suite green. That is the same shape as
    the defect this session already shipped once: the web rubric existed in
    RUBRICS and was never called, and everything that tested the rubric's
    text passed.

    A predicate that is never invoked is not a filter. This runs the scan.
    """
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})
    withdrawn = json.dumps([{
        "file": "src/auth.ts", "line_start": 3, "line_end": 3,
        "evidence": "jwt.decode(token)", "severity": "low", "confidence": 0.95,
        "title": "Token decoding is correctly guarded",
        "explanation": "The caller verifies it first.",
        "fix_hint": "No action needed — the guard is correct.",
    }])

    findings, stats = run_llm_scan(buf, FakeLLM(withdrawn),
                                   rubrics=("auth",))

    assert findings == []
    assert stats.self_cancelled == 1
    assert stats.verified == 0
    assert stats.discarded == 0, (
        "a withdrawn finding is not an unverifiable one; counting it as "
        "discarded would hide it among the verifier's rejections"
    )


def test_a_real_finding_still_survives_the_filter():
    """The other half, on the same path: the filter must be invisible to
    everything that is not a withdrawal."""
    buf = make_zip({"src/auth.ts": VULN_TS.encode()})
    real = json.dumps([{
        "file": "src/auth.ts", "line_start": 3, "line_end": 3,
        "evidence": "jwt.decode(token)", "severity": "critical",
        "confidence": 0.9, "title": "JWT decoded without verification",
        "explanation": "No signature check.",
        "fix_hint": "Use jwt.verify with the shared secret.",
    }])

    findings, stats = run_llm_scan(buf, FakeLLM(real), rubrics=("auth",))

    assert len(findings) == 1
    assert stats.self_cancelled == 0
    assert stats.verified == 1


# --- the missing ownership check (BOLA) ---
#
# OWASP API Security Top 10 has this at number one, and it is what most real
# data leaks from an API actually are. The auth rubric named the adjacent
# things -- a route that mutates without checking the session, a user id taken
# from the client -- and not this one: the session IS checked, the caller IS
# who they say, and the query still returns someone else's row.


def test_the_auth_rubric_asks_for_the_ownership_check_not_only_the_session():
    """The two are different failures and the rubric conflated them by only
    naming one. `where id = $1` inside a handler that verified the session is
    a leak; the session check being present is exactly why it reads as safe.
    """
    instructions = RUBRICS["auth"]["instructions"]

    assert "missing OWNERSHIP check" in instructions
    assert "different thing from a missing session check" in instructions
    assert "user_id, owner_id, team_id or workspace_id" in instructions


def test_the_ownership_finding_is_proved_by_quoting_the_query():
    """Today's lesson, applied on the way in rather than after five runs: a
    claim that survives is one settled by reading lines. The proof here is two
    absences -- no owner column in the query, and no earlier line comparing
    the record's owner to the session -- and BOTH have to hold, or a handler
    that checks ownership on the line above gets reported anyway."""
    instructions = RUBRICS["auth"]["instructions"]

    assert "QUOTE the query" in instructions
    assert "one of them present means there is nothing to report" in instructions

    # The conjunction itself, not just a sentence about it. Weakening this
    # AND to an OR is the mutation that turns the rule into "report every
    # query without an owner column", which fires on every correctly guarded
    # handler that checks ownership on the line above -- and the first draft
    # of this test did not catch it, because the following sentence still
    # said "Both have to be missing" and the assertion matched that instead.
    assert "the owner column in it AND the absence of" in instructions


def test_the_rubric_knows_row_level_security_can_make_it_a_non_finding():
    """The exclusion that keeps this from firing on every correct Supabase
    route. A user-scoped client against an RLS table is filtered by the
    database, and the code is right to omit the owner column."""
    instructions = RUBRICS["auth"]["instructions"]

    assert "row-level security" in instructions
    assert "the database applies the filter" in instructions
    assert "It is NOT a finding" in instructions


def test_the_rubric_names_the_service_role_key_as_the_critical_case():
    """The signature failure of this customer segment. The author enables RLS,
    believes the database is enforcing ownership, and then reaches the table
    from a route with a service-role key -- which bypasses RLS entirely, so
    the policy protects nothing on that path."""
    instructions = RUBRICS["auth"]["instructions"]

    assert "service-role or admin key" in instructions
    assert "bypasses" in instructions
    assert "critical one" in instructions


# --- what the ownership rule's first measured run cost ---
#
# nextjs-subscription-payments, three findings, none of them a defect. The
# search was right -- it located every service-role call site and the one
# RLS-dependent query, which is exactly the set a reviewer would open. The
# verdict was wrong three times out of three: it reported the places instead
# of clearing them.


def test_the_auth_rubric_is_told_to_follow_the_id_to_its_origin():
    """The webhook case, which is the one that made the rule misfire hardest.

    A signature-verified Stripe webhook carries no user session, so
    manageSubscriptionStatusChange looks the customer up in a mapping table
    and writes with a service-role key. That is correct and is the only way it
    can work -- and it was reported HIGH 0.75 because the rule said
    "service-role plus an id" without saying "check where the id came from".
    """
    instructions = RUBRICS["auth"]["instructions"]

    assert "not by itself a finding" in instructions
    assert "FOLLOW THE ID" in instructions
    assert "mapping table" in instructions
    assert "is not caller-controlled and there" in instructions


def test_the_auth_rubric_carries_the_silence_rule_too():
    """Ported from the web rubric, where it was measured to be necessary. It
    was left out of the auth rule when the rest of the discipline was carried
    over, and the omission produced two of the three false findings on the
    first run."""
    instructions = RUBRICS["auth"]["instructions"]

    assert "report " in instructions and "NOTHING" in instructions
    assert "Silence is the correct output" in instructions
    assert "a caller that does not exist in these files" in instructions


def test_a_withdrawal_in_the_title_is_caught_too():
    """`fix_hint` was the documented place to match, and the auth run showed
    what that misses: a finding can withdraw itself in its own headline."""
    for title in (
        "Service-role client reads customers table — safe in normal flow "
        "but dangerous if called from any non-session path",
        "Retry payment: double-submit correctly guarded via ref",
        "setInterval for draft saving is correctly cleaned up",
        "Partner link modal: save button correctly disabled while loading",
        "No duplicate-submit risk on this handler",
        "This is actually correct",
    ):
        assert llm_scan.self_cancelling({"title": title}), title


def test_a_real_title_survives_the_withdrawal_filter():
    """The filter's whole risk, checked against titles measured today that
    were verified real by hand. A title pattern is more dangerous than a
    fix_hint pattern because every finding has a title."""
    for title in (
        "No error boundary wrapping the routes",
        "Missing await leaves in-flight flag cleared immediately",
        "getUserDetails query has no explicit user_id filter — relies "
        "entirely on RLS",
        "Hooks called after conditional early return — violates Rules of Hooks",
        "isGenerating flag never cleared when generatePersonaResponse throws",
        "Stripe checkout button not disabled while request is in flight",
        "Long persona form has no navigation guard",
    ):
        assert not llm_scan.self_cancelling({"title": title}), title


# --- plurals in rubric keywords ---
#
# A codebase names the file after the collection: coupons.py, migrations/,
# routers.tsx. Requiring the singular made the closing word boundary exclude
# the commonest spelling, and the boundary itself is not the problem -- it is
# what stops "discount" matching inside an unrelated identifier.
#
# Measured cost of the omission: on a ground-truth app the real
# read-then-decrement race lived in coupons.py, with an explicit sleep between
# the read and the write and no rowcount check. The money rubric never saw the
# file, and the model spent its finding on the correctly guarded twin instead.


def test_money_and_web_keywords_match_the_plural_spelling():
    files = [
        ("api/coupons.py", "def redeem(code): ..."),
        ("api/migrations/0001.py", "def upgrade(): ..."),
        ("api/coupon.py", "def redeem(code): ..."),
        ("src/routers.tsx", "export const routers = []"),
    ]

    money = [n for n, _ in select_files(files, "money")]
    assert "api/coupons.py" in money
    assert "api/migrations/0001.py" in money
    assert "api/coupon.py" in money        # the singular must keep working

    assert "src/routers.tsx" in [n for n, _ in select_files(files, "web")]


# --- a finding's category is a fact about the finding ---


def _one_finding_response(**overrides) -> str:
    f = {
        "file": "src/auth.ts",
        "line_start": 3,
        "line_end": 3,
        "evidence": "jwt.decode(token)",
        "severity": "high",
        "confidence": 0.9,
        "title": "Command injection in the token handler",
        "explanation": "...",
        "fix_hint": "...",
    }
    f.update(overrides)
    return json.dumps([f])


def test_finding_category_comes_from_the_finding_not_the_rubric():
    """19 findings once arrived under Auth and about 5 were about auth.

    The rest were SQL injection, command injection, unsafe deserialisation,
    SSTI, path traversal and an unauthenticated environment dump -- Security
    every one, filed as Auth because the auth rubric was the prompt that
    happened to be reading those files. The reader was told the app had an
    authentication problem when it had a remote code execution problem.
    """
    findings, stats = run_llm_scan(
        make_zip({"src/auth.ts": VULN_TS.encode()}),
        FakeLLM(_one_finding_response(category="Security")),
        rubrics=("auth",),
    )
    assert [f.category for f in findings] == ["Security"]
    assert stats.recategorised == 1


@pytest.mark.parametrize("declared", [None, "", "RCE", "Testing", "auth"])
def test_an_unusable_declared_category_falls_back_to_the_rubric(declared):
    """Including "Testing", which the scorer knows but no rubric produces.

    Letting a model post into a static-only category would change what that
    subscore means with no producer behind the change; a category the scorer
    does not know at all scores as free. Both fall back.
    """
    overrides = {} if declared is None else {"category": declared}
    findings, stats = run_llm_scan(
        make_zip({"src/auth.ts": VULN_TS.encode()}),
        FakeLLM(_one_finding_response(**overrides)),
        rubrics=("auth",),
    )
    assert [f.category for f in findings] == ["Auth"]
    assert stats.recategorised == 0


def test_the_prompt_offers_exactly_the_rubric_categories():
    for category in llm_scan.RUBRIC_CATEGORIES:
        assert f'"{category}"' in SYSTEM_PROMPT
    # Static-only categories must not be on offer.
    for category in set(CATEGORIES) - set(llm_scan.RUBRIC_CATEGORIES):
        assert f'"{category}"' not in SYSTEM_PROMPT


# --- truncation must not read as absence ---
#
# MAX_FILE_CHARS used to slice a file with t[:cap], mid-token, with nothing to
# say the file continued. On a real CRM that ended sales_kpi_board.py on
#
#     629    if sale is None or sale.company_id != compa
#
# and the engine reported "Manual sale payment patch missing ownership check"
# against a handler whose check the cut had removed. It was the only auth false
# positive in that run, and the engine manufactured it.


def test_truncation_cuts_on_a_line_boundary():
    text = "".join(f"line {i} padding padding\n" for i in range(400))
    out = llm_scan.truncate_at_line(text, 1_000)

    body, marker = out.rsplit("\n", 1)
    assert marker.startswith("[... truncated:")
    # No half-line survives: every line kept is a line the file really has.
    assert all(f"{ln}\n" in text for ln in body.splitlines())


def test_truncation_reports_how_many_lines_were_withheld():
    text = "".join(f"line {i}\n" for i in range(100))
    out = llm_scan.truncate_at_line(text, 200)

    kept = len(out.splitlines()) - 1          # minus the marker line
    withheld = int(re.search(r"truncated: (\d+) more", out).group(1))
    assert kept + withheld == len(text.splitlines())


def test_a_file_within_the_cap_is_untouched():
    text = "a\nb\nc\n"
    assert llm_scan.truncate_at_line(text, 1_000) == text
    assert "truncated" not in llm_scan.truncate_at_line(text, 1_000)


def test_selected_files_carry_the_marker_when_cut():
    big = ("api/auth/session.ts", "const token = 1  // session\n" * 6_000)
    selected = dict(select_files([big], "auth"))

    sent = selected["api/auth/session.ts"]
    assert len(sent) <= llm_scan.MAX_FILE_CHARS + len(llm_scan.TRUNCATION_MARKER) + 16
    assert "[... truncated:" in sent


def test_the_marker_fails_verification_rather_than_becoming_evidence():
    """A model that quotes the marker must be discarded, not believed."""
    files = {"src/auth.ts": VULN_TS}
    quoted = llm_scan.TRUNCATION_MARKER.format(n=120)
    assert not verify_finding(valid_finding(evidence=quoted), files)


def test_the_prompt_forbids_concluding_absence_from_a_truncated_file():
    assert "truncation marker" in SYSTEM_PROMPT
    assert "MISSING" in SYSTEM_PROMPT


def test_the_verifier_accepts_a_wrong_conclusion_about_real_code():
    """The scope of `discarded`, asserted so it stops being read as quality.

    Both false positives found by hand in real runs quoted real lines
    accurately and concluded something untrue about them. verify_finding
    measures whether the quoted code EXISTS, so it passes them -- correctly,
    because that is the question it answers. Anyone reading discarded == 0 as
    "the findings are right" is reading a different number than the one being
    reported.
    """
    files = {"src/auth.ts": VULN_TS}
    nonsense = valid_finding(
        title="This line mines cryptocurrency",
        explanation="It does not. The evidence below is real all the same.",
    )

    assert verify_finding(nonsense, files)


def test_a_hardcoded_credential_is_named_as_Security_in_the_prompt():
    """Measured, not guessed: across two runs of the same repository the
    hardcoded secrets at action_service.py:17 and action_service_fixed.py:19
    were found by the auth rubric and stayed in Auth, while five other
    findings per run DID move category. The model reclassifies readily; it
    treated a credential as within auth's remit because the prompt's list of
    examples never said otherwise."""
    assert "credential hardcoded in source" in SYSTEM_PROMPT
    assert 'are "Security" even when you find' in SYSTEM_PROMPT
