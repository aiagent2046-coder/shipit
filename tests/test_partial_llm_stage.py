"""What happens when the provider fails PART WAY through a scan.

Measured on Avisafety-1/blank-slate during a two-model comparison run. One
rubric took a 400 from the provider; run_llm_scan raised; and the whole LLM
stage was written off. The tokens the earlier rubrics had already spent were
recorded -- the accumulator is owned by the pipeline and survives an exception
-- while the findings those tokens bought died with the frame.

The result was an audit that scored 6.0 where the same repository scored 3.9
with its LLM stage intact: 38 findings became 5, and the report was at its most
reassuring exactly where it had broken. That is the failure this file exists to
keep fixed, and each test below names one part of it.
"""

import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.scan.llm_scan import ALL_RUBRICS, RUBRICS, run_llm_scan
from app.scan.pipeline import (BASIS_FULL, BASIS_PARTIAL, BASIS_STATIC_ONLY,
                               LLM_FAILURE_BILLING, LLM_FAILURE_PROVIDER,
                               _SCORED_FIELDS, llm_failure_kind, run_scan)
from app.scan.scoring import (LLM_ONLY_CATEGORIES, ScoredFinding,
                               compute_scores)

# Matches every rubric's keywords, so the order calls arrive in is the rubric
# declaration order and a test can say "fail on the third" and mean it.
WIDE = {
    "package.json": json.dumps({"dependencies": {"next": "15.0.0"}}).encode(),
    "src/api/session.ts": (
        b"// jwt token session login password cookie authorization\n"
        b"export function decode(t: string) { return jwt.decode(t) }\n"
    ),
    "src/api/pay.ts": (
        b"// stripe payout invoice refund webhook idempotency charge\n"
        b"export async function pay() { await stripe.charge() }\n"
    ),
    "src/api/exec.ts": (
        b"// eval exec cors sql injection upload redirect secret env\n"
        b"export function run(cmd: string) { return eval(cmd) }\n"
    ),
    "src/ui/form.tsx": (
        b"// useEffect useState render component form submit onClick\n"
        b"export const Form = () => null\n"
    ),
}


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


FINDING = json.dumps([{
    "file": "src/api/session.ts", "line_start": 2, "line_end": 2,
    "evidence": "jwt.decode(t)", "severity": "critical", "confidence": 0.9,
    "title": "JWT decoded without verification", "explanation": "...",
    "fix_hint": "use jwt.verify",
}])


class FailsOnCall(LLMClient):
    """Answers normally until call number `nth`, which raises LLMError."""

    def __init__(self, nth: int, message: str = "provider exploded"):
        super().__init__(providers=[Provider("anthropic", "https://x", "k",
                                             "claude-sonnet-4.6")])
        self.nth = nth
        self.message = message
        self.calls = 0

    def complete(self, system, user, max_tokens=4096):
        self.calls += 1
        if self.calls == self.nth:
            raise LLMError(self.message)
        return FINDING, LLMUsage(model="claude-sonnet-4.6",
                                 input_tokens=1000, output_tokens=200)


def scan(nth: int, message: str = "provider exploded") -> dict:
    return run_scan(make_zip(WIDE), FailsOnCall(nth, message))


# --- the scan stage itself ---------------------------------------------------

def test_a_late_failure_does_not_raise_and_does_not_lose_the_earlier_findings():
    llm = FailsOnCall(nth=len(ALL_RUBRICS))          # the last rubric

    findings, stats = run_llm_scan(io.BytesIO(make_zip(WIDE)), llm)

    assert findings, "the rubrics that answered found something; it must survive"
    assert stats.calls == len(ALL_RUBRICS) - 1
    assert stats.failed_rubric == ALL_RUBRICS[-1]
    assert "provider exploded" in (stats.failure or "")


def test_the_failed_rubric_is_not_counted_among_the_ones_that_ran():
    """The whole point of recording rubrics_ran. A rubric whose reply never
    arrived examined nothing, and a category nobody examined must not be
    scored -- an empty category reads 10.0."""
    llm = FailsOnCall(nth=1)

    _, stats = run_llm_scan(io.BytesIO(make_zip(WIDE)), llm)

    assert ALL_RUBRICS[0] not in stats.rubrics_ran


def test_a_failure_stops_the_loop_rather_than_skipping_one_rubric():
    """The client has already retried and walked the whole provider chain, so
    the next rubric is three more minutes of the same failure -- paid for if
    any of them half-succeeds."""
    llm = FailsOnCall(nth=2)

    run_llm_scan(io.BytesIO(make_zip(WIDE)), llm)

    assert llm.calls == 2


# --- what the audit then claims about itself ---------------------------------

def test_a_partial_audit_keeps_its_findings():
    result = scan(nth=len(ALL_RUBRICS))
    assert any(f.get("rule_id", "").startswith("llm-")
               for f in result["findings"])


def test_a_partial_audit_does_not_claim_the_full_basis():
    """basis is the third component of the audit cache key. A three-of-four
    audit reporting BASIS_FULL is served later to a request that asked for a
    complete one, and nothing downstream can tell."""
    assert scan(nth=len(ALL_RUBRICS))["score"]["basis"] == BASIS_PARTIAL
    # ...and an untroubled scan is unaffected.
    assert run_scan(make_zip(WIDE),
                    FailsOnCall(nth=0))["score"]["basis"] == BASIS_FULL


def test_the_failed_rubrics_category_is_unexamined_rather_than_perfect():
    """The rubric lost is the LAST one whose category has no static producer.

    It used to be simply the last rubric, which is "web" -> Frontend. That
    stopped being a lost category on 2026-09-01: app/scan/error_boundary.py
    examines Frontend at every depth, so a failed web rubric leaves Frontend
    honestly in the mean and this test's premise -- "nothing looked" -- false
    for it. The premise still holds for every category in LLM_ONLY_CATEGORIES,
    and the test now picks one of those rather than a position in the list,
    so the next producer that moves a category out does not silently turn it
    into a test of the wrong thing.
    """
    lose = max(i for i, r in enumerate(ALL_RUBRICS)
               if RUBRICS[r]["category"] in LLM_ONLY_CATEGORIES)
    result = scan(nth=lose + 1)

    lost = RUBRICS[ALL_RUBRICS[lose]]["category"]
    score = result["score"]

    assert lost in score["unexamined"]
    # And it is genuinely out of the arithmetic, not merely annotated. An
    # empty category reads 10.0, so a lost rubric left in the mean does not
    # lower the score -- it RAISES it, which is the direction that matters.
    scored = [ScoredFinding(**{k: f[k] for k in _SCORED_FIELDS if k in f})
              for f in result["findings"]]
    examined = frozenset(RUBRICS[r]["category"] for r in ALL_RUBRICS[:lose])

    honest = compute_scores(scored, llm_categories=examined)["total"]
    as_if_it_had_run = compute_scores(
        scored, llm_categories=examined | {lost})["total"]

    assert honest == score["total"]
    assert as_if_it_had_run > honest


def test_a_failure_before_any_answer_is_static_only():
    """Nothing came back, so there is no LLM depth to report. Calling that
    partial would be static-only wearing a more expensive name."""
    result = scan(nth=1)

    assert result["score"]["basis"] == BASIS_STATIC_ONLY


def test_the_money_the_failed_run_spent_is_still_recorded():
    """This half was already right and must stay right: the accumulator is
    owned by the pipeline precisely so a failure cannot erase the invoice."""
    result = scan(nth=len(ALL_RUBRICS))

    assert result["llm_usage"]["input_tokens"] > 0


# --- a rejection for SIZE is a measurement, not a verdict --------------------
#
# The 400 that started all of this was our own doing. input_char_budget turns a
# model's token window into a character ceiling using 3.0 characters per token
# -- the mean over four real prompts -- and a mean is not a bound. Denser code
# crosses the window at the same character count, the provider refuses, and
# until now that ended the rubric.
#
# The provider is the only party that knows its own ceiling for certain. So
# when it says no for size, we come back smaller, and when it says no for any
# other reason we do not: a 400 is equally what a provider returns for a model
# name it spells differently, and shrinking the prompt for that one buys three
# more rejections at the same wrong name.

ANTHROPIC_TOO_LONG = ("anthropic@https://api.anthropic.com: Client error '400 "
                      "Bad Request' for url '...': {\"error\":{\"type\":"
                      "\"invalid_request_error\",\"message\":\"prompt is too "
                      "long: 235000 tokens > 200000 maximum\"}}")
OPENAI_TOO_LONG = ("openai_compat@https://api.aitunnel.ru/v1: Client error "
                   "'400 Bad Request' for url '...': {\"error\":{\"code\":"
                   "\"context_length_exceeded\",\"message\":\"This model's "
                   "maximum context length is 200000 tokens.\"}}")
WRONG_MODEL = ("openai_compat@https://api.aitunnel.ru/v1: Client error '400 "
               "Bad Request' for url '...': {\"error\":{\"message\":\"model "
               "claude-haiku-4-5 not found\"}}")


# The same two messages as templates, so the double can state numbers that
# match the ceiling it is actually enforcing. A double whose complaint says
# "235000 > 200000" while it rejects everything over 30,000 is telling the code
# under test a lie, and the code would be right to believe it.
ANTHROPIC_TEMPLATE = ANTHROPIC_TOO_LONG.replace("235000", "<USED>") \
                                       .replace("200000", "<ALLOWED>")
OPENAI_TEMPLATE = OPENAI_TOO_LONG.replace("200000", "<ALLOWED>")


class RejectsUntilSmallerThan(LLMClient):
    """Refuses any prompt over `ceiling` characters, the way a provider does."""

    def __init__(self, ceiling: int, message: str = ANTHROPIC_TEMPLATE):
        super().__init__(providers=[Provider("anthropic", "https://x", "k",
                                             "claude-sonnet-4.6")])
        self.ceiling = ceiling
        self.message = message
        self.sizes: list[int] = []

    def complete(self, system, user, max_tokens=4096):
        self.sizes.append(len(system) + len(user))
        if self.sizes[-1] > self.ceiling:
            raise LLMError(
                self.message.replace("<USED>", str(self.sizes[-1] // 3))
                            .replace("<ALLOWED>", str(self.ceiling // 3)))
        return FINDING, LLMUsage(model="claude-sonnet-4.6",
                                 input_tokens=1000, output_tokens=200)


def _bulky() -> bytes:
    # Big enough that the first attempt is over the ceiling below.
    return make_zip({**WIDE, **{
        f"src/api/h{i}.ts": (b"// jwt token session login password cookie\n"
                             b"export function h() { return jwt.decode(t) }\n"
                             * 200)
        for i in range(20)}})


def test_a_prompt_refused_for_its_size_is_resent_smaller():
    llm = RejectsUntilSmallerThan(ceiling=30_000)

    findings, stats = run_llm_scan(io.BytesIO(_bulky()), llm)

    assert stats.oversize_retries > 0
    assert stats.failure is None
    assert findings
    assert llm.sizes[1] < llm.sizes[0]


def test_the_narrowed_ceiling_holds_for_the_rest_of_the_scan():
    """Otherwise every remaining rubric repeats the same rejection and
    relearns the same number, one round trip at a time."""
    llm = RejectsUntilSmallerThan(ceiling=30_000)

    _, stats = run_llm_scan(io.BytesIO(_bulky()), llm)

    assert stats.oversize_retries < stats.prompts - stats.calls + 1
    assert all(s <= 30_000 for s in llm.sizes[-2:])


@pytest.mark.parametrize("message", [ANTHROPIC_TEMPLATE, OPENAI_TEMPLATE])
def test_both_api_shapes_are_recognised(message):
    llm = RejectsUntilSmallerThan(ceiling=30_000, message=message)

    _, stats = run_llm_scan(io.BytesIO(_bulky()), llm)

    assert stats.oversize_retries > 0


def test_a_400_that_is_not_about_size_is_not_retried_smaller():
    """A model name the provider spells differently returns the same status
    code. Shrinking for that buys nothing and costs three round trips."""
    llm = RejectsUntilSmallerThan(ceiling=30_000, message=WRONG_MODEL)

    _, stats = run_llm_scan(io.BytesIO(_bulky()), llm)

    assert stats.oversize_retries == 0
    assert stats.failure is not None


def test_the_shrink_uses_the_numbers_the_provider_gave():
    """235000 against a 200000 maximum says the prompt was 17.5% too big.
    There is nothing left to estimate, and the blind fallback would have cut
    40% -- throwing away a fifth of the code for no reason."""
    from app.scan.llm_scan import _BLIND_SHRINK, shrunk_limit

    exact = shrunk_limit(1_000_000, ANTHROPIC_TOO_LONG)

    assert exact == int(1_000_000 * (200_000 / 235_000) * 0.95)
    assert exact > int(1_000_000 * _BLIND_SHRINK)


def test_a_rejection_without_numbers_falls_back_to_a_flat_cut():
    from app.scan.llm_scan import _BLIND_SHRINK, shrunk_limit

    assert shrunk_limit(1_000_000, OPENAI_TOO_LONG.split("maximum")[0]
                        + "maximum context length exceeded") == \
        int(1_000_000 * _BLIND_SHRINK)


def test_a_rejected_prompt_is_not_counted_as_bytes_the_provider_read():
    """input_truncated compares what we sent against what the provider says it
    received. A rejected request cost zero tokens, so counting its characters
    would accuse the provider of dropping a prompt it never took."""
    llm = RejectsUntilSmallerThan(ceiling=30_000)

    _, stats = run_llm_scan(io.BytesIO(_bulky()), llm)

    assert stats.prompt_chars == sum(s for s in llm.sizes if s <= 30_000)
    assert stats.input_truncated is False


# --- and the operator hears about it -----------------------------------------

@pytest.mark.parametrize("message,kind", [
    ("provider exploded", LLM_FAILURE_PROVIDER),
    ("Client error '402 Payment Required' for url ...", LLM_FAILURE_BILLING),
])
def test_a_partial_audit_still_alerts(message, kind):
    """Making failures survivable must not make them invisible. A partial
    audit returns findings, scores, and looks like any other audit; the only
    thing missing is the rubric nobody was told about."""
    result = scan(nth=len(ALL_RUBRICS), message=message)

    assert llm_failure_kind(result["llm"]) == kind


def test_a_clean_audit_raises_no_alert():
    assert llm_failure_kind(run_scan(make_zip(WIDE),
                                     FailsOnCall(nth=0))["llm"]) is None
