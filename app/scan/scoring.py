"""Production Readiness Score, v2.

Per-category subscore = 10 − Σ(severity_weight × confidence) over that
category's findings, clamped to [0..10]. Total = weighted mean of the
category subscores.

v1 computed total as one global 10 − Σ(...), which saturated at 0.0
for typical vibe-coded repos (6 of 10 real repos in the first batch
run scored exactly 0.0): one noisy category, or one anti-pattern
repeated across many files, zeroed the whole scale, destroying both
differentiation and reproducibility measurement (clamping hides
variance). With per-category floors, a repo drowning in one category
still gets credit for the others. See shipit-architecture.md 2.2 C.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_WEIGHT = {"critical": 2.0, "high": 1.0, "medium": 0.4, "low": 0.1}

# Only categories a producer can actually assign. "Correctness" and "Config"
# used to be here and were removed: nothing ever emitted a finding in either,
# so both scored a constant 10.0 and together carried 25% of the weight. The
# effect was a scale whose bottom half was unreachable -- a repository with a
# totally failed Security category still totalled 7.5, and audit 0a043539
# (vercel/nextjs-subscription-payments) scored 8.1 while holding a committed
# .env, a subscriptions table with no write RLS policies and two open
# redirects. See issue #181.
#
# Producers, for whoever adds the next category: app/scan/checks.py emits
# Security, Testing and Deploy; the secret rules in app/scan/secrets.py emit
# Security; the rubrics in app/scan/llm_scan.py map to Auth, Security and
# Money & Data. Adding a name here without adding a producer re-creates the
# same dead weight.
CATEGORIES = ("Security", "Auth", "Testing", "Deploy", "Money & Data")

# Weighted mean for the total. Security and Auth dominate because the product's
# wedge is "safe to put in production".
#
# Declared as the original raw weights and normalised, rather than as
# pre-divided decimals: it keeps the relative importance of the survivors
# exactly as it was chosen, makes "sums to 1" true by construction instead of
# by assertion, and means dropping or adding a category is a one-line edit
# that cannot silently stop summing to 1.
#
# "Money & Data" sits level with Auth because what it finds costs the owner
# directly and needs no attacker: a battle-pass purchase that never deducts
# the currency (blitz-blueprint, every player premium for free), a cron firing
# paid LLM calls every five minutes (next-ai-news, ~1,700 calls/day), a
# webhook with no idempotency guard against the provider's own retries
# (nextjs-subscription-payments). Measured on ten real repositories before
# being given this weight.
_RAW_CATEGORY_WEIGHT = {
    "Security": 0.25, "Auth": 0.20, "Testing": 0.15, "Deploy": 0.15,
    "Money & Data": 0.20,
}
_RAW_TOTAL = sum(_RAW_CATEGORY_WEIGHT.values())
CATEGORY_WEIGHT = {k: v / _RAW_TOTAL for k, v in _RAW_CATEGORY_WEIGHT.items()}
assert set(CATEGORY_WEIGHT) == set(CATEGORIES)
assert abs(sum(CATEGORY_WEIGHT.values()) - 1.0) < 1e-9

# Categories only the LLM stage can fill. A static-only audit never runs it,
# so these sit at a perfect 10.0 for reasons that have nothing to do with the
# repository -- dead weight in the precise sense of issue #181, just arriving
# by a different route: not "no producer exists" but "no producer ran".
#
# It was already happening and already visible: across the audits holding
# category data, static-only ones average 8.99 against 7.79 for full ones,
# and Auth reads exactly 10.0 in 25 of 25 of them. The free tier was telling
# people their auth was perfect when nothing had looked at it. Adding a second
# LLM-only category would have taken 42% of the weight to a constant 10.0.
LLM_ONLY_CATEGORIES = frozenset({"Auth", "Money & Data"})


@dataclass(frozen=True)
class ScoredFinding:
    """Normalized finding shape shared by all scanners."""
    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    file: str = ""
    line: int = 0
    masked: str = ""
    # Plain-language layer: what this means for a non-technical owner
    # and what to do about it. Filled from the rule dictionary for
    # static findings and from the model's own explanation/fix_hint for
    # LLM findings (previously dropped on the floor).
    explanation: str = ""
    fix_hint: str = ""
    # Machine-readable damping/eligibility context, propagated from the
    # scanner (see SecretFinding.context). "test_fixture" when a finding
    # was damped as a test-fixture placeholder, None otherwise. Lets
    # downstream consumers (the future Fix Pack filter) branch reliably
    # instead of string-matching the title suffix.
    context: str | None = None


def _score(findings: list[ScoredFinding]) -> float:
    penalty = sum(
        SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings
    )
    return round(max(0.0, min(10.0, 10.0 - penalty)), 1)


# A weighted mean lets a strong category pay for a failing one. That is the
# right shape for "how finished is this repo", and the wrong shape for the
# question the product actually answers, which is "is this safe to put in
# front of users". Testing and Deploy are real work, but no amount of them
# makes a repo with an auth hole safe to ship, and averaging says otherwise:
# audit 0a043539 (vercel/nextjs-subscription-payments) held Security 5.9 and
# Auth 6.2 -- an open redirect, a service-role client that silently no-ops
# when misconfigured, a subscriptions table with no write RLS policies -- and
# still totalled 8.1, because Testing 9.7 and Deploy 9.8 carried it. The
# reader sees the headline number and stops.
#
# So failing either safety category imposes a CEILING on the total. It does
# not replace the total with the failing subscore: that was tried, and on the
# 72 real audits carrying category data it collapsed 10 of them (every repo
# whose Security penalty saturated the subscore to 0.0) to exactly 0.0 --
# re-creating for these two categories precisely the v1 flattening this
# module's docstring exists to describe, where a repo at Security 0.0 / Auth
# 10.0 became indistinguishable from Security 0.0 / Auth 6.3.
#
# A ceiling gets the product outcome without that cost. Below it the weighted
# mean is untouched, so every gated repo keeps its full ordering; above it the
# score is pulled down to the ceiling and no further. Of those same 72 audits
# 40 fail the gate -- a majority, which is the expected shape for a product
# that audits vibe-coded repos, not evidence the threshold is wrong.
#
# Money & Data gates for the same reason the other two do, not a softer one.
# blitz-blueprint scores 2.9 there -- purchasePremiumPass marks the pass
# premium without ever deducting the 1000 currency, and the store grants the
# item before checking the balance -- while Security 9.2, Testing 10.0 and
# Deploy 10.0 carried its mean to 8.3. "Every player gets premium free" is not
# a repository that should present an 8.3, and no amount of clean Testing
# makes it one. The gate is about the headline never contradicting the
# finding underneath it, which is as true of revenue as of an auth hole.
GATED_CATEGORIES = ("Security", "Auth", "Money & Data")

# Set at 7.0 because that is where these subscores stop meaning "some issues"
# and start meaning "something is actually going wrong here": the audits that
# motivated this sat just under it (Security 5.9 / Auth 6.2, and 6.5). A repo
# at 7.0+ in all of them still gets its averaged score.
GATE_THRESHOLD = 7.0

# The top of the band a gated repo is compressed into: just under
# GATE_THRESHOLD, so a failing repo can never present a passing headline.
GATED_MAX = 6.9

# A single critical finding in a gated category fails the gate on its own,
# whatever the subscore arithmetic says.
#
# The subscore route could not do this. One critical costs 2.0 x confidence,
# so a lone critical at 0.9 leaves Security at 8.2 -- comfortably clear of
# GATE_THRESHOLD -- and the gate needed a second one before it fired.
#
# Measured on the 67 stored audits carrying a basis and both gated
# subscores, that took the gate from 40 repositories to 47. All seven it
# adds were presenting 9.0 to 9.5 while holding a critical: five a committed
# .env (link9jatree, metalcraft-forge-hub, blitz-blueprint,
# nextjs-subscription-payments, drydock-vite-react-fixture), one a private
# key block, one a critical from the security rubric. A committed .env is
# the product's flagship finding; printing 9.1 above it is the headline
# contradicting the finding underneath, which is the one thing this gate
# exists to stop. They land at 6.2-6.6 -- inside the gated band, still
# ordered among themselves.
#
# Lowering GATE_THRESHOLD to reach those repos was the alternative and is
# worse: it would have to land near 8.3, which also gates every repo holding
# three merely-high findings, a much larger and less defensible sweep. The
# rule belongs on severity because that is what the claim is about -- "one
# critical is enough" is a statement about criticals, not about a threshold.
#
# Applied to all of GATED_CATEGORIES, not Security alone. The reasoning that
# makes one critical secret disqualifying is the same reasoning the Money &
# Data note above makes for revenue, and a rule that gated a leaked key but
# not a critical auth bypass would be indefensible on its own terms.
GATE_ON_CRITICAL = True

# ...but only a critical its producer is actually sure of. Severity is a
# claim about impact, confidence a claim about certainty, and the weighted
# sum multiplies them precisely so an uncertain finding costs less. The gate
# is categorical instead -- it either disqualifies the headline or does not
# -- so it needs its own floor rather than inheriting that arithmetic.
#
# Set at 0.7, which changes nothing measurable today: across every stored
# audit the lowest-confidence critical is 0.85 and 99% sit at 0.9 or above,
# and the static rules cannot emit one lower, because a credential on a test,
# example or doc path is capped at medium before it ever gets here
# (damp_for_non_production_path in app/scan/secrets.py, applied to the LLM
# pass too). The floor is for the producer not yet written: a rubric that
# reports "critical if real, but I am guessing" must not be able to fail a
# repository by itself.
CRITICAL_GATE_MIN_CONFIDENCE = 0.7


def _gating_criticals(findings: list[ScoredFinding],
                      counted: list[str]) -> list[ScoredFinding]:
    """Criticals confident enough, and in a category examined enough, to gate.

    Restricted to `counted` for the same reason the subscore test is: on a
    static-only audit nothing ran that could have produced an Auth or
    Money & Data finding, so their absence is not evidence of anything.
    """
    return [f for f in findings
            if f.severity == "critical"
            and f.confidence >= CRITICAL_GATE_MIN_CONFIDENCE
            and f.category in GATED_CATEGORIES
            and f.category in counted]


def _apply_gate(total: float, by_cat: dict[str, float],
                counted: list[str],
                findings: list[ScoredFinding]) -> float:
    """Compress a failing repo's mean into [0, GATED_MAX], preserving order.

    A flat ceiling was tried first: total = min(mean, GATED_MAX). It stopped
    the flattering headline but flattened the top of the failing range,
    because a repo's mean is usually well above 6.9 even when one category
    fails. Measured on the 42 full audits, 17 of them -- 40% -- would have
    printed exactly 6.9, making a repo failing one category indistinguishable
    from one failing three. That is the same loss of resolution this module's
    docstring describes at the bottom of the v1 scale, relocated to the middle.

    Scaling instead of clamping keeps the ordering intact everywhere: the mean
    is still the measure, 6.9 is merely the top of the range it is expressed
    in. Monotonic by construction, so a worse repo always scores lower, and
    nothing collapses to a constant.
    """
    gated = [c for c in GATED_CATEGORIES if c in counted]
    fails_subscore = any(by_cat[c] < GATE_THRESHOLD for c in gated)
    if fails_subscore or _gating_criticals(findings, counted):
        return total * (GATED_MAX / 10.0)
    return total


def compute_scores(findings: list[ScoredFinding],
                   llm_ran: bool = True) -> dict:
    """Per-category subscores and their weighted mean.

    `llm_ran=False` marks a static-only audit, where LLM_ONLY_CATEGORIES had
    no producer and their 10.0 means "not examined", not "clean". Those
    categories are still reported -- hiding them would make the report look
    like the audit covered less than it did -- but they are excluded from the
    mean, and the remaining weights renormalise over themselves. A number
    nothing measured must not vote on the total.

    The default is True so every existing caller keeps the full-audit
    behaviour; only the pipeline, which knows whether the stage ran, passes
    False.
    """
    by_cat = {
        cat: _score([f for f in findings if f.category == cat])
        for cat in CATEGORIES
    }
    counted = [c for c in CATEGORIES
               if llm_ran or c not in LLM_ONLY_CATEGORIES]
    divisor = sum(_RAW_CATEGORY_WEIGHT[c] for c in counted)
    total = sum(by_cat[c] * _RAW_CATEGORY_WEIGHT[c] for c in counted) / divisor
    # The gate reads only categories that were actually examined, for the same
    # reason: an unexamined Auth sitting at 10.0 must not be able to clear a
    # gate, and an unexamined one cannot fail it either.
    total = round(_apply_gate(total, by_cat, counted, findings), 1)
    if findings and total == 10.0:
        total = 9.9  # a perfect 10 with a non-empty findings list is a lie
    return {"total": total, "categories": by_cat}
