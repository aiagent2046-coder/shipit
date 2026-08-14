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
# Security; the rubrics in app/scan/llm_scan.py map to Auth, Security, Money &
# Data and Frontend. Adding a name here without adding a producer re-creates
# the same dead weight.
#
# Frontend is the sixth, added for the "web" rubric. The objection to it was
# the one issue #181 is about -- a category that is usually clean sits at 10.0
# and props up every total, which is what the fifth category cost, measured at
# +0.29 on the average. Five measured runs answer it: the rubric produced
# findings on 3 of 3 repositories in every run, including a mature monorepo,
# and the last of those runs verified 16 of 21 by hand. It is not a category
# that will sit at 10.0.
#
# What it scores is whether the app works for the person using it, which none
# of the other five asks: a render error with no boundary above the routes
# turning every future bug into a white page, a flag set before an await and
# cleared after it with no try/finally so one timeout disables the form until
# reload, a submit control the component never actually disables. Filing these
# under Deploy -- where the rubric's draft category sat while it was a
# candidate -- would have diluted what a Deploy subscore means rather than
# renormalising six honest weights.
CATEGORIES = ("Security", "Auth", "Testing", "Deploy", "Money & Data",
              "Frontend")

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
#
# Frontend sits with Testing and Deploy rather than with the safety three.
# What it finds is real and a user hits it on a normal day, but the product's
# wedge is "safe to put in production", and a blank page is not an auth hole.
# Declaring it at 0.15 leaves the relative order of the first five exactly as
# it was chosen and measured -- the normalisation divisor moves from 0.95 to
# 1.10, which scales every weight by the same factor.
_RAW_CATEGORY_WEIGHT = {
    "Security": 0.25, "Auth": 0.20, "Testing": 0.15, "Deploy": 0.15,
    "Money & Data": 0.20, "Frontend": 0.15,
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
#
# Frontend joins them: the "web" rubric is its only producer, no static check
# emits it, so on a static-only audit it would read a perfect 10.0 for the
# reason this set exists. That takes the LLM-only share of the weight from 36%
# to 45%, which is the cost of the note above being right about Auth -- a free
# tier that stayed silent on three categories is honest, one that reports 10.0
# on them is not.
LLM_ONLY_CATEGORIES = frozenset({"Auth", "Money & Data", "Frontend"})


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
    # The category this finding's PRODUCER would have assigned, recorded only
    # when the model overrode it (app/scan/llm_scan.py). Findings are filed by
    # what they are rather than by which rubric emitted them -- but a category
    # that hands all of its findings to a neighbour then holds none of its own,
    # and an empty category scores a perfect 10.0. Without this field there is
    # nothing to tell "the auth rubric looked and found nothing" apart from
    # "the auth rubric found two holes and filed them under Security", and the
    # second one must never print as a clean bar. See compute_scores.
    origin_category: str | None = None


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
#
# Frontend is deliberately NOT gated, though it can emit a critical -- a
# Subscribe button the component never disables is the browser half of a
# duplicate charge, and that is what its one CRITICAL finding across five runs
# was. Two reasons. The gate is about a headline that contradicts the finding
# under it, and "safe to put in production" is the claim these three speak to;
# a white page on a render error is a bad app, not an unsafe one. And the
# money-shaped half of what this rubric finds already reaches the reader
# through a gated category, because the server half of the same duplicate
# charge is Money & Data's remit by construction -- the rubric is told not to
# report it precisely so the two do not collide.
#
# Gating it later is a calibration change with its own evidence, not a
# follow-on to this one: it would need re-measuring against the stored audits
# the way GATE_ON_CRITICAL was, since a fourth gated category moves every
# repository that currently passes.
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


def _gate_reasons(by_cat: dict[str, float], counted: list[str],
                  findings: list[ScoredFinding]) -> list[dict]:
    """Why the gate fired, in the scorer that decided it.

    Emitted because the two gate routes no longer look the same to a reader.
    A subscore failure is self-evident on the page -- the category bar is
    visibly short. A lone critical is not: every bar can sit above 7.0 while
    the headline reads 6.3, and without a reason printed beside it the number
    contradicts the breakdown directly under it. That is the same species of
    dishonesty the gate was built to remove, one level down.

    Computed here rather than re-derived in each report surface. The web page
    and the HTML report would each need their own copy of GATE_THRESHOLD,
    GATED_CATEGORIES and the confidence floor to work it out, and three
    copies of this rule will not stay in agreement.
    """
    reasons: list[dict] = [
        {"kind": "subscore", "category": c, "value": by_cat[c]}
        for c in GATED_CATEGORIES
        if c in counted and by_cat[c] < GATE_THRESHOLD
    ]
    reasons += [
        {"kind": "critical", "category": f.category, "rule_id": f.rule_id,
         "title": f.title}
        for f in _gating_criticals(findings, counted)
    ]
    return reasons


def _apply_gate(total: float, reasons: list[dict]) -> float:
    """Compress a failing repo's mean into [0, GATED_MAX], preserving order.

    Driven off the reason list rather than re-testing the conditions, so the
    decision and its published explanation cannot disagree: if the gate
    fires, something is in `reasons` to print, and if `reasons` is empty the
    gate did not fire. There is no third state to fall out of sync.

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
    if reasons:
        return total * (GATED_MAX / 10.0)
    return total


def compute_scores(findings: list[ScoredFinding],
                   llm_ran: bool = True,
                   llm_categories: frozenset[str] | None = None) -> dict:
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

    `llm_categories` narrows that further: which LLM-only categories a producer
    actually ran for. A boolean was enough while the stage was all-or-nothing,
    and stopped being enough the moment the free tier ran ONE rubric -- with
    llm_ran=True and no further detail, Auth, Money & Data and Frontend each
    scored 10.0 and drew a full green bar off a stage that never looked at
    them. That is issue #22 again, on a preview instead of a free static scan.

    None means "all of them", which is what a paid audit does and what every
    caller written before previews existed means. An empty set is not the same
    as None and must not be conflated: it means the stage ran and covered none
    of these categories.
    """
    by_cat = {
        cat: _score([f for f in findings if f.category == cat])
        for cat in CATEGORIES
    }
    # Categories that produced findings and then handed every one of them to a
    # neighbour. Their 10.0 is dead weight in the exact sense issue #181
    # describes, arriving by a fourth route: not "no producer exists" (Config,
    # Correctness), not "no producer ran" (LLM_ONLY_CATEGORIES on a free scan),
    # not "the producer found nothing" -- but "the producer found things, and
    # they are counted next door".
    #
    # Measured on kristina_agent_center: the auth rubric reported an endpoint
    # running arbitrary shell commands with no login check, the model filed it
    # as Security because that is what it is, and Auth was left holding
    # nothing. Auth printed 10.0, was NOT in `unexamined`, and rendered as a
    # full green bar directly above an unauthenticated RCE. Counting it also
    # propped the mean up by a fifth of the weight for a reason that has
    # nothing to do with the repository.
    #
    # Only the fully-emptied case qualifies. A category that keeps one finding
    # and exports another is scoring its own remainder honestly and is left
    # alone.
    reported_elsewhere = {
        c: sorted({f.category for f in findings
                   if f.origin_category == c and f.category != c})
        for c in CATEGORIES
        if not any(f.category == c for f in findings)
        and any(f.origin_category == c for f in findings)
    }
    def _examined(cat: str) -> bool:
        if cat not in LLM_ONLY_CATEGORIES:
            return True          # a static producer always ran
        if not llm_ran:
            return False
        return llm_categories is None or cat in llm_categories

    counted = [c for c in CATEGORIES
               if _examined(c) and c not in reported_elsewhere]
    divisor = sum(_RAW_CATEGORY_WEIGHT[c] for c in counted)
    total = sum(by_cat[c] * _RAW_CATEGORY_WEIGHT[c] for c in counted) / divisor
    # The gate reads only categories that were actually examined, for the same
    # reason: an unexamined Auth sitting at 10.0 must not be able to clear a
    # gate, and an unexamined one cannot fail it either.
    reasons = _gate_reasons(by_cat, counted, findings)
    total = round(_apply_gate(total, reasons), 1)
    # ...and the same ceiling on the CATEGORY that holds the critical.
    #
    # The gate used to bound the headline alone, on the stated reasoning that
    # subscores are diagnostic and may read higher than the total. The report
    # even says so. Then a measured run said it back: kristina_agent_center
    # scored Auth 8.1 while action_service_fixed.py:128 -- an endpoint running
    # arbitrary shell commands as root with no authentication at all -- sat
    # inside that category as a CRITICAL at 0.95 confidence. A reader asking
    # "is my authentication sound?" reads the Auth bar, not the note beside
    # the headline, and 8.1 answers yes.
    #
    # Scaled, not clamped, for the reason _apply_gate gives at length: a flat
    # 6.9 would make one critical indistinguishable from six. Applied AFTER
    # the total so the same gate is never counted twice -- the total already
    # carries it.
    # Only the "critical" route, and only once per category.
    #
    # Reduced to a set of categories before scaling, because `reasons` carries
    # one entry per critical FINDING. Reading it as a loop compounded the
    # ceiling: kristina_agent_center holds three criticals in Security, and its
    # published subscore went 0.9 -> 0.6 -> 0.4 -> 0.3 across three passes while
    # the raw subscore had not moved at all. The claim this ceiling makes is
    # "the category may not present above GATED_MAX" -- a statement about the
    # category, not a penalty per finding. The per-finding penalty is the
    # weighted sum in _score, and it has already been charged.
    #
    # A "subscore" reason means the category is ALREADY below GATE_THRESHOLD
    # and is failing on its own arithmetic, so it is excluded outright rather
    # than scaled: the ceiling would be charging it a second time for the same
    # findings, dragging an honest 5.0 to 3.5. The defect being fixed is a
    # category reading HIGH while holding a confident critical, and a category
    # that already reads low is not that defect.
    already_failing = {r.get("category") for r in reasons
                       if r.get("kind") == "subscore"}
    capped = {r.get("category") for r in reasons
              if r.get("kind") == "critical" and r.get("category") in by_cat}
    for cat in capped - already_failing:
        by_cat[cat] = round(by_cat[cat] * (GATED_MAX / 10.0), 1)
    if findings and total == 10.0:
        total = 9.9  # a perfect 10 with a non-empty findings list is a lie
    # Empty list, not omitted, when the gate did not fire: a consumer can
    # then tell "not gated" from "produced before this key existed", which a
    # missing key conflates. Stored rows predating it have no `gated_by` at
    # all, and every surface that renders it must keep treating that as
    # unknown rather than as a clean bill.
    # Which categories nothing looked at. `categories` reports all of them
    # because hiding a row would make the audit look narrower than it is --
    # but an unexamined category sits at 10.0 for want of a producer, and a
    # 10.0 rendered as a full green bar is the single most misleading thing
    # this module can emit. It already does not vote on the total; this key
    # is what lets a report say "not checked" instead of drawing that bar.
    #
    # Derived here rather than in each surface: working it out downstream
    # needs LLM_ONLY_CATEGORIES and the basis, and a second copy of that
    # rule is how the report starts disagreeing with the score.
    #
    # `reported_elsewhere` is excluded here on purpose. Both keys name a
    # category whose number must not be drawn, but for opposite reasons, and a
    # report that conflates them tells the reader the wrong thing: "not
    # checked" about a category that WAS checked is its own falsehood, and it
    # sends someone hunting for an audit that already happened.
    unexamined = [c for c in CATEGORIES
                  if c not in counted and c not in reported_elsewhere]
    return {"total": total, "categories": by_cat, "gated_by": reasons,
            "unexamined": unexamined, "reported_elsewhere": reported_elsewhere}
