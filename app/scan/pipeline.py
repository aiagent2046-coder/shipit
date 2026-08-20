"""Combined static + LLM scan pipeline, shared by the API and the CLI.

Static scan always runs. The LLM auth/security stage runs only when the
client has configured providers, and degrades to static-only findings
instead of raising if the provider chain fails at request time — the
caller can still see what happened via the `llm` field ("failed: ...").
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import zipfile

from app.llm.client import LLMClient, LLMError
from app.fixpack.generate import mark_unfixable_findings
from app.scan.collapse import collapse_repeats
from app.scan.llm_scan import RUBRICS, LLMScanStats, run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.static import run_static_scan

logger = logging.getLogger(__name__)

# Every field that must survive the round trip out of the scanners, through
# the findings dicts (which persist to findings_json) and back into a
# ScoredFinding for the scorer. A field missing here is dropped silently: the
# producer sets it, the report can still read it off the dict, and only the
# SCORE quietly computes as though it were never set. "origin_category" is the
# one that makes an emptied-by-recategorisation category visible, so leaving
# it out restores exactly the defect it was added to fix, with every test
# against compute_scores still passing.
_SCORED_FIELDS = ("rule_id", "title", "severity", "confidence",
                  "category", "file", "line", "masked", "explanation",
                  "fix_hint", "context", "origin_category")


# Bump when any part of the audit engine changes in a way that should
# invalidate cached results: the LLM prompt (app/scan/llm_scan.py), the
# scoring formula (app/scan/scoring.py), the static rules
# (app/scan/secrets.py, app/scan/checks.py), or the LLM model. The model is
# a RUNTIME value (DEFAULT_MODEL / the LLM_MODEL env override in
# app/llm/client.py), NOT a code constant, so changing LLM_MODEL alone will
# not change this string -- an operator who switches models must bump this
# by hand, or the cache will keep serving pre-switch results.
#
# Folded into the audit cache key alongside content_digest (see
# AuditRepository.get_by_content_hash): a bump makes the next audit of
# byte-identical content recompute instead of reusing a now-stale row,
# which is what stops an engine improvement (or bug fix) from being frozen
# out by a result produced under the old engine.
AUDIT_ENGINE_VERSION = "2026-08-18-1"

# How many LLM passes a PAID audit runs (union-of-N; see run_llm_scan). 2, and
# not because two is round: measured on four same-engine runs of a real repo
# (ai-co-founder-matching @ c15be34, 2026-08-18), one pass surfaces 23-27 of
# the 34 finding keys the four-run union holds (~53-79%, high-severity keys
# reproducing at 84%, mediums 77%), so a single pass is a sample and was being
# sold as a census. Two passes lift coverage to roughly 75-80% of the union
# and make criticals effectively certain, at about twice the provider cost --
# which is why JOB_COST_CAP_USD moved when this landed (app/scan/llm_scan.py)
# and why this constant's change bumped AUDIT_ENGINE_VERSION above: a 2-pass
# result is a different distribution, and a cached 1-pass row must not be
# served as one.
#
# The free preview stays at one pass: it is static+one-rubric by policy and
# its own text says it is a preview. Monitoring re-audits also stay at one
# pass (cost is per push, and the union baseline in app/monitor/diff.py is
# what absorbs single-pass flicker there) -- which means a monitoring row can
# be reused by a paid job's content-hash lookup and hand a paying customer a
# 1-pass result. Known, accepted for now: it needs the same content hash on
# the same engine version, and the fix (recording passes on the row) is not
# worth the column until it is seen happening.
PAID_AUDIT_PASSES = int(os.environ.get("PAID_AUDIT_PASSES", "2"))


# The three values `score["basis"]` can take, named because they are a pricing
# boundary and not only a diagnostic. BASIS_STATIC_ONLY used to mean "something
# went wrong or the budget ran out", and still does -- it is what a preview
# degrades to when the spend cap is reached or the provider fails.
BASIS_FULL = "static+llm"

# The free tier's depth, and why it cannot borrow either of the other two
# names.
#
# `basis` is not only a label: it is the third component of the audit cache
# key (AuditRepository.get_by_content_hash), and that key is a pricing
# boundary. A preview scan reporting BASIS_FULL would let an anonymous
# visitor's cheap result be served to a paying account that audits the same
# content -- the exact cross-boundary reuse the cache's docstring records as
# already fixed, re-opened from the other side. Reporting BASIS_STATIC_ONLY
# would be a plain falsehood: an LLM ran, and its findings are in the result.
#
# So a third value, and every consumer that branches on depth must handle it.
# A preview is a narrower scan by a weaker reader -- one rubric on
# FREE_TIER_MODEL -- which is why what it publishes is findings rather than
# scores: naming what was found is a claim the model can support, and a
# number out of ten is not.
BASIS_PREVIEW = "static+preview"

# ...and a fourth, for the audit that started at full depth and did not get
# there: some rubrics answered, one failed, and the findings of the ones that
# answered are real and in the result.
#
# Measured on Avisafety-1/blank-slate. One rubric took a 400, run_llm_scan
# raised, and the whole stage was written off: the tokens the earlier rubrics
# had already spent were recorded (the accumulator is owned by this module and
# survives) while their findings died with the frame. The audit degraded to
# static-only and scored 6.0 where the same repository with the LLM stage
# scored 3.9 -- the report reassuring exactly where it broke.
#
# It needs its own name for the same reason BASIS_PREVIEW does. `basis` is the
# third component of the audit cache key, so a three-of-four audit reporting
# BASIS_FULL would be served later to a request that asked for a full one, and
# nothing downstream could tell. Under its own name the lookup simply misses
# and the next request pays for a complete scan.
#
# Distinct from BASIS_PREVIEW, which is also partial: that one is partial ON
# PURPOSE and to a known extent. This one is partial by accident and to an
# extent only the run itself knows, which is why rubrics_ran travels with it.
BASIS_PARTIAL = "static+partial"

# What the free tier spends. One rubric, because the security surface is the
# product's wedge and the one a visitor most needs to see; the cheapest model,
# because this is given away to unauthenticated traffic.
#
# Both are env-overridable so an operator can widen or narrow the giveaway
# without a deploy -- but note that widening it costs money per anonymous
# request, and the daily spend cap is what bounds that, not this.
FREE_TIER_MODEL = os.environ.get("FREE_TIER_LLM_MODEL", "claude-haiku-4-5")

# A function, not an inline comprehension, so the reading can be tested
# without reloading this module -- and a module-level constant built from the
# environment is otherwise only testable by reloading, which leaves every
# other importer holding the old value.
_FREE_TIER_MODEL_ENV_BY_KIND = (
    ("openai_compat", "FREE_TIER_LLM_MODEL_AITUNNEL"),
    ("anthropic", "FREE_TIER_LLM_MODEL_ANTHROPIC"),
)


def free_tier_models_by_kind() -> dict[str, str]:
    """The preview's model name per provider kind, for the kinds that set one.

    Absent means "use FREE_TIER_MODEL", which is what a one-provider chain
    wants and what with_model does with an unmapped kind. An empty value is
    absent too: an operator commenting a line out leaves `VAR=` behind, and
    that must not configure a model named "".
    """
    return {kind: value
            for kind, var in _FREE_TIER_MODEL_ENV_BY_KIND
            if (value := os.environ.get(var, "").strip())}


# The per-provider spellings of the preview's model, for a chain with more
# than one provider. Same trap as LLM_MODEL one tier down, and worse here: the
# preview is what unauthenticated visitors get, so a fallback that 400s turns
# every free scan into a static-only report on the day the primary is down --
# the thinner report the visitor cannot tell apart from a real one.
#
# Empty on every deployment today, because every deployment runs one provider.
# It exists so that adding a second one is a configuration change rather than
# a silent downgrade.
FREE_TIER_MODEL_BY_KIND: dict[str, str] = free_tier_models_by_kind()
FREE_TIER_RUBRICS: tuple[str, ...] = tuple(
    r for r in os.environ.get("FREE_TIER_LLM_RUBRICS", "security").split(",")
    if r.strip()
)

# Why a provider failure needs a name, and two of them.
#
# The `llm` field has carried "failed: ..." since a 402 mid-run turned a 0.0
# into a 9.2. That fixed the diagnosis and not the discovery: the job still
# finalises as succeeded, the audit still persists, and the only trace is a
# WARNING nobody reads until they go looking. On 2026-08-12 it happened twice
# inside three minutes -- two paid audits delivered at 9.7 with three of six
# categories quietly unexamined -- and was found only because someone was
# running dubinc/dub by hand for an unrelated reason.
#
# Split in two because the operator does two different things. BILLING is
# "top up the provider account", actionable in a minute, and until it is done
# EVERY audit degrades. PROVIDER is an outage or a bad response, usually
# transient, usually nothing to do but wait. One alert for both would train
# the reader to ignore the one that matters.
LLM_FAILURE_BILLING = "billing"
LLM_FAILURE_PROVIDER = "provider"

# Deliberately narrow. 429 is rate limiting and 403 is authorisation, and
# calling either of them "top up the account" sends the operator to the wrong
# page; both are PROVIDER. This matches what the provider actually said today:
# "Client error '402 Payment Required' for url ...".
_BILLING_SIGNATURE = re.compile(
    r"\b402\b|payment\s+required|insufficient\s+(funds|balance|credit)"
    r"|out\s+of\s+credit|quota\s+exceeded",
    re.I,
)
BASIS_STATIC_ONLY = "static_only"

# Passed as llm_skip_reason when the caller is not a paying account. Distinct
# from "daily_spend_cap" on purpose: that reason means we ran out of money, this
# one means we never intended to spend any.
FREE_TIER_LLM_SKIP_REASON = "free_tier"


def llm_failure_kind(llm_summary: object) -> str | None:
    """Which kind of provider failure this scan hit, or None if it did not.

    Reads the same `llm` value the caller already has rather than taking the
    exception, because run_scan is synchronous and every alerting caller is
    async -- classifying here keeps the decision in one place and lets the
    two async call sites (the worker, and run_repo_audit for the Fix Pack's
    deep review) share it instead of each parsing a string.

    Two shapes carry a failure. A stage that never produced anything writes
    the string "failed: ..."; a stage that lost ONE RUBRIC part-way through
    now returns its stats dict with `failure` set, because its findings are
    real and are in the result.

    The second shape has to alert too, and that is the whole reason this
    function was touched. A partial audit is the quiet kind of broken: it
    returns findings, it scores, it looks like every other audit, and the
    only thing missing is the rubric nobody was told about. If only the
    all-or-nothing shape raised an alert, making failures survivable would
    have made them invisible -- trading a loud outage for a silent one.
    """
    if isinstance(llm_summary, dict):
        detail = llm_summary.get("failure")
        return _classify_failure(detail) if isinstance(detail, str) and detail \
            else None
    if not isinstance(llm_summary, str) or not llm_summary.startswith("failed:"):
        return None
    return _classify_failure(llm_summary)


def _classify_failure(detail: str) -> str:
    if _BILLING_SIGNATURE.search(detail):
        return LLM_FAILURE_BILLING
    return LLM_FAILURE_PROVIDER


def basis_for_account(account_id: object | None) -> str:
    """Which scan depth this caller is entitled to.

    One definition, because three places need to agree: the worker deciding
    whether to call the LLM, and the two cache lookups deciding which stored
    result may be reused. When they disagreed, an anonymous visitor could be
    served a paid full audit out of the cache and a paying account could be
    served a free static one.

    Anonymous gets a preview, not a degraded paid audit. The static rules and
    secret scanning cost nothing to run and are what found the committed .env
    in audit ed402e63; the preview adds one rubric on the cheapest model, so a
    visitor can SEE the problems that the paid depth then examines properly.
    That is deliberate: a free scan whose reader learns nothing never becomes
    a paying one.

    It returns the ENTITLEMENT, not the outcome. A preview whose LLM stage is
    skipped (spend cap) or fails still reports BASIS_STATIC_ONLY in its score,
    so this value must never be read as a claim about what actually ran -- only
    as what this caller may be served from the cache.
    """
    return BASIS_FULL if account_id else BASIS_PREVIEW


def content_digest(data: bytes) -> str:
    """Canonical SHA-256 identity of an uploaded archive's *contents*.

    Hashes the sorted (path, per-file SHA-256) of every non-directory
    entry, so it is independent of zip packaging (member order,
    timestamps, compression level): the same repository content always
    yields the same digest. This is the reproducibility key -- an
    identical re-audit reuses the prior stored result instead of
    re-running the LLM scan, which returns a different findings set (and
    thus a different score) run to run even at temperature=0. If the zip
    can't be opened, fall back to hashing the raw bytes so the caller
    still gets a stable, total function.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            entries = [
                (info.filename, hashlib.sha256(zf.read(info)).hexdigest())
                for info in zf.infolist()
                if not info.is_dir()
            ]
    except zipfile.BadZipFile:
        return "raw:" + hashlib.sha256(data).hexdigest()
    entries.sort()
    h = hashlib.sha256()
    for name, digest in entries:
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(digest.encode("ascii"))
        h.update(b"\0")
    return h.hexdigest()


def run_scan(data: bytes, llm_client: LLMClient, llm_passes: int = 1,
             llm_skip_reason: str | None = None,
             llm_rubrics: tuple[str, ...] | None = None,
             depth: str = BASIS_FULL) -> dict:
    """Returns {"score", "findings", "llm": <stats | status>, "llm_usage"}.

    `llm` is a stats dict when the stage ran, and also a stats-shaped dict
    (all-zero, with `skipped_reason` set) when it never ran because no
    providers are configured -- so `skipped_reason` distinguishes that from
    a real run that matched no rubric-relevant files (prompts=0,
    skipped_reason=None). A hard provider failure stays the honest string
    "failed: <reason>".

    `llm_skip_reason`, when set by the caller (e.g. "daily_spend_cap"), forces
    the LLM stage off exactly as if no providers were configured: the scan
    degrades to static-only with that reason recorded, and calls=0 means no
    llm_usage row is written. This is the soft-degrade path an anon daily
    spend cap uses -- a backstop that stops spending, not an error to the user.

    `llm` and `llm_usage` are deliberately two different things. `llm` is the
    diagnostic the user and the report see, and on a provider failure it is the
    honest string "failed: ...". `llm_usage` is the accounting fact: the tokens
    that were actually bought, which on that same failure are whatever the calls
    made BEFORE it cost -- money the provider will bill regardless of the scan
    being useless. Reading spend off `llm` is what let a partial scan's cost
    disappear; the accounting path reads this key instead.

    `llm_rubrics` narrows the stage to a subset (the free tier runs one);
    None means every rubric.

    `depth` is the basis to REPORT IF the stage actually runs -- BASIS_FULL for
    a paid audit, BASIS_PREVIEW for the free tier. It is what the caller
    intended, never a claim about what happened: if the stage is skipped or
    fails, the result says BASIS_STATIC_ONLY regardless, because that is what
    it then is. Keeping the two apart is what stops a preview that never
    reached the provider from being cached and served as one.
    """
    static = run_static_scan(io.BytesIO(data))
    findings = static["findings"]
    llm_summary: object = vars(LLMScanStats(
        skipped_reason=llm_skip_reason or "no_providers_configured"))
    # Owned here, not by run_llm_scan, so its contents survive an LLMError.
    spend = LLMScanStats()

    if llm_client.providers and llm_skip_reason is None:
        try:
            llm_findings, stats = run_llm_scan(
                io.BytesIO(data), llm_client, passes=llm_passes, stats=spend,
                **({} if llm_rubrics is None else {"rubrics": llm_rubrics}))
        except LLMError as exc:
            # A provider failure mid-audit silently degrades the score to
            # static-only (a real 402-mid-run once turned a 0.0 into a 9.2).
            # Record it in the log so the next occurrence is visible without
            # diffing scores — the caller still sees it in the `llm` field.
            logger.warning("LLM scan stage failed, degrading to static-only: %s", exc)
            llm_summary = f"failed: {exc}"
        else:
            findings = findings + [vars(f) for f in llm_findings]
            llm_summary = vars(stats)

    findings = collapse_repeats(findings)

    # Here and nowhere else, because here is the last place the repository is
    # in memory. Whether the Fix Pack's RLS generator can actually write a
    # policy depends on the customer's schema, and every consumer of that
    # answer -- the report, the purchase gate -- runs in a request handler
    # with no bytes to read. A repo whose only eligible finding is one the
    # generator will refuse was sold a Fix Pack twice before this call
    # existed; see mark_unfixable_findings.
    findings = mark_unfixable_findings(data, findings)

    # One expression, read twice: it decides the reported basis AND which
    # categories are allowed to vote on the total. Computing it once is what
    # stops the two from drifting apart -- a score whose basis says
    # static-only while Auth still carries weight is the exact lie this
    # replaced.
    llm_ran = (isinstance(llm_summary, dict)
               and llm_summary.get("skipped_reason") is None)

    # Which rubrics actually answered. run_llm_scan no longer raises when a
    # provider fails mid-scan -- it stops and reports how far it got -- so the
    # rubrics REQUESTED and the rubrics that ran are two different lists, and
    # only one of them may decide which categories were examined.
    #
    # Missing key means a stats dict from before this existed; falling back to
    # the requested list reproduces exactly what such a scan meant.
    ran = (llm_summary.get("rubrics_ran") if llm_ran else None)
    if ran is None:
        ran = llm_rubrics if llm_rubrics is not None else tuple(RUBRICS)
    # A stage that answered nothing is not a stage that ran, whatever it says
    # about itself. Without this, a failure on the first prompt would report a
    # partial basis, which is static-only wearing a more expensive name.
    #
    # Keyed on `calls` -- answers received -- and not on `ran`, which also
    # counts rubrics that matched no files and so sent nothing. A scan where
    # the only rubric with matching code failed made zero LLM calls, whatever
    # the others did or did not look at.
    if llm_ran and llm_summary.get("failure") and not llm_summary.get("calls"):
        llm_ran = False

    return {
        "score": {
            **compute_scores(
                [ScoredFinding(**{k: f[k] for k in _SCORED_FIELDS if k in f})
                 for f in findings],
                llm_ran=llm_ran,
                # Derived from the rubrics that ran, never written out: a
                # preview covers one of them, and a category no rubric looked
                # at must not score 10.0 off the back of the ones that did.
                # Reading RUBRICS is what keeps this correct when the free
                # tier's rubric list is changed by an env var.
                llm_categories=frozenset(
                    RUBRICS[r]["category"] for r in ran if r in RUBRICS),
            ),
            # An audit whose LLM stage was skipped or failed must not
            # look like a clean bill of health: a repo that scored 0.0
            # with the LLM stage present scored 9.2 without it (seen in
            # a real batch run when the provider returned 402 mid-run).
            # The basis travels inside score_json so it persists to the
            # DB and reaches every consumer of the score, not just ones
            # that also read `llm`.
            #
            # The same flag now also keeps Auth and Money & Data out of the
            # mean on a static-only audit: nothing ran that could have filled
            # them, and their 10.0 means "not examined", not "clean".
            #
            # A run that lost a rubric to a provider failure reports
            # BASIS_PARTIAL instead of `depth`, which keeps it out of the
            # cache slot a full audit reads from -- see BASIS_PARTIAL.
            "basis": ((BASIS_PARTIAL if llm_summary.get("failure") else depth)
                      if llm_ran else BASIS_STATIC_ONLY),
        },
        "findings": findings,
        "llm": llm_summary,
        "llm_usage": vars(spend),
    }
