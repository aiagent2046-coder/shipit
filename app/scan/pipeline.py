"""Combined static + LLM scan pipeline, shared by the API and the CLI.

Static scan always runs. The LLM auth/security stage runs only when the
client has configured providers, and degrades to static-only findings
instead of raising if the provider chain fails at request time — the
caller can still see what happened via the `llm` field ("failed: ...").
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import io
import logging
import os
import re
import zipfile

from app.llm.client import LLMClient, LLMError
from app.fixpack.generate import mark_unfixable_findings
from app.scan.collapse import collapse_repeats
from app.scan.manifest import scan_manifest
from app.scan.llm_scan import RUBRICS, LLMScanStats, run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.static import run_static_scan
from app.sca.osv import OsvClient
from app.sca.stage import run_sca_stage

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
                  "fix_hint", "context", "origin_category", "source",
                  "verification_status", "verification_method", "claim_evidence")


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
# FOUR ENGINE CHANGES SHIPPED BEHIND A STALE STRING. Between 2026-08-18 and
# 2026-08-20 the static stage gained schema_drift (#298), service_role (#299),
# the sellability stamp (#305) and ci_deploy_source (#306). None of them
# touched this constant, so every repository already in the cache kept being
# served its pre-change result: a customer re-ran an audit after the deploy,
# got a byte-identical report, and concluded the new rule did not work. It ran
# nowhere, because the audit never ran at all.
#
# The comment above already said to bump it. Saying so is evidently not
# enough — see tests/test_engine_version_pins_the_scanners.py, which fails
# when the set of wired scanners changes and this string does not.
#
# AND IT HAPPENED AGAIN, one gap to the left. #358 changed no scanner's
# presence, so that test stayed green, but it changed what an existing scanner
# EMITS: a new rule_id (connection-string-local-host) and a new damping context
# (ci_service). A cached row therefore disagreed with the running engine about
# the same bytes -- carrying the very advice the release was shipped to stop
# printing -- and the first re-audit after the deploy would have returned it,
# byte for byte, looking exactly like a fix that did not work.
#
# So the pin now covers the emitted vocabulary too, not just the scanner set.
#
# 2026-08-28-1 is a THIRD kind of change again: no scanner, no rule id, no
# context -- a different LLM behind the free preview (FREE_TIER_LLM_MODEL,
# below). No test can catch that one, because the model is not in the code:
# it is an environment variable read at process start, which is exactly what
# this constant's opening comment warns about. It is bumped here by hand, in
# the same change that prices the model, so the two travel together.
# 2026-09-01-1: a new static scanner (error_boundary), a new rule id
# (missing-error-boundary), and Frontend leaving LLM_ONLY_CATEGORIES -- so a
# static-only audit now scores a category it used to leave out. All three are
# exactly the kind of change the pin test above was written for.
# 2026-09-04-1: the error_boundary rule tightened -- only a ROOT-level
# error.tsx/global-error.tsx silences it now, not one buried in a route
# segment. Same scanner, same rule id, but the same repository can now score
# differently (a nested-only boundary that read as covered now fires), so
# cached audits must not serve the pre-change verdict. Measured floors that
# motivated it: DRYDOCK_LENS_PLAN.md, 2026-09-03/04.
# 2026-09-04-2: Expo Router joins _FRAMEWORK_MOUNTS. An `app/_layout.tsx` app
# with the `expo-router` dependency was `undetermined` -- no createRoot, because
# the framework writes the mount -- so it produced no finding and left the
# incidence denominator. It can now both mount and fire, which is a different
# verdict for the same repository.
# 2026-09-04-3: a boundary token in a test file or a story no longer silences
# the finding. A fixture built to be rendered BY a test does not stand between
# a visitor and a blank page, and one was holding a real repository's only
# boundary token. Repositories protected only that way now fire.
# 2026-09-04-4: a confident critical gates from whatever category it sits in.
# The gate used to read only categories an examiner had covered, on the premise
# that nothing could produce an Auth or Money & Data finding without one --
# false since #299 (a static Auth producer) and since #10 (a rubric that ran
# files its finding by what it IS, so a preview's Security rubric can return a
# CRITICAL categorised Auth). Measured: the same critical scored 6.6 with the
# gate firing on a full audit and 9.9 with it silent on a preview. 0 stored
# rows move; the mean is deliberately unchanged, because admitting such a
# category to it RAISES a weak repository's total
# (scripts/measure_unexamined_evidence.py, route A -- measured and refused).
# 2026-09-07-7: preserve credential source roles and URI protocols;
# alternative deployment configuration is retained as inventory.
# 2026-09-07-8: record why eligible files were not submitted to the model.
# 2026-09-07-10: avoid native Point.row corruption on JS/TS files with large line numbers.
# 2026-09-07-11: pre-model React async state and button syntax evidence.
# 2026-09-08-1: catch resets, HTTP response branches and bounded absence checks.
# 2026-09-08-2: reject ambiguous archives and record secret-scan exclusions.
# 2026-09-08-3: guard/cost/policy evidence and unchecked HTTP success observations.
# 2026-09-08-5: source-bound premise counterexamples and operation-based cause grouping.
# 2026-09-08-6: count exact quote-bound model repeats once, retaining each response's provenance.
# 2026-09-09-1: bind narrow React network-cleanup repeats to source operations and retain all premises.
# 2026-09-09-2: distinguish default-strip Zod output from input rejection contracts.
# 2026-09-09-3: retain bounded rejection diagnostics and explicit acceptance accounting.
# 2026-09-09-4: compose source-bound React cleanup claims and disclose grouped claim scope.
# 2026-09-09-8: attach observational guard and consequence context without prose-derived refutations.
# 2026-09-09-9: tighten the citation contract and explain bounded quote mismatches without retaining quotes.
# 2026-09-09-10: bind numeric RPC clamps and imported collection caps to bounded source context.
# 2026-09-09-11: require external-operation idempotency and retry-budget prerequisites in advice.
# 2026-09-09-13: bind fact limits, local Intl handlers and parsed-string guards to individual claims.
# 2026-09-09-14: bind retry and duplicate-call premises, preserving conditional concurrency context.
# 2026-09-10-1: distinguish source interpolation from literal credentials and
# refuse secret Fix Packs for formats without a verified environment rewrite.
# 2026-09-10-2: dependency-known-vulnerability -- a new PAID stage that resolves
# the lockfiles' versions and asks the OSV database about them. It changes what
# a paid audit reports for unchanged bytes (and a new rule id is exactly the
# case this constant exists for), so the bump is not optional. Its answers are
# true of the day they were asked: the manifest records `sca_asked_at`, and a
# cached row older than SCA_FRESHNESS_TTL_DAYS is reported as stale rather than
# presented as current.
# 2026-09-10-3: preserve dependency findings on incomplete OSV refreshes,
# report unresolved inventory honestly, and fill missing SCA on paid cache hits.
# 2026-09-10-4: distinguish explicitly labelled local harness fixtures from
# production credentials and allocate independent environment keys per secret.
# 2026-09-10-5: integrate paid dependency evidence and freshness handling with
# the released harness-fixture classification and independent secret rewrites.
# 2026-09-10-6: python-route-write-auth-consistency -- a route that changes data
# is compared with a sibling route on the same router that shows an identity
# check. A new rule id is exactly the case this constant exists for: a paid or
# free audit reports something it did not report before, for unchanged bytes.
# The dependency vocabulary both route rules share was widened in the same
# change, so the read rule's findings move with it: two hunt rounds through
# scripts/hunt_detector_escapes.py showed a storage dependency renamed
# fetch_record_repository, and a write call named createRecord or executed as
# raw SQL, escaping a vocabulary built from one naming convention.
# 2026-09-10-8: reviewed route checks distinguish an unknown dependency from an
# identity witness, keep different router objects and nested function bodies
# separate, and report recognized write calls without claiming runtime effects.
# 2026-09-10-9: integrate the reviewed outbound URL rule with the reviewed
# route checks. Trace supported local request values to URL authority using
# HTTP import provenance, statement order and field-specific check identity;
# bound AST/template work and report unresolved runtime/network controls.
# This supersedes the outbound branch preview version 2026-09-10-7.
# 2026-09-10-10: skip unrelated Python route scopes; retain imported dependency
# aliases, same-repository guarded reads, and bounded model/string URL origins.
# 2026-09-10-13: bounded TLS configuration analysis with imported client/context
# provenance, real Python signatures and JS/TS syntax. Certificate-chain and
# hostname checks have separate explanations; escaped literals remain in scope.
# 2026-09-10-14: import-resolved deserialization with lexical shadowing and real
# YAML loader provenance; distinguish object construction, marshal values and
# version-dependent YAML defaults. Each changed rule set invalidates the cache.
# 2026-09-10-15: bounded request-to-filesystem traces with proven sink signatures,
# value-specific normalized-path guards and checks before template allocation.
# 2026-09-10-16: distinguish fixed SQL conditional fragments from input-built
# queries while preserving possible assembly paths across expression branches.
# 2026-09-11-1: read route declarations inside block statements -- a module-level
# `if:`/`try:`/`with:`/`for:` opens no scope, so a conditionally registered route
# still hangs on the router built in that scope and its handler still reads
# request input. Read-auth, write-auth, outbound-URL and path-traversal rules.
# 2026-09-11-2: insecure-session-cookie-attributes, a new static scanner for
# session cookies set without HttpOnly (Python calls, Django settings, Express,
# a Next.js cookie store, express-session config, document.cookie) or with an
# explicit SameSite=None. Reads Python and TS/JS; dependency trees excluded.
# 2026-09-11-3: exclude dependency trees before TLS, deserialization, outbound-URL
# and path-traversal file budgets so bundled dependencies do not displace own code.
# 2026-09-11-4: persist actual bounded-rule file coverage, including incomplete
# files, so old cached audits cannot stand in for a newly measured scan.
AUDIT_ENGINE_VERSION = "2026-09-11-4"

# 2026-09-09-18: success-copy vocabulary widened past six exact phrases, with
#               negation excluded -- react_async_context is part of the prompt
#               surface, so what the model is shown changed with it.
# 2026-09-09-19: sql-injection-string-built-query, a new static scanner.
# 2026-09-09-20: auth_read reads nested scopes, so routes declared in a router
#               factory are analysed instead of skipped.
# 2026-09-09-21: Russian success copy recognised in all its inflections, not
#               only the neuter -- react_async_context is in the prompt surface.

# 2026-09-09-22: generic-assignment reads a credential word as a component of an
#               identifier (db_password, adminToken), plus encryption_key.

# 2026-09-09-23: sql-injection-string-built-query now reads TypeScript and
#               JavaScript, which is what most audited repositories are written in.

# 2026-09-09-24: gitignore-missing-secrets reads the root .gitignore only, so a
#               nested one no longer reads as covering the whole repository.
# 2026-09-09-25: ci-deploys-a-different-repository ignores URLs that name no
#               deploy target; no-dockerfile's inventory covers compose,
#               Kubernetes, Terraform, Render, Railway and Dockerfile variants.

# 2026-09-09-26: sql-secret-assignment reads UPDATE/ALTER/DEFAULT assignments,
#               not only typed declarations; generic-assignment tolerates a
#               trailing separator before the value.
# 2026-09-09-27: sql-injection trusts a loop variable bound to a literal list,
#               which was reporting fixed table-name loops on real code.
# 2026-09-09-28: the same trust for a literal dict and its .items()/.keys().
# 2026-09-09-29: generic-assignment reads a credential word that STARTS the
#               name (tokenForAdmin, secretOne), not only one that ends it.
# 2026-09-09-30: generic-assignment reads a QUOTED object key
#               ({"db_password": "..."}); pwd dropped from the vocabulary.
# 2026-09-09-31: sql-secret-assignment reads DEFAULT(...) with parentheses, the
#               form ALTER TABLE actually wears.
# 2026-09-09-32: preserve credential values through Fix Pack planning; distinguish
#               SQL expressions from comparisons and non-SQL calls; scope SQL
#               assignments, deploy commands and completed-success labels.

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


def score_findings(findings: list[dict], *, llm_ran: bool,
                   llm_categories: frozenset[str],
                   incomplete_static: frozenset[str]) -> dict:
    """The single place a finding list becomes a score.

    Extracted so the dependency refresh can rescore an audit it did not run
    (app/sca/refresh.py) without owning a second copy of this expression: a
    second copy is how the refreshed total would drift from the total a full
    scan of the same findings produces, silently, one rule at a time.
    """
    return compute_scores(
        [ScoredFinding(**{k: f[k] for k in _SCORED_FIELDS if k in f})
         for f in findings],
        llm_ran=llm_ran,
        # Derived from the rubrics that ran, never written out: a preview
        # covers one of them, and a category no rubric looked at must not
        # score 10.0 off the back of the ones that did. Reading RUBRICS is
        # what keeps this correct when the free tier's rubric list is changed
        # by an env var.
        llm_categories=llm_categories,
        # A static producer that ran out of read budget did not finish, so the
        # absence of its finding is not evidence of a clean category.
        incomplete_static=incomplete_static,
    )


def run_scan(data: bytes, llm_client: LLMClient, llm_passes: int = 1,
             llm_skip_reason: str | None = None,
             llm_rubrics: tuple[str, ...] | None = None,
             depth: str = BASIS_FULL, llm_cost_cap: Decimal | None = None,
             sca_client: "OsvClient | None" = None) -> dict:
    """Returns {"score", "findings", "llm": <stats | status>, "llm_usage", "sca"}.

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

    `sca_client` turns on the dependency stage: it resolves the archive's
    lockfile versions and asks the OSV database about them. No client means the
    stage is skipped with a recorded reason (for example the free tier or a
    deployment with SCA disabled), and a database
    that cannot be reached degrades the same way -- never a failed audit, and
    never a clean bill of health. It is a separate argument from `llm_client`
    because the two decisions are separate: one is about spending money on a
    model, the other about sending a customer's dependency list to a third
    party.
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
                source_facts=static.get("source_facts"),
                **({} if llm_cost_cap is None else {"cost_cap_usd": llm_cost_cap}),
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

    # After the LLM stage and outside its try/except on purpose: a provider
    # failure must not cost the dependency check, and the dependency check's
    # failure must not degrade the basis. They answer different questions.
    sca_findings, sca_summary = run_sca_stage(data, sca_client)
    if sca_findings:
        findings = findings + [vars(finding) for finding in sca_findings]

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
            **score_findings(
                findings,
                llm_ran=llm_ran,
                llm_categories=frozenset(
                    RUBRICS[r]["category"] for r in ran if r in RUBRICS),
                incomplete_static=frozenset(
                    {"Frontend"}
                    if static.get("coverage", {}).get("error_boundary")
                    == "budget_exhausted" else set()),
            ),
            # Carried through from the static stage, which decided it. Without
            # this line a PAID row would be blind to the same question a
            # static-only row can answer, and the paid rows are the ones a
            # calibration decision costs money to get wrong.
            "scan_manifest": scan_manifest(data, AUDIT_ENGINE_VERSION, static,
                                           llm_summary if isinstance(llm_summary, dict) else vars(spend),
                                           llm_failure_kind(llm_summary),
                                           sca_summary),
            "frontend_scan": static.get("score", {}).get("frontend_scan", {}),
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
            "basis": ((BASIS_PARTIAL if any(llm_summary.get(k) for k in
                                           ("failure", "cost_cap_exceeded", "input_truncated",
                                            "invalid_responses")) else depth)
                      if llm_ran else BASIS_STATIC_ONLY),
        },
        "findings": findings,
        "llm": llm_summary,
        "llm_usage": vars(spend),
        # The dependency stage's facts, including WHY it did not run. Callers
        # that persist a scan carry this into the manifest; a caller that drops
        # it turns "we never asked" into "we found nothing".
        "sca": sca_summary,
    }
