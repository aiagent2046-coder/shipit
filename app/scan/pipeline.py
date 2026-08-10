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
import zipfile

from app.llm.client import LLMClient, LLMError
from app.scan.collapse import collapse_repeats
from app.scan.llm_scan import LLMScanStats, run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.static import run_static_scan

logger = logging.getLogger(__name__)

_SCORED_FIELDS = ("rule_id", "title", "severity", "confidence",
                  "category", "file", "line", "masked", "explanation",
                  "fix_hint", "context")


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
AUDIT_ENGINE_VERSION = "2026-08-10-3"


# The two values `score["basis"]` can take, named because they are now a
# pricing boundary and not only a diagnostic. BASIS_STATIC_ONLY used to mean
# "something went wrong or the budget ran out"; it is now also what the free
# tier deliberately delivers.
BASIS_FULL = "static+llm"
BASIS_STATIC_ONLY = "static_only"

# Passed as llm_skip_reason when the caller is not a paying account. Distinct
# from "daily_spend_cap" on purpose: that reason means we ran out of money, this
# one means we never intended to spend any.
FREE_TIER_LLM_SKIP_REASON = "free_tier"


def basis_for_account(account_id: object | None) -> str:
    """Which scan depth this caller is entitled to.

    One definition, because three places need to agree: the worker deciding
    whether to call the LLM, and the two cache lookups deciding which stored
    result may be reused. When they disagreed, an anonymous visitor could be
    served a paid full audit out of the cache and a paying account could be
    served a free static one.

    Static-only for anonymous is not a degradation to apologise for. It is the
    free product: the static rules and secret scanning cost nothing to run, and
    they are what found the committed .env in audit ed402e63.
    """
    return BASIS_FULL if account_id else BASIS_STATIC_ONLY


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
             llm_skip_reason: str | None = None) -> dict:
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
    """
    static = run_static_scan(io.BytesIO(data))
    findings = static["findings"]
    llm_summary: object = vars(LLMScanStats(
        skipped_reason=llm_skip_reason or "no_providers_configured"))
    # Owned here, not by run_llm_scan, so its contents survive an LLMError.
    spend = LLMScanStats()

    if llm_client.providers and llm_skip_reason is None:
        try:
            llm_findings, stats = run_llm_scan(io.BytesIO(data), llm_client,
                                               passes=llm_passes, stats=spend)
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

    # One expression, read twice: it decides the reported basis AND which
    # categories are allowed to vote on the total. Computing it once is what
    # stops the two from drifting apart -- a score whose basis says
    # static-only while Auth still carries weight is the exact lie this
    # replaced.
    llm_ran = (isinstance(llm_summary, dict)
               and llm_summary.get("skipped_reason") is None)

    return {
        "score": {
            **compute_scores(
                [ScoredFinding(**{k: f[k] for k in _SCORED_FIELDS if k in f})
                 for f in findings],
                llm_ran=llm_ran,
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
            "basis": BASIS_FULL if llm_ran else BASIS_STATIC_ONLY,
        },
        "findings": findings,
        "llm": llm_summary,
        "llm_usage": vars(spend),
    }
