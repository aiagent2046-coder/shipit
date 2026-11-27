"""Audit basis vocabulary: how deep an audit went, and what a caller is
entitled to.

Shared by the scan pipeline, the worker, the MCP tools and the dependency
refresh; extracted from app/scan_pipeline.py during the import-cycles fix
phase.
"""
from __future__ import annotations

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


BASIS_STATIC_ONLY = "static_only"


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
