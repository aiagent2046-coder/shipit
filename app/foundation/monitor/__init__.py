"""Phase C — Continuous Monitoring.

Pure helpers shared by the Telegram bot (`/monitor`), the GitHub push webhook,
and the database layer:

  * normalize_repo_full_name -- one canonical 'owner/repo' form so a
    subscription's stored repo and a push payload's repository name compare
    equal regardless of casing, a trailing '.git', or a trailing slash. This is
    the single normalization both sides route through; a mismatch here would
    silently bury the whole findings diff (the two sides would never join), so
    it lives in exactly one place.
  * new_high_severity_findings (see .diff) -- the "did this push introduce a new
    critical/high finding?" comparison against the previous audit.
"""

from __future__ import annotations

import re

# Monitoring is NOT FOR SALE. Three things were true at the same time (#184):
# the price was a placeholder 1 star; the LLM spend a run drives is attributed
# to the anonymous bucket because a subscriber has no account row; and since
# the free tier became static-only that bucket's daily cap guards nothing,
# because free audits stopped contributing to it. Net effect: every push to a
# subscribed repository triggered an uncapped, effectively unpaid full audit.
#
# Withdrawn rather than repriced. The price, the spend attribution and the cap
# are three separate decisions and none of them has been made, so guessing at
# one of them would just move the leak.
#
# Read at three sale surfaces (/subscribe and /monitor in the bot, the PayPal
# subscription route) AND at the push-webhook enqueue, which is the one that
# matters: gating only the sales would leave any already-active subscription
# row spending on every push. The flag, not a migration, so re-enabling is a
# one-line revert and no paid row is destroyed in the meantime.
MONITORING_FOR_SALE = False

# How long a repo is ineligible after a monitoring run: the cost cap, the
# enqueue-dedup and the concurrency guard, all expressed as one interval in
# SubscriptionRepository.claim_for_monitoring's conditional UPDATE.
#
# WHAT A RUN COSTS, since that is what this number buys. A monitoring run is
# not a cheap incremental check: app/main.py's _process_one_monitoring_run
# calls run_repo_audit, which calls run_scan with its defaults -- one pass,
# all four rubrics, the whole repository. Nothing about the push reaches the
# prompt (build_prompt takes rubric instructions, a repo map and whole files);
# the diff is applied to the FINDINGS afterwards. So a run costs what a
# one-pass paid audit costs: measured across 21 production runs of the
# four-call era, median $0.96, p90 $3.82, max $4.60.
#
# At 24 hours that is up to ~30 runs a month on an actively developed repo,
# ~$29 at the median. At 72 it is ~10, ~$10. The one measurement in llm_usage
# (2026-08-04) is a 12-file fixture at $0.02 and says nothing about a real
# repository -- it is not evidence for a lower number.
#
# WHAT WIDENING IT COSTS, which is only latency. Each run audits HEAD, not the
# push that triggered it, so a skipped push is not skipped coverage: the next
# eligible run sees the accumulated changes and the union baseline still marks
# anything genuinely new. A finding introduced and removed inside the window
# goes unreported, and it is also gone. The subscriber learns about a real new
# finding up to two days later than before; nothing else changes.
#
# Not env-overridable on purpose. It is a spend decision, and this deployment
# has already had one silent env edit turn every paid audit static-only
# (2026-08-28); a cost cap that a hand edit can widen to zero is not a cap.
MONITORING_INTERVAL_HOURS = 72

# owner/repo are the two path segments of a github.com URL. Case-insensitive
# host match (a stored repo_url always has a lowercase host from intake, but a
# push payload's repository.html_url may not); owner/repo casing is captured as
# typed and lowercased below.
_REPO_URL_RE = re.compile(
    r"^https://github\.com/([^/]+?)/([^/]+?)(?:\.git)?/?$", re.IGNORECASE
)


def normalize_repo_full_name(value: str | None) -> str | None:
    """Canonical lowercased 'owner/repo' from either a full github.com URL
    (audits.repo_url, as typed at intake) or an 'owner/repo' string (a push
    payload's repository.full_name). Returns None if it can't be parsed to
    exactly two non-empty segments.

    GitHub treats owner and repo names case-insensitively, so we lowercase:
    an audit stored as https://github.com/Acme/App and a push for Acme/app must
    resolve to the same key or the diff baseline is never found. Also strips a
    trailing '.git' and trailing slash for the same reason."""
    if not value:
        return None
    value = value.strip()
    m = _REPO_URL_RE.match(value)
    if m:
        owner, repo = m.group(1), m.group(2)
    else:
        stripped = value[:-4] if value.endswith(".git") else value
        stripped = stripped.strip("/")
        parts = stripped.split("/")
        if len(parts) != 2:
            return None
        owner, repo = parts
    if not owner or not repo:
        return None
    return f"{owner.lower()}/{repo.lower()}"


def repo_url_from_full_name(repo_full_name: str) -> str:
    """The canonical https URL for a normalized 'owner/repo'. Used to feed the
    audit fetcher and to stamp audits.repo_url on a monitoring re-audit."""
    return f"https://github.com/{repo_full_name}"
