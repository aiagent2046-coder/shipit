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
        stripped = value.removesuffix(".git")
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
