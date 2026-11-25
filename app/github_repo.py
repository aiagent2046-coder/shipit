"""GitHub repository URL parsing: the one shape guard for repo intake.

Bottom layer shared by the routes helpers, the Fix Pack delivery auth,
the worker, the MCP tools and the audit entry point. Moved out of
app.routes._shared during the import-cycles fix phase so that service
modules never import from the routes package.
"""
from __future__ import annotations

import re

_VALID_OWNER_REPO_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")

# Shape guard for the repo_url intake path. Host must be EXACTLY
# github.com (the literal `github.com/` right after the scheme rejects
# userinfo tricks like https://github.com@evil.com/... and any
# subdomain or :port), scheme must be https. The two path segments are
# then re-validated with _VALID_OWNER_REPO_SEGMENT — same rule as
# deliver_to, no second charset — so nothing but a clean owner/repo can
# reach the fetch. This runs before any network call: it is the SSRF guard.
_GITHUB_REPO_URL = re.compile(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")


def _parse_github_repo_url(repo_url: str) -> tuple[str, str] | None:
    m = _GITHUB_REPO_URL.match(repo_url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if not (_VALID_OWNER_REPO_SEGMENT.match(owner)
            and _VALID_OWNER_REPO_SEGMENT.match(repo)):
        return None
    return owner, repo
