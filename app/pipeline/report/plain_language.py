"""Plain-language layer for the audit report.

Describe observations, evidence limits and conditional consequences so the
reader can decide what to verify. A pattern match does not establish that a
credential is live, that a service is reachable, or that an attack succeeded.
"""

from __future__ import annotations

from app.runtime.finding_text import (  # noqa: F401  (re-exported)
    CREDENTIAL_RULES,
    PLAIN,
    _uses_bounded_static_copy,
    plain_fields,
)

# severity -> reader-facing tier (technical severity stays in the API
# and in the collapsed developer details)
TIERS = {
    "critical": ("🔥", "Fix before launch"),
    "high": ("⚠️", "Important"),
    "medium": ("👀", "Worth fixing"),
    "low": ("📝", "Good to know"),
}

# rule_id -> (what it is, what can go wrong, what to do)
def tier(severity: str) -> tuple[str, str]:
    return TIERS.get(severity, ("📝", "Good to know"))
