"""Findings diff for continuous monitoring: which critical/high findings in a
new audit are NEW versus the previous audit of the same repo.

A finding's identity across audit runs is (rule_id, file). We deliberately
EXCLUDE `line`: the LLM/static scanners report a line number, but it shifts when
unrelated code is added or removed above the finding, which would make every
trivial edit look like a brand-new finding and spam the subscriber. (rule_id,
file) is the tightest key that survives incidental line drift while still
distinguishing genuinely different issues.

"New" means the (rule_id, file) key was absent from the ENTIRE previous
findings set (any severity), and the finding is critical or high now. So a
finding that was medium before and is high now on the same (rule_id, file) is
NOT flagged -- it's the same issue re-scored, not a new one. Severity-escalation
alerts are a deliberate non-goal of this MVP.
"""

from __future__ import annotations

from typing import Any

_NOTIFY_SEVERITIES = ("critical", "high")


def _key(finding: dict[str, Any]) -> tuple[str, str]:
    return (finding.get("rule_id") or "", finding.get("file") or "")


def new_high_severity_findings(
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """The critical/high findings in `current` whose (rule_id, file) key did not
    appear anywhere in `previous`. `previous` None/empty (repo never audited)
    means every critical/high finding in `current` is new."""
    prev_keys = {_key(f) for f in (previous or [])}
    out: list[dict[str, Any]] = []
    for f in current or []:
        if f.get("severity") in _NOTIFY_SEVERITIES and _key(f) not in prev_keys:
            out.append(f)
    return out
