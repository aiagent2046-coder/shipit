"""Collapse repeats of one rule into a single finding.

A real report on a Lovable export listed the same Supabase anon key as
47 separate rows — one per migration file — burying every other finding
and reading as noise. When one rule_id fires across many files, the
signal is "this pattern is everywhere", not forty-seven independent
problems. We keep the highest-severity instance as the representative,
record how many places matched, and drop the rest.

Only rules known to spread across files are collapsed; a rule that
legitimately fires once per distinct issue (e.g. a distinct hardcoded
password per service) is left alone.
"""
from __future__ import annotations

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Rules whose repeats are the SAME underlying fact spread across files.
COLLAPSIBLE = frozenset((
    "supabase-anon-key",   # public key copied into every migration
    "jwt-in-code",
    "sql-secret-assignment",
    "generic-assignment",
))


def collapse_repeats(findings: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    passthrough: list[dict] = []
    for f in findings:
        rid = str(f.get("rule_id", ""))
        if rid in COLLAPSIBLE:
            groups.setdefault(rid, []).append(f)
        else:
            passthrough.append(f)

    collapsed: list[dict] = []
    for rid, group in groups.items():
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        rep = min(group, key=lambda f: (
            _SEV_RANK.get(str(f.get("severity")), 9),
            -float(f.get("confidence", 0)),
        ))
        rep = dict(rep)
        n = len(group)
        files = sorted({str(f.get("file", "")) for f in group if f.get("file")})
        shown = ", ".join(files[:5]) + (f" and {len(files) - 5} more" if len(files) > 5 else "")
        rep["occurrence_count"] = n
        rep["occurrence_files"] = files
        base_title = str(rep.get("title", "")).split(" · ")[0]
        rep["title"] = f"{base_title} — found in {n} places"
        note = f" This appears in {n} files: {shown}."
        rep["explanation"] = (str(rep.get("explanation", "")) + note).strip()
        collapsed.append(rep)

    return passthrough + collapsed
