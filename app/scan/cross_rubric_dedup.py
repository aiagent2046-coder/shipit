"""Collapse the same LLM finding reported by more than one rubric.

The auth and security rubrics run as two independent prompts over
overlapping file sets, so both can flag the SAME issue at the same
(file, line) — seen in production: one hardcoded cron secret reported
once per rubric, double-penalizing the score. (In union-of-N mode the
same issue also repeats across passes.) We keep the single most-severe
instance per location and, when a *different* rubric also flagged it,
record that on the survivor instead of dropping it silently — a second
rubric independently confirming an issue is signal, not noise.

Grouping is on (file, line) only — NOT rule_id — so a medium from one
rubric and a high from the other collapse into one. Only LLM findings
(rule_id "llm-*") are grouped: static-scan findings pass through
untouched even when they share a location with an LLM finding, because
the two scanners detect genuinely different things (a regex secret hit
vs. a semantic auth flaw) and are not the same issue.
"""
from __future__ import annotations

from dataclasses import replace

from app.scan.scoring import ScoredFinding

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# rule_id -> plain-language rubric name, for the provenance note (the
# report is read by non-technical founders — see app/report/plain_language.py).
_RUBRIC_LABEL = {"llm-auth": "auth review", "llm-security": "security review"}


def dedup_cross_rubric(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Keep one finding per (file, line) across LLM rubrics, most severe
    (then most confident) wins; ties keep the first seen. Non-LLM
    findings are returned untouched, in their original positions."""
    groups: dict[tuple[str, int], list[ScoredFinding]] = {}
    slot_of: dict[tuple[str, int], int] = {}
    out: list[ScoredFinding | None] = []

    for f in findings:
        if not f.rule_id.startswith("llm-"):
            out.append(f)  # static scan — never merged with LLM findings
            continue
        key = (f.file, f.line)
        if key not in groups:
            groups[key] = []
            slot_of[key] = len(out)
            out.append(None)  # reserve this location's slot, filled below
        groups[key].append(f)

    for key, members in groups.items():
        rep = min(members, key=lambda f: (_SEV_RANK[f.severity], -f.confidence))
        others = sorted({f.rule_id for f in members} - {rep.rule_id})
        if others:
            labels = ", ".join(_RUBRIC_LABEL.get(r, r) for r in others)
            note = f" Also independently flagged by the {labels}."
            rep = replace(rep, explanation=(rep.explanation + note).strip()[:600])
        out[slot_of[key]] = rep

    return out
