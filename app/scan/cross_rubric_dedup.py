"""Collapse the same LLM finding reported by more than one rubric.

The auth and security rubrics run as two independent prompts over
overlapping file sets, so both can flag the SAME issue at the same
(file, line) — seen in production: one hardcoded cron secret reported
once per rubric, double-penalizing the score. (In union-of-N mode the
same issue also repeats across passes.) We keep the single most-severe
instance per location and, when a *different* rubric also flagged it,
record that on the survivor instead of dropping it silently — a second
rubric independently confirming an issue is signal, not noise.

Grouping is on file + nearby line + title similarity — NOT rule_id — so
a medium from one rubric and a high from the other collapse into one.
Two rubrics often anchor the same issue to different lines of one
multi-line statement (seen in production: an HMAC-derived-password call
spanning four lines, flagged at line 46 by one rubric and 47 by the
other), so exact-line grouping under-merged. We now group within a small
line window AND require the titles to be about the same thing, so
genuinely distinct issues that merely sit near each other are not merged.
Only LLM findings (rule_id "llm-*") are grouped: static-scan findings
pass through untouched even when they share a location with an LLM
finding, because the two scanners detect genuinely different things (a
regex secret hit vs. a semantic auth flaw) and are not the same issue.
"""
from __future__ import annotations

from dataclasses import replace
from difflib import SequenceMatcher

from app.scan.scoring import ScoredFinding

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# rule_id -> plain-language rubric name, for the provenance note (the
# report is read by non-technical founders — see app/report/plain_language.py).
_RUBRIC_LABEL = {"llm-auth": "auth review", "llm-security": "security review"}

# Two rubrics may anchor the same issue to different lines within one
# multi-line statement. 3 covers a typical such statement end-to-end (the
# real calibration case is a 4-line crypto.createHmac(...) call, lines
# 46-49, so its ends are 3 apart) without reaching into the next, unrelated
# statement. Exact-line matches (distance 0) are the trivial subset.
_NEARBY_LINE_WINDOW = 3

# difflib ratio (case-insensitive) over the two titles. Calibrated on the
# real duplicate that motivated this: "Deterministic password derived from
# service-role key — key rotation breaks all Telegram accounts" vs
# "Telegram user password derived from SUPABASE_SERVICE_ROLE_KEY" scores
# 0.535 lowercased and MUST merge; a same-domain-but-distinct pair (missing
# auth check vs. missing rate limit) scores ~0.42-0.49 and must NOT. 0.5
# sits in that gap. Titles are compared (not explanations): title is always
# populated (llm_scan REQUIRED), explanation can be empty.
_TITLE_SIMILARITY_THRESHOLD = 0.5


def _title_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _same_issue(anchor: ScoredFinding, f: ScoredFinding) -> bool:
    """Both signals required (AND): near in the file AND about the same
    thing. Same-line (distance 0) is included, keeping the old exact-line
    behavior as the trivial subset of this one condition."""
    return (
        anchor.file == f.file
        and abs(anchor.line - f.line) <= _NEARBY_LINE_WINDOW
        and _title_ratio(anchor.title, f.title) >= _TITLE_SIMILARITY_THRESHOLD
    )


def dedup_cross_rubric(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Keep one finding per same-issue group across LLM rubrics, most
    severe (then most confident) wins; ties keep the first seen. A group
    is findings in the same file, within a small line window, with
    similar titles (see _same_issue). Non-LLM findings are returned
    untouched, in their original positions."""
    groups: list[list[ScoredFinding]] = []
    slot_of: list[int] = []  # parallel to groups: each group's out index
    out: list[ScoredFinding | None] = []

    for f in findings:
        if not f.rule_id.startswith("llm-"):
            out.append(f)  # static scan — never merged with LLM findings
            continue
        # First group whose anchor (first seen, per tie rule) is the same
        # issue. Adjacency is judged against that anchor, matching the old
        # "first seen wins" semantics.
        gi = next((i for i, m in enumerate(groups) if _same_issue(m[0], f)), None)
        if gi is None:
            slot_of.append(len(out))
            groups.append([f])
            out.append(None)  # reserve this group's slot, filled below
        else:
            groups[gi].append(f)

    for members, slot in zip(groups, slot_of):
        rep = min(members, key=lambda f: (_SEV_RANK[f.severity], -f.confidence))
        others = sorted({f.rule_id for f in members} - {rep.rule_id})
        if others:
            labels = ", ".join(_RUBRIC_LABEL.get(r, r) for r in others)
            # Say "at a nearby line" only when the confirmation was actually
            # at a different line, so the note stays accurate for both the
            # same-line and widened cases.
            where = " at a nearby line" if any(m.line != rep.line for m in members) else ""
            note = f" Also independently flagged by the {labels}{where}."
            rep = replace(rep, explanation=(rep.explanation + note).strip()[:600])
        out[slot] = rep

    return out
