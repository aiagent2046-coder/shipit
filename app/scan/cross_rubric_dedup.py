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
    """Same line is enough. A nearby line additionally needs similar titles.

    Requiring title similarity everywhere was measured and does not work. On a
    paying customer's report two pairs reached the reader twice each, and the
    ratios explain why the gate never fired:

        0.317  "Command injection via unsanitised user-controlled parameter"
               vs "User-controlled input interpolated into SSH shell commands"
        0.352  "Unauthenticated endpoint executes arbitrary SSH commands"
               vs "No authentication on action execution endpoint"
        0.535  the pair this threshold was calibrated to MERGE
        0.588  a same-place-but-distinct pair that must NOT merge

    The classes are interleaved: the pair that must stay apart scores higher
    than both that must join. No threshold separates them, so the signal is
    wrong rather than the constant, and lowering it would only merge more of
    the wrong things.

    What does separate them is position. Two rubrics anchoring to the SAME
    line are looking at one place in one file, and two prompts over
    overlapping files reaching the same line is the ordinary way one issue
    gets reported twice. The line window exists for a different case -- one
    statement spanning several lines, where the titles genuinely are alike --
    so it keeps the similarity test it was calibrated with.

    The cost is named: two genuinely distinct issues anchored to the same line
    (a decorator attracts "no auth" and "no rate limit" alike) now merge. That
    is why the merge carries the other title into the survivor's explanation
    instead of discarding it -- the finding loses its own row, not its
    existence.
    """
    if anchor.file != f.file:
        return False
    distance = abs(anchor.line - f.line)
    if distance == 0:
        return True
    return (distance <= _NEARBY_LINE_WINDOW
            and _title_ratio(anchor.title, f.title) >= _TITLE_SIMILARITY_THRESHOLD)


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
            # The other wording, kept. Merging on position alone can join two
            # genuinely different issues that share a line, so the survivor
            # has to carry what the other one said or the second issue leaves
            # no trace at all. Dissimilar titles are exactly the ones worth
            # repeating; near-identical ones would only pad the explanation.
            extra = [
                m.title for m in members
                if m is not rep
                and _title_ratio(m.title, rep.title) < _TITLE_SIMILARITY_THRESHOLD
            ]
            if extra:
                note += " Reported there as: " + "; ".join(sorted(set(extra))) + "."
            rep = replace(rep, explanation=(rep.explanation + note).strip()[:600])
        out[slot] = rep

    return out
