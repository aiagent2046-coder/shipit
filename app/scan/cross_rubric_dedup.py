"""Conservative cross-rubric grouping by location and a shared cause.

A shared line is not an issue identity. Unknown paraphrases stay separate;
recognized single mechanisms can merge, with every original retained.
"""
from __future__ import annotations

from dataclasses import replace
from difflib import SequenceMatcher
import re

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


def _mechanisms(title: str) -> frozenset[str]:
    """Small, conservative cause vocabulary; categories/rubrics are not causes.

    Compound titles are never reduced to one of their constituent mechanisms.
    This is grouping of hypotheses, not verification of their source claims.
    """
    patterns = {
        "authentication": r"unauthenticated|(?:no|missing|without) (?:server.side )?(?:authentication|auth check)",
        "rate_limit": r"rate[ -]limit",
        "service_role_access": r"service[ _-]*role.*(?:client|database|reads|writes|RLS)|"
                               r"(?:client|RLS).*service[ _-]*role",
        "derived_password": r"password.*(?:derived|service.role)|(?:deterministic|derived).*password",
        "shell_interpolation": r"command injection|(?:input|parameter).*interpolat.*(?:shell|SSH)|"
                               r"(?:shell|SSH).*interpolat.*input",
    }
    return frozenset(key for key, pattern in patterns.items() if re.search(pattern, title, re.I))


def _same_issue(anchor: ScoredFinding, f: ScoredFinding) -> bool:
    if anchor.file != f.file:
        return False
    # A contradicted or partially checked claim cannot absorb an unresolved one.
    for key in ("syntax_check", "premise_checks"):
        if (anchor.claim_evidence or {}).get(key) != (f.claim_evidence or {}).get(key):
            return False

    def recommendation_status(item):
        return ((item.claim_evidence or {}).get("recommendation_check") or {}).get("result")
    if recommendation_status(anchor) != recommendation_status(f):
        return False

    def function_key(item):
        return {(c["file"], c["function_line_start"], c["function_line_end"],
                 tuple(c["read_lines"]), c["equivalence"])
                for c in (item.claim_evidence or {}).get("context_checks", [])
                if c.get("kind") == "operator_guard_order" and c.get("equivalence")}

    if function_key(anchor) & function_key(f):
        return True
    if abs(anchor.line - f.line) > _NEARBY_LINE_WINDOW:
        return False
    a, b = anchor.title.casefold().strip(), f.title.casefold().strip()
    if a == b:
        return True
    causes_a, causes_b = _mechanisms(a), _mechanisms(b)
    if len(causes_a) != 1 or causes_a != causes_b:
        return False
    # Recognized paraphrases at the same line share one mechanism. Nearby
    # statements still need similar wording to limit accidental joining.
    return anchor.line == f.line or _title_ratio(a, b) >= _TITLE_SIMILARITY_THRESHOLD


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
            # Say "at a nearby line" only when the other observation was actually
            # at a different line, so the note stays accurate for both the
            # same-line and widened cases.
            where = " at a nearby line" if any(m.line != rep.line for m in members) else ""
            note = (f" Also reported by the {labels}{where}; "
                    "this is not independent confirmation.")
            # Preserve recognized paraphrases as provenance, not confirmation.
            extra = [
                m.title for m in members
                if m is not rep
                and _title_ratio(m.title, rep.title) < _TITLE_SIMILARITY_THRESHOLD
            ]
            if extra:
                note += " Reported there as: " + "; ".join(sorted(set(extra))) + "."
            rep = replace(rep, explanation=(rep.explanation + note).strip())
        if len(members) > 1:
            # Keep all original interpretations, including same-rubric repeats.
            # Source excerpts are intentionally absent (they may contain secrets).
            originals = [{"rule_id": m.rule_id, "file": m.file, "line": m.line,
                          "title": m.title, "explanation": m.explanation,
                          "fix_hint": m.fix_hint, "severity": m.severity, "confidence": m.confidence,
                          "category": m.category, "claim_evidence": m.claim_evidence}
                         for m in members]
            rep = replace(rep, claim_evidence={"version": 1, **(rep.claim_evidence or {}),
                                              "grouped_originals": originals})
        out[slot] = rep

    return out
