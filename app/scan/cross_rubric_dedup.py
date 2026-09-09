"""Conservative grouping by source operation and compatible claim status.

New interpretations require a trusted source identity. Exact repeats of one
quote-checked observation can also share a row when that identity is unresolved.
Legacy reports retain their location/cause fallback. All original interpretations
and statuses survive grouping, including pre-grouped input.
"""
from __future__ import annotations

from dataclasses import fields, replace
from collections import Counter
from difflib import SequenceMatcher
import re
import json

from app.scan.scoring import ScoredFinding
from app.scan.react_network_identity import (
    MECHANISM, network_premise_projection, title_label_disagreement, valid_network_identity,
)

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


def _exact_observation(finding: ScoredFinding) -> str | None:
    """An identical observation is not a new penalty for another model response.

    Only scanner-accepted, quote-bound LLM rows with an explicitly unresolved
    identity qualify. Do not infer semantic equivalence from similar text or
    erase any substantive field, status, or producer metadata. The original
    response numbers stay in grouped_originals; this key is only for matching.
    """
    record = finding.claim_evidence or {}
    if ("source_issue_identity" not in record or record["source_issue_identity"] is not None
            or finding.source != "llm" or finding.verification_method != "model_review"
            or not isinstance(finding.file, str) or not finding.file.strip()
            or type(finding.line) is not int or finding.line < 1):
        return None
    check, producer = record.get("source_check"), record.get("producer")
    if not isinstance(check, dict) or not isinstance(producer, dict):
        return None
    start, end = check.get("line_start"), check.get("line_end")
    if (check.get("kind") != "quote_match" or type(start) is not int or type(end) is not int
            or not 1 <= start <= finding.line <= end
            or any(not isinstance(producer.get(key), str) or not producer[key].strip()
                   for key in ("model", "rubric"))
            or type(producer.get("response")) is not int or producer["response"] < 1):
        return None
    payload = {key: getattr(finding, key) for key in _FINDING_FIELDS}
    payload["claim_evidence"] = {
        **record, "producer": {key: value for key, value in producer.items() if key != "response"},
    }
    try:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return None  # Malformed evidence cannot establish an exact repeat.


def _same_issue(anchor: ScoredFinding, f: ScoredFinding) -> bool:
    if anchor.file != f.file:
        return False
    ea, eb = anchor.claim_evidence or {}, f.claim_evidence or {}
    has_source = "source_issue_identity" in ea or "source_issue_identity" in eb
    identity_a, identity_b = ea.get("source_issue_identity"), eb.get("source_issue_identity")
    if has_source and (not identity_a or identity_a != identity_b):
        exact = _exact_observation(anchor)
        return exact is not None and exact == _exact_observation(f)
    network = isinstance(identity_a, dict) and identity_a.get("mechanism") == MECHANISM
    if network:
        if not valid_network_identity(identity_a, anchor.file):
            return False
        # Grouping an unresolved hypothesis cannot turn different execution or
        # verification dispositions into one row. Other matchers are unchanged.
        for key in ("source", "verification_method", "verification_status", "category", "origin_category"):
            if getattr(anchor, key) != getattr(f, key):
                return False
        if anchor.source != "llm" or anchor.verification_method != "model_review":
            return False
    # The source operation, not the model's selector coordinates, establishes
    # identity. Different check kinds/dispositions still retain separate rows.
    for key in ("syntax_check", "premise_checks"):
        a, b = ea.get(key), eb.get(key)
        if network and key == "premise_checks":
            a, b = network_premise_projection(a, identity_a), network_premise_projection(b, identity_b)
        if has_source:
            a, b = _check_status(a), _check_status(b)
        if a != b:
            return False
    for key in ("conditions_status", "consequence_status"):
        if ea.get(key) != eb.get(key):
            return False

    def recommendation_status(item):
        return ((item.claim_evidence or {}).get("recommendation_check") or {}).get("result")
    if recommendation_status(anchor) != recommendation_status(f):
        return False
    if has_source:
        return True

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


def _check_status(value):
    """Keep semantic status, excluding selector coordinates and prose."""
    if isinstance(value, list):
        return sorted({_check_status(item) for item in value}, key=repr)
    if not isinstance(value, dict):
        return value
    return tuple((key, json.dumps(value[key], sort_keys=True)) for key in (
        "kind", "result", "target", "source_entities", "scope", "claim_scope", "disposition", "whole_finding"
    ) if key in value)


_FINDING_FIELDS = {field.name for field in fields(ScoredFinding)}
_REQUIRED_FIELDS = {"rule_id", "title", "severity", "confidence", "category"}


def _original(finding):
    # Retain origin_category, provenance and verification statuses as well as
    # all original evidence. Never nest a grouping inside another grouping.
    values = {key: getattr(finding, key) for key in _FINDING_FIELDS}
    if values["claim_evidence"]:
        values["claim_evidence"] = {key: value for key, value in values["claim_evidence"].items()
                                    if key != "grouped_originals"}
    return values


def _flatten(finding, depth=0):
    originals = (finding.claim_evidence or {}).get("grouped_originals")
    if not isinstance(originals, list) or not originals or depth >= 8:
        yield finding
        return
    # Malformed history cannot silently erase the displayed representative.
    if any(not isinstance(item, dict) or not _REQUIRED_FIELDS <= item.keys() for item in originals):
        yield finding
        return
    for item in originals:
        original = ScoredFinding(**{key: value for key, value in item.items() if key in _FINDING_FIELDS})
        yield from _flatten(original, depth + 1)


def dedup_cross_rubric(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Group source-identical LLM hypotheses with compatible evidence status.

    Historical findings without source identities retain the conservative
    legacy matcher. Representatives are selected before grouping, so choosing
    a more severe row cannot leave two representatives that should join. Every
    original is retained, and pre-grouped input is flattened before regrouping.
    """
    entries = []
    seen = Counter()
    seen_groups = set()
    for position, finding in enumerate(findings):
        if not finding.rule_id.startswith("llm-"):
            entries.append((position, finding))
            continue
        from_group = bool((finding.claim_evidence or {}).get("grouped_originals"))
        represented_before = seen.copy() if from_group else None
        group_counts = Counter()
        for leaf in _flatten(finding):
            fingerprint = json.dumps(_original(leaf), sort_keys=True, ensure_ascii=False, default=str)
            # Pre-grouped input can overlap with another group or an original.
            # Such overlap is not an additional observation/model response.
            if from_group:
                seen_groups.add(fingerprint)
                group_counts[fingerprint] += 1
                if group_counts[fingerprint] <= represented_before[fingerprint]:
                    continue
            elif fingerprint in seen_groups:
                continue
            seen[fingerprint] += 1
            entries.append((position, leaf))

    groups = []
    static = []
    def priority(item):
        finding = item[1][1]
        # Input positions change when old groups are flattened. A stable
        # source/origin tie-break keeps group membership unchanged on replay.
        return (_SEV_RANK.get(finding.severity, 4), -finding.confidence,
                finding.file, finding.line,
                json.dumps(_original(finding), sort_keys=True, ensure_ascii=False, default=str))

    ordered = sorted(enumerate(entries), key=priority)
    for original_order, (position, finding) in ordered:
        if not finding.rule_id.startswith("llm-"):
            static.append((position, original_order, finding))
            continue
        match = next((members for members in groups if _same_issue(members[0][2], finding)), None)
        if match is None:
            groups.append([(position, original_order, finding)])
        else:
            match.append((position, original_order, finding))

    out = list(static)
    for members in groups:
        rep = members[0][2]
        origins = [item[2] for item in sorted(members, key=lambda item: item[1])]
        others = sorted({finding.rule_id for finding in origins} - {rep.rule_id})
        if others:
            labels = ", ".join(_RUBRIC_LABEL.get(rule, rule) for rule in others)
            distance = max(abs(finding.line - rep.line) for finding in origins)
            where = (" at another source location" if distance > _NEARBY_LINE_WINDOW else
                     " at a nearby line" if distance else "")
            note = (f" Also reported by the {labels}{where}; "
                    "this is not independent confirmation.")
            extra = [finding.title for finding in origins if finding is not rep
                     and _title_ratio(finding.title, rep.title) < _TITLE_SIMILARITY_THRESHOLD]
            if extra:
                note += " Reported there as: " + "; ".join(sorted(set(extra))) + "."
            rep = replace(rep, explanation=(rep.explanation + note).strip())
        if len(origins) > 1:
            rep = replace(rep, claim_evidence={"version": 1, **(rep.claim_evidence or {}),
                                              "grouped_originals": [_original(item) for item in origins]})
            identity = (rep.claim_evidence or {}).get("source_issue_identity")
            if valid_network_identity(identity, rep.file):
                rep = replace(rep, claim_evidence={**rep.claim_evidence, "grouped_claim_scope": {
                    "mechanism": MECHANISM,
                    "scope": "Same source operation and network-rejection cleanup hypothesis only.",
                    "consequences": "Original conditions and consequences retain their own verification statuses.",
                    "title_source_disagreements": [
                        {"original_index": index, "result": "different_handler_label",
                         "source_handler": identity["handler"]}
                        for index, item in enumerate(origins)
                        if title_label_disagreement(item.title, identity)
                    ],
                }})
        first = min((position, order) for position, order, _ in members)
        out.append((*first, rep))
    return [finding for _, _, finding in sorted(out, key=lambda item: (item[0], item[1]))]
