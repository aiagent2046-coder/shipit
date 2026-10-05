"""Group identical, source-corrected fact-count interpretations after projection.

This is deliberately narrower than hypothesis deduplication. Existing groups
are left intact: their representative alone cannot establish that every
historical observation has the same corrected interpretation.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
import math

from app.scan.claim_narrative import narrative_projection
from app.scan.scoring import ScoredFinding

MECHANISM = "fact_count_projection"
SCOPE = "Same source path and corrected fact-count interpretation only."
CONSEQUENCES = ("Original conditions and cost claims remain separate and unverified; "
                "repetition is not independent confirmation.")
GROUP_SCOPE = {"mechanism": MECHANISM, "scope": SCOPE, "consequences": CONSEQUENCES}


def _key(finding: dict) -> str | None:
    record = finding.get("claim_evidence")
    if (not isinstance(record, dict) or type(record.get("version")) is not int or record["version"] != 1
            or "source_issue_identity" not in record or record["source_issue_identity"] is not None
            or "grouped_originals" in record or "grouped_claim_scope" in record
            or finding.get("source") != "llm" or finding.get("verification_method") != "model_review"
            or finding.get("verification_status") != "unverified"
            or not str(finding.get("rule_id", "")).startswith("llm-")
            or record.get("conditions_status") != "not_checked"
            or record.get("consequence_status") != "not_checked"):
        return None
    confidence = finding.get("confidence")
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        return None
    conditions = record.get("required_conditions")
    if not isinstance(conditions, list) or any(not isinstance(item, str) for item in conditions):
        return None
    projection = narrative_projection(finding)
    if projection is None or projection["kind"] != "fact_input_count_unbounded":
        return None
    payload = deepcopy(finding)
    payload.pop("confidence", None)
    evidence = payload["claim_evidence"]
    evidence.pop("required_conditions")
    evidence["producer"].pop("response")
    # These differing historical claims remain in each complete original.
    evidence["narrative_projection"].pop("original")
    evidence["narrative_projection"].pop("previous_fix_hint")
    try:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return None


def validated_fact_group(finding: dict) -> bool:
    """Validate the scope against the representative and every saved original."""
    record = finding.get("claim_evidence")
    if not isinstance(record, dict) or record.get("grouped_claim_scope") != GROUP_SCOPE:
        return False
    originals = record.get("grouped_originals")
    if not isinstance(originals, list) or len(originals) < 2:
        return False
    representative = deepcopy(finding)
    evidence = representative["claim_evidence"]
    evidence.pop("grouped_claim_scope")
    evidence.pop("grouped_originals")
    key = _key(representative)
    return (key is not None and representative in originals
            and all(isinstance(item, dict) and _key(item) == key for item in originals))


def group_fact_projections(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Combine eligible singleton rows, retaining all their fields as originals.

    Run after narrative projection. Never flatten or extend an existing group.
    Matching requires all fields to agree except model confidence, response
    number, pending conditions and retained superseded prose.
    """
    groups: dict[str, list[tuple[int, ScoredFinding]]] = {}
    out = []
    for index, finding in enumerate(findings):
        key = _key(asdict(finding))
        if key is None:
            out.append((index, finding))
        else:
            groups.setdefault(key, []).append((index, finding))
    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        originals = [asdict(item) for _, item in members]
        rep = min((item for _, item in members), key=lambda item: (
            -item.confidence, json.dumps(asdict(item), sort_keys=True, ensure_ascii=False)))
        # Do not append provenance to projected prose: consumers validate its
        # exact equality to the deterministic source correction.
        rep = replace(rep, claim_evidence={**deepcopy(rep.claim_evidence),
                      "grouped_originals": originals, "grouped_claim_scope": dict(GROUP_SCOPE)})
        out.append((members[0][0], rep))
    return [item for _, item in sorted(out, key=lambda pair: pair[0])]
