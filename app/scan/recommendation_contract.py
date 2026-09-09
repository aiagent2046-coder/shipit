"""Compose scanner-owned recommendation prerequisites without losing originals."""
from copy import deepcopy
from dataclasses import replace

from app.scan.claim_evidence import static_claim_evidence


def recommendation_record(finding):
    evidence = finding.claim_evidence if isinstance(finding.claim_evidence, dict) else {}
    record = evidence.get("recommendation_check")
    return record if isinstance(record, dict) else {}


def list_field(record, key):
    value = record.get(key)
    return value if isinstance(value, list) else []


def has_recommendation_check(finding, kind):
    return any(check.get("kind") == kind and check.get("version") == 1
               for check in list_field(recommendation_record(finding), "checks") if isinstance(check, dict))


def require_prerequisites(finding, hint, checks, *, contexts=()):
    """Replace active advice, preserving the earliest original and earlier checks.

    The caller composes the active conditional advice. Earlier wording omitted
    from that advice stays explicitly superseded, never an alternative fix.
    """
    existing_evidence = finding.claim_evidence if isinstance(finding.claim_evidence, dict) else {}
    evidence = deepcopy(existing_evidence or static_claim_evidence())
    if not existing_evidence and finding.source != "static":
        evidence["source_check"] = {"kind": "not_recorded"}
    if finding.claim_evidence is not None and not isinstance(finding.claim_evidence, dict):
        evidence["legacy_claim_evidence"] = deepcopy(finding.claim_evidence)
    previous = deepcopy(recommendation_record(finding))
    original = previous.get("original_fix_hint", finding.fix_hint)
    detail = previous.get("detail") if isinstance(previous.get("detail"), str) else ""
    for check in checks:
        if check["detail"] not in detail:
            detail = " ".join(part for part in (detail, check["detail"]) if part)
    superseded = list(list_field(previous, "superseded_fix_hints"))
    if (finding.fix_hint != original and finding.fix_hint not in hint
            and finding.fix_hint not in superseded):
        superseded.append(finding.fix_hint)
    provenance = previous.get("original_provenance")
    if not isinstance(provenance, dict):
        provenance = {
            "source": finding.source, "verification_method": finding.verification_method,
            "verification_status": finding.verification_status,
            **({"producer": deepcopy(evidence["producer"])} if evidence.get("producer") else {}),
        }
    existing_contexts = list_field(evidence, "context_checks")
    existing_contexts.extend(c for c in contexts if c not in existing_contexts)
    evidence["context_checks"] = existing_contexts
    old_checks = list_field(previous, "checks")
    kinds = {check["kind"] for check in checks}
    # Preserve unknown fields/check kinds as evidence. Only fresh known
    # templates determine active advice; a marker never certifies old prose.
    merged = [c for c in old_checks if not (isinstance(c, dict) and c.get("version") == 1
              and isinstance(c.get("kind"), str) and c["kind"] in kinds)]
    for check in checks:
        old = next((c for c in old_checks if isinstance(c, dict) and c.get("version") == 1
                    and c.get("kind") == check["kind"]), {})
        merged.append({**old, **check, "version": 1, "result": "prerequisites_required"})
    evidence["recommendation_check"] = {
        **previous, "result": "prerequisites_required", "original_fix_hint": original,
        "original_status": "superseded", "original_provenance": provenance, "detail": detail,
        "checks": merged,
        **({"superseded_fix_hints": superseded} if superseded else {}),
    }
    updated = replace(finding, fix_hint=hint, claim_evidence=evidence)
    return finding if updated == finding else updated
