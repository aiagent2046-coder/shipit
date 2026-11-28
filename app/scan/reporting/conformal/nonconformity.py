"""Deterministic nonconformity score s(x) in [0, 1] for static and LLM findings.

Lower s(x) means stronger structural evidence and lower false-positive risk;
higher s(x) means weaker or non-production evidence. Kept pure-Python and
dependency-free so server scans, drydock-local, and Pyodide WASM compute
identical scores byte-for-byte.
"""

from __future__ import annotations

from typing import Any

from app.scan.core.secrets import RULES as _SECRET_RULES

NON_PROD_CONTEXTS = frozenset({"test_fixture", "doc_example", "test_file", "comment"})

STRATUM_AST_CFG = "deterministic_ast_cfg"
STRATUM_SECRET = "secret_pattern"
STRATUM_CONFIG = "config_and_schema"
STRATUM_LLM = "llm_rubric"

_KNOWN_SECRET_RULE_IDS = frozenset(r.id for r in _SECRET_RULES)

_CONFIG_RULES = frozenset({
    "env-file-committed",
    "gitignore-missing-secrets",
    "no-dockerfile",
    "ci-deploys-a-different-repository",
    "supabase-rls-disabled",
    "supabase-rls-write-policy-missing",
    "supabase-schema-drift",
})


def producer_stratum(
    *,
    rule_id: str,
    source: str = "unknown",
    masked: str = "",
) -> str:
    """Assign a finding to its statistical calibration stratum."""
    if source == "llm" or rule_id.startswith("llm-"):
        return STRATUM_LLM
    if (
        masked
        or rule_id in _KNOWN_SECRET_RULE_IDS
        or rule_id.endswith(("-key", "-token", "-secret", "-pat", "-webhook", "-block"))
    ):
        return STRATUM_SECRET
    if rule_id in _CONFIG_RULES:
        return STRATUM_CONFIG
    return STRATUM_AST_CFG


def _structural_evidence_bonus(
    claim_evidence: dict[str, Any] | None,
    verification_status: str,
) -> float:
    """Reward independently verified or graph-proven structural witnesses."""
    bonus = 0.0
    if verification_status == "verified":
        bonus += 0.06
    if not isinstance(claim_evidence, dict):
        return bonus
    src_type = claim_evidence.get("source_type")
    if src_type == "static_cfg_dominator" and claim_evidence.get("optimal_cut_lines"):
        bonus += 0.05
    if src_type == "static_interproc_taint_summary" and claim_evidence.get("call_chain"):
        bonus += 0.05
    sql_obs = claim_evidence.get("sql_observation")
    if isinstance(sql_obs, dict) and sql_obs.get("driver_status") == "source_resolved":
        bonus += 0.05
    if isinstance(claim_evidence.get("deserialization_observation"), dict):
        bonus += 0.04
    return min(0.10, bonus)


def compute_nonconformity_score(
    *,
    confidence: float,
    context: str | None = None,
    source: str = "unknown",
    verification_status: str = "unverified",
    claim_evidence: dict[str, Any] | None = None,
) -> float:
    """Compute bounded nonconformity s(x) in [0.0, 1.0]."""
    clamped_conf = max(0.0, min(1.0, float(confidence)))
    base = 1.0 - clamped_conf
    if context in NON_PROD_CONTEXTS:
        base += 0.35
    if source == "llm" and verification_status != "verified":
        base += 0.12
    base -= _structural_evidence_bonus(claim_evidence, verification_status)
    return round(max(0.0, min(1.0, base)), 6)


def finding_nonconformity(finding: Any) -> float:
    """Accept either a ScoredFinding dataclass or a serialized finding dict."""
    if isinstance(finding, dict):
        return compute_nonconformity_score(
            confidence=float(finding.get("confidence", 0.5)),
            context=finding.get("context"),
            source=str(finding.get("source", "unknown")),
            verification_status=str(finding.get("verification_status", "unverified")),
            claim_evidence=finding.get("claim_evidence"),
        )
    return compute_nonconformity_score(
        confidence=float(getattr(finding, "confidence", 0.5)),
        context=getattr(finding, "context", None),
        source=str(getattr(finding, "source", "unknown")),
        verification_status=str(getattr(finding, "verification_status", "unverified")),
        claim_evidence=getattr(finding, "claim_evidence", None),
    )


def finding_stratum(finding: Any) -> str:
    """Determine calibration stratum for either ScoredFinding or dict."""
    if isinstance(finding, dict):
        return producer_stratum(
            rule_id=str(finding.get("rule_id", "")),
            source=str(finding.get("source", "unknown")),
            masked=str(finding.get("masked", "")),
        )
    return producer_stratum(
        rule_id=str(getattr(finding, "rule_id", "")),
        source=str(getattr(finding, "source", "unknown")),
        masked=str(getattr(finding, "masked", "")),
    )
