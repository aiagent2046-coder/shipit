"""Integration tests for CRC stratification in scoring and Fix Pack gates."""

from __future__ import annotations

import io
import zipfile

from app.pipeline.fixpack.conformal_gate import (
    CONFORMAL_SKIP_REASON,
    passes_conformal_fixpack_gate,
)
from app.pipeline.fixpack.generate import (
    build_fixpack_plan,
    has_auto_fixable_findings,
    mark_unfixable_findings,
)
from app.scan.reporting.conformal.strata_thresholds import (
    ZONE_AUTO_FIX,
    ZONE_DAMPED_ADVISORY,
    ZONE_HUMAN_REVIEW,
)
from app.scan.reporting.scoring import ScoredFinding, compute_conformal_summary


def _minimal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", "# demo\n")
    return buf.getvalue()


def test_compute_conformal_summary_emits_three_zones() -> None:
    findings = [
        ScoredFinding(
            rule_id="python-cfg-partial-guard-bypass",
            title="Bypass",
            severity="high",
            confidence=0.85,
            category="Auth",
            source="static",
            claim_evidence={"source_type": "static_cfg_dominator", "optimal_cut_lines": [9]},
        ),
        ScoredFinding(
            rule_id="llm-auth-missing-check",
            title="Model review note",
            severity="medium",
            confidence=0.80,
            category="Auth",
            source="llm",
        ),
        ScoredFinding(
            rule_id="stripe-live-key",
            title="Fixture key",
            severity="medium",
            confidence=0.60,
            category="Security",
            context="test_fixture",
            masked="sk_live_****",
            source="static",
        ),
    ]
    crc = compute_conformal_summary(findings)
    assert crc["zones"][ZONE_AUTO_FIX] == 1
    assert crc["zones"][ZONE_HUMAN_REVIEW] == 1
    assert crc["zones"][ZONE_DAMPED_ADVISORY] == 1


def test_low_confidence_fixable_rule_is_blocked_across_all_three_fixpack_seams() -> None:
    low_conf_finding = {
        "rule_id": "gitignore-missing-secrets",
        "title": ".gitignore does not cover .env",
        "severity": "low",
        "confidence": 0.42,  # nonconformity = 0.58 in (lambda_fix=0.50, lambda_review=0.65]
        "category": "Security",
        "file": ".gitignore",
        "line": 1,
        "source": "static",
    }
    assert passes_conformal_fixpack_gate(low_conf_finding) is False
    assert has_auto_fixable_findings([low_conf_finding]) is False

    zip_bytes = _minimal_zip()
    stamped = mark_unfixable_findings(zip_bytes, [low_conf_finding])
    assert stamped[0]["fixpack_eligible"] is False
    assert stamped[0]["conformal_gate"]["zone"] == ZONE_HUMAN_REVIEW

    plan = build_fixpack_plan(zip_bytes, [low_conf_finding])
    assert plan.files == {}
    assert len(plan.skipped) == 1
    assert plan.skipped[0].reason == CONFORMAL_SKIP_REASON


def test_canonical_secret_and_legacy_findings_remain_auto_fix_eligible() -> None:
    generic_secret = {
        "rule_id": "generic-assignment",
        "title": "Hardcoded credential assignment",
        "severity": "high",
        "confidence": 0.50,
        "category": "Security",
        "file": "config.py",
        "line": 1,
        "source": "static",
    }
    legacy_without_conf = {
        "rule_id": "gitignore-missing-secrets",
        "title": ".gitignore does not cover .env",
        "severity": "medium",
        "category": "Security",
        "file": ".gitignore",
        "line": 1,
    }
    assert passes_conformal_fixpack_gate(generic_secret) is True
    assert passes_conformal_fixpack_gate(legacy_without_conf) is True
    assert has_auto_fixable_findings([generic_secret]) is True
    assert has_auto_fixable_findings([legacy_without_conf]) is True
