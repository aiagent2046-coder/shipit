"""Unit tests for the secrets_leak proof template and shared registry.

Uses synthetic zip workspaces. Stripe keys are assembled at runtime so this
file never holds a literal sk_live_… pattern that secret scanning would flag
as a committed credential.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from app.proof.compare import build_proof_report, run_proof_pair
from app.proof.registry import TEMPLATE_IDS, get_template, list_templates
from app.proof.render import render_proof_markdown
from app.proof.types import (
    ExploitAttempt,
    proof_report_from_json,
    proof_report_to_json,
)

# Matches app.scan.secrets stripe-live-key rule without a literal sk_live_…
# in this file. 24+ alnum after the prefix is required by the rule.
_FAKE_STRIPE = "sk_" + "live_" + ("A" * 24)


def _zip_with(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


def test_registry_lists_three_templates() -> None:
    assert TEMPLATE_IDS == ("secrets_leak", "sqli", "cors_open")
    meta = {row["id"]: row for row in list_templates()}
    assert meta["secrets_leak"]["implemented"] is True
    assert meta["sqli"]["implemented"] is True
    assert meta["cors_open"]["implemented"] is True


def test_unknown_template_raises() -> None:
    with pytest.raises(KeyError, match="unknown proof template"):
        get_template("not_a_real_template")


def test_secrets_leak_detects_stripe_key() -> None:
    original = _zip_with({
        "app/api/checkout/route.ts": f'const key = "{_FAKE_STRIPE}";\n',
    })
    attempt = get_template("secrets_leak")(original)
    assert attempt.status == "success"
    assert attempt.success is True
    assert attempt.evidence["finding_count"] >= 1
    sample = attempt.evidence["samples"][0]
    assert sample["masked"].startswith("sk_l")
    assert _FAKE_STRIPE not in sample["masked"]


def test_secrets_leak_clean_workspace() -> None:
    clean = _zip_with({
        "app/main.py": "print('hello')\n",
    })
    attempt = get_template("secrets_leak")(clean)
    assert attempt.status == "failure"
    assert attempt.success is False
    assert attempt.evidence["finding_count"] == 0


def test_proof_pair_verified_when_secret_removed() -> None:
    original = _zip_with({
        "cfg.py": f'STRIPE = "{_FAKE_STRIPE}"\n',
    })
    patched = _zip_with({
        "cfg.py": 'STRIPE = os.environ["STRIPE_SECRET_KEY"]\n',
    })
    report = run_proof_pair("secrets_leak", original, patched)
    assert report.verified is True
    assert report.before.success is True
    assert report.after.success is False
    assert report.template_id == "secrets_leak"


def test_proof_pair_not_verified_when_secret_remains() -> None:
    original = _zip_with({
        "cfg.py": f'STRIPE = "{_FAKE_STRIPE}"\n',
    })
    report = run_proof_pair("secrets_leak", original, original)
    assert report.verified is False
    assert report.before.success is True
    assert report.after.success is True


def test_static_templates_fail_clean_on_empty() -> None:
    """Implemented static templates report failure (not skipped) on a clean zip."""
    empty = _zip_with({"README.md": "x\n"})
    for tid in ("sqli", "cors_open"):
        attempt = get_template(tid)(empty)
        assert attempt.status == "failure"
        assert attempt.success is False


def test_clean_pair_is_not_verified() -> None:
    empty = _zip_with({"README.md": "x\n"})
    report = run_proof_pair("sqli", empty, empty)
    assert report.verified is False
    assert report.before.status == "failure"
    assert report.after.status == "failure"


def test_json_roundtrip() -> None:
    before = ExploitAttempt(
        template_id="secrets_leak",
        status="success",
        success=True,
        detail="found 1",
        evidence={"finding_count": 1, "samples": []},
        duration_ms=3,
    )
    after = ExploitAttempt(
        template_id="secrets_leak",
        status="failure",
        success=False,
        detail="none",
        evidence={"finding_count": 0, "samples": []},
        duration_ms=2,
    )
    report = build_proof_report(before, after)
    restored = proof_report_from_json(proof_report_to_json(report))
    assert restored == report


def test_render_contains_verdict() -> None:
    before = ExploitAttempt(
        template_id="secrets_leak",
        status="success",
        success=True,
        detail="found 1",
        evidence={
            "finding_count": 1,
            "samples": [{
                "file": "cfg.py", "line": 1,
                "rule_id": "stripe-live-key",
                "severity": "critical",
                "masked": "sk_l****(32 chars)",
            }],
        },
    )
    after = ExploitAttempt(
        template_id="secrets_leak",
        status="failure",
        success=False,
        detail="none",
        evidence={"finding_count": 0, "samples": []},
    )
    report = build_proof_report(before, after, informational=False)
    md = render_proof_markdown(report)
    assert "Проверка «до / после»" in md
    assert "secrets_leak" in md
    assert "подтверждён" in md


def test_a_verified_report_does_not_claim_an_attack_was_executed():
    """The section a customer reads may not say the exploit ran.

    All three templates are static scanners -- secrets_leak re-runs
    app.scan.secrets, sqli and cors_open match regexes -- and nothing in
    app/proof/ opens a socket or starts a container. The verified verdict
    used to read "атака сработала до патча и не сработала после": close
    enough on a leaked key, unsupportable on a regex hit, and on a false
    positive it told a customer their app had been exploited.

    Anchored on the strongest wording (the verified branch), because that is
    the one that overclaims, plus the method note that keeps the section
    honest when only the table is read.
    """
    before = ExploitAttempt(
        template_id="sqli", status="success", success=True,
        detail="found 1 likely SQL injection sink(s)",
        evidence={"finding_count": 1, "samples": []},
    )
    after = ExploitAttempt(
        template_id="sqli", status="failure", success=False,
        detail="no high-confidence SQL injection sinks found",
        evidence={"finding_count": 0, "samples": []},
    )
    md = render_proof_markdown(
        build_proof_report(before, after, informational=False))

    assert "Атака не выполняется" in md
    assert "статическая" in md
    # No wording anywhere in the section may assert a executed attack.
    for banned in ("атака сработала", "эксплойт всё ещё срабатывает",
                   "атака всё ещё"):
        assert banned not in md, banned
