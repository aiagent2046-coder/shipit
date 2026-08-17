"""Unit tests for Proof-of-Exploit scaffold (no docker).

Stripe-shaped values are assembled at runtime so the source tree never
contains a literal that GitHub secret scanning (or our own scanner on
this repo) would flag as a committed credential.
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
    assert meta["sqli"]["implemented"] is False
    assert meta["cors_open"]["implemented"] is False


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
    assert report.informational is True
    assert report.before.success is True
    assert report.after.success is False


def test_proof_pair_not_verified_when_secret_remains() -> None:
    original = _zip_with({
        "cfg.py": f'STRIPE = "{_FAKE_STRIPE}"\n',
    })
    report = run_proof_pair("secrets_leak", original, original)
    assert report.verified is False
    assert report.before.success is True
    assert report.after.success is True


def test_stubs_skip() -> None:
    empty = _zip_with({"README.md": "x\n"})
    for tid in ("sqli", "cors_open"):
        attempt = get_template(tid)(empty)
        assert attempt.status == "skipped"
        assert attempt.success is False


def test_skipped_pair_is_not_verified() -> None:
    empty = _zip_with({"README.md": "x\n"})
    report = run_proof_pair("sqli", empty, empty)
    assert report.verified is False
    assert report.before.status == "skipped"


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


def test_render_contains_verdict_and_informational_note() -> None:
    original = _zip_with({
        "cfg.py": f'STRIPE = "{_FAKE_STRIPE}"\n',
    })
    patched = _zip_with({"cfg.py": "STRIPE = os.environ['STRIPE']\n"})
    report = run_proof_pair("secrets_leak", original, patched)
    md = render_proof_markdown(report)
    assert "Proof-of-Exploit" in md
    assert "верифицирован" in md
    assert "Informational only" in md
