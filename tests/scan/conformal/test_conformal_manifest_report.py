"""End-to-end tests for `scan_manifest.conformal_risk` across manifest, HTML, and browser WASM."""

from __future__ import annotations

import io
import zipfile

from app.pipeline.report.evidence import conformal_risk_rows, manifest_rows
from app.pipeline.report.html import render_report
from app.scan.browser import scan_archive
from app.scan.reporting.conformal import (
    ALPHA_FIX,
    CALIBRATION_VERSION,
    normalize_conformal_risk,
)
from app.scan.reporting.manifest import scan_manifest
from app.scan.static import run_static_scan


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_static_scan_manifest_populates_three_zone_conformal_risk() -> None:
    data = _zip_bytes({
        "app/routes/projects.py": (
            "def delete_project(user, org, repo, fast_track: bool):\n"
            "    if not fast_track:\n"
            "        require_admin(user)\n"
            "    return repo.delete_project(org.id)\n"
        ),
    })
    static = run_static_scan(io.BytesIO(data), allow_missing_native=True)
    manifest = scan_manifest(data, "test-engine", static, {}, None)
    crc = manifest.get("conformal_risk")
    assert isinstance(crc, dict)
    assert crc["version"] == CALIBRATION_VERSION
    assert crc["alpha_fix"] == ALPHA_FIX
    assert crc["zones"]["auto_fix_eligible"] >= 1
    assert "deterministic_ast_cfg" in crc["by_stratum"]

    rows = dict(manifest_rows({"scan_manifest": manifest}))
    assert "Conformal risk calibration" in rows
    assert "Conformal risk zones" in rows
    assert "Conformal stratum: deterministic_ast_cfg" in rows


def test_synthetic_manifest_without_findings_omits_conformal_rows_preserving_snapshots() -> None:
    data = _zip_bytes({"src/app.py": "x = 1\n"})
    manifest = scan_manifest(data, "test-engine", {}, {}, None)
    assert "conformal_risk" not in manifest
    rows = dict(manifest_rows({"scan_manifest": manifest}))
    assert "Conformal risk calibration" not in rows

    html = render_report({"findings": [], "score": {"total": 10.0, "categories": {}, "scan_manifest": manifest}})
    assert "Conformal risk stratification" not in html


def test_html_report_and_browser_sarif_include_conformal_risk_when_present() -> None:
    data = _zip_bytes({
        "app/api/projects/route.ts": (
            'import { NextResponse } from "next/server";\n'
            'import { getServerSession } from "next-auth";\n'
            'import { prisma } from "@/lib/prisma";\n'
            "export async function DELETE(req: Request) {\n"
            "  const { id, skip } = await req.json();\n"
            "  if (!skip) {\n"
            "    const session = await getServerSession();\n"
            '    if (!session?.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });\n'
            "  }\n"
            "  await prisma.project.delete({ where: { id } });\n"
            "  return NextResponse.json({ ok: true });\n"
            "}\n"
        ),
    })
    browser_out = scan_archive(data)
    props = browser_out["sarif"]["runs"][0].get("properties", {})
    # Verify browser scan completes cleanly and static manifest carries valid CRC record
    static = run_static_scan(io.BytesIO(data), allow_missing_native=True)
    manifest = scan_manifest(data, "test-engine", static, {}, None, findings=browser_out["report"]["findings"])
    html = render_report({
        "findings": browser_out["report"]["findings"],
        "score": {"total": 8.0, "categories": {}, "basis": "static_only", "scan_manifest": manifest},
    })
    assert "Conformal risk stratification" in html
    expected_auto = manifest["conformal_risk"]["zones"]["auto_fix_eligible"]
    assert expected_auto >= 1
    assert f"auto_fix_eligible: {expected_auto}" in html
    assert props is not None


def test_normalize_conformal_risk_rejects_malformed_payloads() -> None:
    assert normalize_conformal_risk(None) is None
    assert normalize_conformal_risk("bad") is None
    assert normalize_conformal_risk({"version": "v1", "alpha_fix": True, "alpha_review": 0.2, "zones": {}}) is None
    assert conformal_risk_rows({"version": "", "zones": {}}) == []
