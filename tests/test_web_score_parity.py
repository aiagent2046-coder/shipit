"""The result page and demo must use the same evidence presentation as HTML.

Behaviour is exercised by test_report.py and AuditCoverage.test.tsx. These
wiring checks prevent the page from accidentally reintroducing a score widget.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_result_and_demo_use_evidence_coverage_and_no_readiness_widget():
    for path in ("web/src/app/audit/[id]/page.tsx", "web/src/components/DemoReport.tsx"):
        text = (ROOT / path).read_text()
        assert "<AuditCoverage" in text
        assert "<ScoreRing" not in text
        assert "<CategoryBars" not in text
        assert "findings={" in text


def test_wire_type_includes_every_scan_basis():
    from app.scan.pipeline import BASIS_FULL, BASIS_PARTIAL, BASIS_PREVIEW, BASIS_STATIC_ONLY

    text = (ROOT / "web/src/lib/types.ts").read_text()
    for basis in (BASIS_FULL, BASIS_PARTIAL, BASIS_PREVIEW, BASIS_STATIC_ONLY):
        assert f'"{basis}"' in text
