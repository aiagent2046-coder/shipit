"""The one Frontend check with a static producer: an app with no error
boundary above its routes turns any render error into a white page.

Beyond the positives/negatives, these tests pin the COVERAGE contract:
'no finding' is only meaningful when the scan finished. A budget-exhausted
scan must say so, and callers must not be able to read it as a clean bill
(issue #392).
"""

from __future__ import annotations

from app.scan.error_boundary import (
    COVERAGE_COMPLETE,
    MOUNT_NOT_REACT,
    scan_error_boundary,
)

from .conftest import NEXTJS_PACKAGE, make_zip


def _nextjs(extra: dict[str, str]) -> dict[str, str]:
    files = {
        "package.json": NEXTJS_PACKAGE,
        "app/layout.tsx": "export default function L({children}) { return <html>{children}</html> }",
        "app/page.tsx": "export default function P() { return <div/> }",
    }
    files.update(extra)
    return files


def test_nextjs_without_boundary_is_flagged():
    scan = scan_error_boundary(make_zip(_nextjs({})))
    assert [f.rule_id for f in scan.findings] == ["missing-error-boundary"]
    assert scan.findings[0].category == "Frontend"
    assert scan.mount != MOUNT_NOT_REACT
    assert scan.coverage == COVERAGE_COMPLETE


def test_root_error_tsx_is_recognised_by_the_presence_check():
    scan = scan_error_boundary(make_zip(_nextjs({
        "app/error.tsx": "'use client'\nexport default function E(){return <div/>}",
    })))
    assert scan.findings == []


def test_global_error_tsx_is_recognised_by_the_presence_check():
    scan = scan_error_boundary(make_zip(_nextjs({
        "app/global-error.tsx": "'use client'\nexport default function E(){return <html><body>Error</body></html>}",
    })))
    assert scan.findings == []


def test_boundary_buried_in_a_route_segment_does_not_cover_the_root():
    """Tightened 2026-09-04: only a ROOT-level boundary silences the rule --
    a nested error.tsx leaves the routes above it unprotected."""
    scan = scan_error_boundary(make_zip(_nextjs({
        "app/dashboard/error.tsx": "'use client'\nexport default function E(){return <div/>}",
    })))
    assert [f.rule_id for f in scan.findings] == ["missing-error-boundary"]


def test_non_react_repository_is_out_of_scope_not_clean():
    scan = scan_error_boundary(make_zip({
        "main.py": "print('hello')",
        "requirements.txt": "fastapi\n",
    }))
    assert scan.findings == []
    assert scan.mount == MOUNT_NOT_REACT  # 'not applicable', not 'passed'


def test_scan_reports_what_it_actually_read():
    """The coverage contract: the result object always carries coverage,
    mount and the read counts, so a report can distinguish 'clean' from
    'stopped early'."""
    scan = scan_error_boundary(make_zip(_nextjs({})))
    assert scan.coverage in ("complete", "budget_exhausted")
    assert scan.files_total > 0
    assert scan.files_read <= scan.files_total
