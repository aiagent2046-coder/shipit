"""Synthetic source fixtures: no uploaded code or live requests are executed."""
import io
import zipfile
from pathlib import Path

import pytest

from app.scan.auth_read import RULE_ID, scan_auth_read
from app.scan.static import run_static_scan

PREFIX = '''from fastapi import APIRouter, Depends
router = APIRouter()
@router.get("/audits/{audit_id}")
async def detail(audit_id, token, audit_repo=Depends(get_audit_repo)):
    return await audit_repo.get_authorized(audit_id, token)
'''
UNPROTECTED = '''
@router.get("/audits/{audit_id}/status")
async def status(audit_id, audit_repo=Depends(get_audit_repo)):
    return await audit_repo.get(audit_id)
'''


def archive(source, path="repo/app/reads.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(path, source)
    buf.seek(0)
    return buf


def test_local_ownership_mismatch_is_an_unverified_static_signal():
    source = PREFIX + UNPROTECTED
    result = run_static_scan(archive(source))
    findings = [f for f in result["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "get(audit_id)" in source.splitlines()[f["line"] - 1]
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "public reachability have not been resolved" in f["explanation"]


@pytest.mark.parametrize("source", [
    PREFIX + UNPROTECTED.replace(".get(audit_id)", ".get_authorized(audit_id, token)"),
    PREFIX + UNPROTECTED.replace("return await", "await require_owner(audit_id)\n    return await"),
    PREFIX + UNPROTECTED.replace("Depends(get_audit_repo)", "Depends(require_owner)"),
    PREFIX + UNPROTECTED.replace('status")', 'status", dependencies=[Depends(require_owner)])'),
    (PREFIX + UNPROTECTED).replace("APIRouter()", "APIRouter(dependencies=[Depends(require_owner)])"),
    PREFIX + UNPROTECTED.replace("return await", "await audit_repo.get_authorized(audit_id, token)\n    return await"),
    UNPROTECTED,  # imported/unresolved routers cannot establish this comparison
    "not valid python (",
])
def test_guarded_or_unresolved_routes_do_not_assert_an_auth_gap(source):
    assert scan_auth_read(archive(source)) == []


def test_examples_are_excluded_and_no_code_is_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = PREFIX + UNPROTECTED + f"\nopen({str(marker)!r}, 'w').write('executed')\n"
    assert scan_auth_read(archive(source, "repo/tests/fixture.py")) == []
    assert scan_auth_read(archive(source))
    assert not marker.exists()


def test_current_fixpack_status_uses_the_protected_read():
    source = Path("app/routes/reads.py").read_text()
    assert scan_auth_read(archive(source)) == []
    # Keep protected siblings; undo only the status endpoint fix.
    start = source.index("async def get_fixpack_status(")
    previous = source[:start] + source[start:].replace(
        "audit = await audit_repo.get_authorized(audit_id, token)",
        "audit = await audit_repo.get(audit_id)",
        1,
    )
    hits = scan_auth_read(archive(previous))
    assert any("/fixpack-status" in f.explanation for f in hits)


@pytest.mark.parametrize("assignment,decorator", [
    ("other = APIRouter()", "@other."),
    ("router = APIRouter()", "@router."),
    ("router = imported_router", "@router."),
])
def test_protected_reads_must_belong_to_the_same_router_object(assignment, decorator):
    source = PREFIX + "\n" + assignment + "\n" + UNPROTECTED.replace("@router.", decorator)
    assert scan_auth_read(archive(source)) == []
    assert scan_auth_read(archive(PREFIX + UNPROTECTED))


@pytest.mark.parametrize("dependency", [
    "Depends(dependency=require_owner)", "Depends()", "Depends(dependency=handler)",
    "Security(require_owner)", "Depends(get_auth_service)", "Depends(get_user_session)",
])
def test_shared_dependency_classifier_keeps_guarded_reads_silent(dependency):
    source = PREFIX + UNPROTECTED.replace("audit_id, audit_repo", f"audit_id, actor={dependency}, audit_repo")
    assert scan_auth_read(archive(source)) == []


@pytest.mark.parametrize("dependency", ["fetch_audit_repository", "load_audit_service", "get_db_connection"])
def test_renamed_storage_dependency_does_not_hide_a_read_disagreement(dependency):
    source = (PREFIX + UNPROTECTED).replace("get_audit_repo", dependency)
    assert scan_auth_read(archive(source))


def test_nested_protected_lookup_cannot_supply_a_read_witness():
    source = PREFIX.replace("    return await audit_repo.get_authorized",
                            "    async def unused():\n        return await audit_repo.get_authorized")
    assert scan_auth_read(archive(source + UNPROTECTED)) == []


def test_nested_unprotected_lookup_is_not_handler_read_evidence():
    source = UNPROTECTED.replace("    return await audit_repo.get",
                                 "    async def unused():\n        return await audit_repo.get")
    assert scan_auth_read(archive(PREFIX + source)) == []


def test_nested_guard_does_not_hide_a_read_disagreement():
    source = UNPROTECTED.replace("    return await", "    def unused():\n        require_owner()\n    return await")
    assert scan_auth_read(archive(PREFIX + source))
