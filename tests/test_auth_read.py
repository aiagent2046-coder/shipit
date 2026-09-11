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


GUARDED_COLLECTION = '''from fastapi import APIRouter, Depends
repo = Repository()
router = APIRouter()
@router.get("/notes")
def list_notes(actor=Depends(current_actor)):
    return repo.list()
'''
OPEN_ITEM = '''
@router.get("/notes/{note_id}")
def get_note(note_id):
    return repo.get(note_id)
'''


@pytest.mark.parametrize("read", ["repo.list()", "repo.get(note_id)"])
def test_dependency_guarded_read_supplies_a_same_binding_witness(read):
    source = GUARDED_COLLECTION.replace("list_notes(actor", "list_notes(note_id, actor").replace("repo.list()", read)
    source += OPEN_ITEM
    hits = scan_auth_read(archive(source))
    assert len(hits) == 1
    assert "return repo.get(note_id)" in source.splitlines()[hits[0].line - 1]
    assert "declares an identity dependency" in hits[0].explanation
    assert "same repository binding" in hits[0].explanation
    assert "get_authorized" not in hits[0].explanation
    fixed = source.replace("get_note(note_id)", "get_note(note_id, actor=Depends(current_actor))")
    assert scan_auth_read(archive(fixed)) == []


@pytest.mark.parametrize("dependency", ["Depends as Inject", "Security as Inject"])
def test_read_witness_uses_fastapi_dependency_aliases(dependency):
    source = "from fastapi import " + dependency + "\n" + GUARDED_COLLECTION.replace(
        "Depends(current_actor)", "Inject(current_actor)") + OPEN_ITEM
    assert len(scan_auth_read(archive(source))) == 1


@pytest.mark.parametrize("mutation", [
    ("return repo.list()", "return other_repo.list()"),
    ("return repo.list()", "return render_notes()"),
    ("return repo.list()", "def unused():\n        return repo.list()\n    return []"),
    ("actor=Depends(current_actor)", "actor=Depends(handler)"),
    ("actor=Depends(current_actor)", "actor=Depends(get_storage_repo)"),
    ("return repo.list()", "return repo.render()"),
])
def test_identity_guard_needs_a_visible_read_of_the_same_repository(mutation):
    old, new = mutation
    source = GUARDED_COLLECTION.replace(old, new) + OPEN_ITEM
    assert scan_auth_read(archive(source)) == []
    assert len(scan_auth_read(archive(source.replace(new, old, 1)))) == 1


def test_body_guard_on_an_unrelated_object_does_not_supply_the_new_read_witness():
    source = GUARDED_COLLECTION.replace("actor=Depends(current_actor)", "").replace(
        "    return repo.list()", "    require_owner(other_id)\n    return repo.list()") + OPEN_ITEM
    assert scan_auth_read(archive(source)) == []


@pytest.mark.parametrize("separation", [
    "other = APIRouter()\n",
    "other = imported_router\n",
])
def test_dependency_read_witness_does_not_cross_routers(separation):
    source = GUARDED_COLLECTION + separation + OPEN_ITEM.replace("@router.", "@other.")
    assert scan_auth_read(archive(source)) == []


# The provenance boundary the block-declaration fix deliberately does NOT cross: an
# import written inside a block establishes no dependency provenance. Measured on
# twelve pinned public FastAPI projects (569 Python files; the measurement ships as
# scripts/measure_route_block_impact.py in the block-declaration change): the only
# occurrences were `if TYPE_CHECKING: from fastapi import ...` -- typing-only,
# binding nothing at run time -- and one docs generator's try/except. Reading those
# as runtime bindings would invent provenance and accuse a caller-filled value on it.
CONDITIONAL_IMPORTS = {
    "type-checking-only": ("from typing import TYPE_CHECKING\n"
                           "if TYPE_CHECKING:\n"
                           "    from fastapi import APIRouter, Depends\n"),
    "runtime-fallback": ("try:\n"
                         "    from fastapi import APIRouter, Depends\n"
                         "except ImportError:\n"
                         "    APIRouter = None\n"
                         "    Depends = None\n"),
}


@pytest.mark.parametrize("shape", sorted(CONDITIONAL_IMPORTS))
def test_a_conditional_import_establishes_no_dependency_provenance(shape):
    body = "\n".join(line for line in (GUARDED_COLLECTION + OPEN_ITEM).strip().splitlines()
                     if not line.startswith("from fastapi"))
    assert scan_auth_read(archive(CONDITIONAL_IMPORTS[shape] + body + "\n")) == []
    # the one change that removes the property: the same import, written directly
    assert len(scan_auth_read(archive("from fastapi import APIRouter, Depends\n" + body + "\n"))) == 1


@pytest.mark.parametrize("target", [
    OPEN_ITEM.replace("get_note(note_id)", "get_note(note_id, repo)"),
    OPEN_ITEM.replace("return repo.get", "repo = PublicRepository()\n    return repo.get"),
    OPEN_ITEM.replace("return repo.get", "for repo in repositories:\n        return repo.get"),
    "repo = PublicRepository()\n" + OPEN_ITEM,
    "from other_storage import repo\n" + OPEN_ITEM,
])
def test_same_name_on_a_different_repository_binding_is_not_a_read_disagreement(target):
    assert scan_auth_read(archive(GUARDED_COLLECTION + target)) == []
    assert len(scan_auth_read(archive(GUARDED_COLLECTION + OPEN_ITEM))) == 1


def test_dependency_repository_identity_is_the_provider_not_the_parameter_spelling():
    source = GUARDED_COLLECTION.replace("repo = Repository()\n", "").replace(
        "actor=Depends(current_actor)", "actor=Depends(current_actor), storage=Depends(fetch_notes_repository)")
    source = source.replace("repo.list()", "storage.list()")
    source += OPEN_ITEM.replace("get_note(note_id)", "get_note(note_id, repo=Depends(fetch_notes_repository))")
    assert len(scan_auth_read(archive(source))) == 1
    assert scan_auth_read(archive(source.replace("repo=Depends(fetch_notes_repository)",
                                                "repo=Depends(fetch_public_repository)"))) == []


def test_rebound_repository_provider_cannot_supply_a_same_binding_witness():
    source = "from storage import fetch_notes_repository\n" + GUARDED_COLLECTION.replace(
        "actor=Depends(current_actor)", "actor=Depends(current_actor), repo=Depends(fetch_notes_repository)")
    source += "\nfetch_notes_repository = another_provider\n" + OPEN_ITEM.replace(
        "get_note(note_id)", "get_note(note_id, repo=Depends(fetch_notes_repository))")
    assert scan_auth_read(archive(source)) == []
    assert len(scan_auth_read(archive(source.replace("fetch_notes_repository = another_provider\n", "")))) == 1


def test_dependency_guarded_reads_inside_router_factories_remain_comparable():
    body = (GUARDED_COLLECTION + OPEN_ITEM).split("\n", 1)[1]
    source = "from fastapi import APIRouter, Depends\ndef create_router():\n" + "\n".join(
        "    " + line for line in body.splitlines())
    assert len(scan_auth_read(archive(source))) == 1


def test_old_protected_lookup_also_requires_the_same_repository_provider():
    source = PREFIX + UNPROTECTED.replace("Depends(get_audit_repo)", "Depends(get_public_repo)")
    assert scan_auth_read(archive(source)) == []
    assert len(scan_auth_read(archive(PREFIX + UNPROTECTED))) == 1
