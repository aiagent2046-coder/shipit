"""Synthetic source fixtures: no uploaded code or live requests are executed.

Two tests here exist because the others can pass while proving nothing:

  * every negative case in the corpus is MUTATED in the single place that
    removes the property it pins, and the rule must fire on the result. A
    negative that stays silent for the wrong reason fails here instead of
    looking like discrimination;
  * the product's own routes are scanned. The rule sees 28 write routes in
    app/ today and must report none of them -- if that ever changes, either
    the product grew the defect or the rule grew a false positive, and both
    are worth a failing build. The count is asserted first, so silence on an
    archive with no write routes cannot masquerade as the test passing.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.auth_write import RULE_ID, scan_auth_write
from app.scan.static import run_static_scan

GUARDED = '''from fastapi import APIRouter, Depends
router = APIRouter()
@router.put("/audits/{audit_id}")
async def update_audit(audit_id, payload, actor=Depends(current_actor), audit_repo=Depends(get_audit_repo)):
    return audit_repo.update(audit_id, payload)
'''

UNGUARDED = '''
@router.post("/audits")
async def create_audit(payload, audit_repo=Depends(get_audit_repo)):
    return audit_repo.create(payload)
'''

REPO_ROOT = Path(__file__).resolve().parent.parent


def archive(files: dict[str, str] | str, path: str = "repo/app/routes.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_unprotected_write_beside_a_guarded_sibling_is_an_unverified_signal():
    source = GUARDED + UNGUARDED
    findings = [f for f in run_static_scan(archive(source))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    # The finding points at the WRITE, not at the top of the file: a route in a
    # 400-line module is otherwise a line the owner has to re-find.
    assert "create(payload)" in source.splitlines()[f["line"] - 1]
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert f["category"] == "Auth"
    assert "public reachability have not been resolved" in f["explanation"]


@pytest.mark.parametrize("source", [
    # both write routes declare an identity: nothing disagrees
    GUARDED + UNGUARDED.replace("payload, audit_repo", "payload, actor=Depends(current_actor), audit_repo"),
    # guarded by a named dependency rather than the sibling's shape
    GUARDED + UNGUARDED.replace("payload, audit_repo", "payload, actor=Depends(require_actor), audit_repo"),
    # guarded by a call in the body
    GUARDED + UNGUARDED.replace("    return audit",
                               "    await require_actor(payload)\n    return audit"),
    # guarded at the route declaration
    GUARDED + UNGUARDED.replace('"/audits")', '"/audits", dependencies=[Depends(require_actor)])'),
    # guarded on the router: the scanner cannot read that list, so it withdraws
    (GUARDED + UNGUARDED).replace("APIRouter()", "APIRouter(dependencies=[Depends(require_actor)])"),
    # the only write route has nothing to disagree with
    UNGUARDED,
    # conventionally public paths are excluded
    GUARDED + UNGUARDED.replace('"/audits")', '"/auth/login")'),
    # a POST that only computes a response is not a write
    GUARDED + UNGUARDED.replace(".create(payload)", ".render(payload)"),
    # an unrecognized second decorator could be the guard
    GUARDED + UNGUARDED.replace('@router.post("/audits")',
                               '@router.post("/audits")\n@limiter.limit("5/minute")'),
    # an imported router is not a router this file builds
    UNGUARDED.replace("router = APIRouter()", "").replace(
        "from fastapi import APIRouter, Depends",
        "from app.routers import router\nfrom fastapi import Depends"),
    "not valid python (",
])
def test_write_routes_without_a_disagreement_are_silent(source):
    assert scan_auth_write(archive(source)) == []


def test_examples_are_excluded_and_no_code_is_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = GUARDED + UNGUARDED + f"\nopen({str(marker)!r}, 'w').write('executed')\n"
    assert scan_auth_write(archive(source, "repo/tests/fixture.py")) == []
    assert scan_auth_write(archive(source))
    assert not marker.exists()


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "both-guarded": ("app/routes.py",
                     "async def create_audit(payload, actor=Depends(current_actor),",
                     "async def create_audit(payload,"),
    "extra-decorator": ("app/routes.py", '@limiter.limit("5/minute")\n', ""),
    "no-guarded-sibling": ("app/routes.py", '@router.get("/audits/{audit_id}")',
                           '@router.put("/audits/{audit_id}")'),
    "no-write-call": ("app/reports.py", "record_repo.render(payload)", "record_repo.update(payload)"),
    "public-path-segment": ("app/auth_routes.py", '@router.post("/auth/login")',
                            '@router.post("/auth/start")'),
    "router-level-dependencies": ("app/routes.py", "APIRouter(dependencies=[Depends(require_actor)])",
                                  "APIRouter()"),
    "separate-factories": ("app/routes.py",
                           '''def build_public_router():
    router = APIRouter()

    @router.post("/audits")''',
                           '''def build_public_router():
    router = APIRouter()

    @router.post("/admin/audits")
    async def create_audit(payload, actor=Depends(require_actor), audit_repo=Depends(get_audit_repo)):
        return audit_repo.create(payload)

    @router.post("/audits")'''),
    # the identity word that also looks like storage: drop it and the route is
    # left with nothing but repository injection
    "auth-word-beats-storage-shape": ("app/routes.py",
                                      "async def create_audit(payload, guard=Depends(get_auth_service),",
                                      "async def create_audit(payload,"),
    # the residual limitation: rename the witness to a name that is NOT
    # storage-shaped and the disagreement becomes visible
    "storage-shaped-witness-only": ("app/data.py", "manager=Depends(resolve_manager)",
                                    "manager=Depends(resolve_actor)"),
    # an unclassifiable name counts as authorization; name it storage and the
    # pair disagrees again
    "unknown-dependency-name": ("app/logs.py", "handler=Depends(handler)",
                                "handler=Depends(fetch_handler_repository)"),
    # SQL is only write evidence when the statement OPENS with a mutation
    "select-statement": ("app/reports.py", '"SELECT * FROM reports',
                         '"INSERT INTO reports'),
    # a scheduler is not storage
    "scheduler-is-not-a-write": ("app/billing.py", "background.add_task(",
                                 "background.add("),
    # conventionally public segment: rename it and the route is ordinary again
    "provider-notification-path": ("app/payments.py", '"/payments/notifications"',
                                   '"/payments/charge"'),
    # an ambiguous tail plus a person noun is not evidence; a repository tail is
    "person-noun-ambiguous-tail": ("app/audits.py", "Depends(get_user_session)",
                                   "Depends(get_user_session_repo)"),
    # the documented limit: an unplaceable verb in front of a security-sounding
    # tail is not read as storage; name it a repository and the pair disagrees
    "unplaceable-storage-verb": ("app/checks.py", "Depends(handle_security)",
                                 "Depends(get_security_repo)"),
}


def test_every_corpus_negative_has_a_mutation():
    """Guards the guard: a negative with no mutation above is only pinned by the
    detector's silence, which is the one thing silence cannot prove."""
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_auth_write(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_auth_write(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_write_routes_report_nothing():
    sources = [p.read_text() for p in (REPO_ROOT / "app").rglob("*.py")]
    write_routes = sum(len(re.findall(r"@\w+\.(?:post|put|patch|delete)\(", source))
                       for source in sources)
    assert write_routes >= 20, (
        f"this test is only meaningful while the product has write routes; found {write_routes}")
    files = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
             for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_auth_write(archive(files)) == []
