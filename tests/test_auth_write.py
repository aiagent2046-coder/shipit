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


@pytest.mark.parametrize("declaration", [
    "other = APIRouter()",
    "other = APIRouter(dependencies=[Depends(require_actor)])",
    "other = imported_router",
])
def test_different_router_objects_cannot_supply_a_guarded_sibling(declaration):
    source = GUARDED + "\n" + declaration + "\n" + UNGUARDED.replace("@router.", "@other.")
    assert scan_auth_write(archive(source)) == []
    # Removing only the router distinction restores the original disagreement.
    assert scan_auth_write(archive(source.replace("@other.", "@router.")))


@pytest.mark.parametrize("assignment", [
    "router = APIRouter()",
    "router = APIRouter(dependencies=[Depends(require_actor)])",
    "router = imported_router",
])
def test_rebinding_a_router_does_not_reuse_an_old_object_witness(assignment):
    assert scan_auth_write(archive(GUARDED + "\n" + assignment + "\n" + UNGUARDED)) == []


def test_sibling_is_selected_from_the_targets_router():
    second = GUARDED[GUARDED.index("@router.put"):].replace("@router.", "@other.")
    source = GUARDED + "\nother = APIRouter()\n" + second
    source += UNGUARDED.replace("@router.", "@other.")
    hits = scan_auth_write(archive(source))
    assert len(hits) == 1
    second_witness_line = source.index("@other.put")
    line = source[:second_witness_line].count("\n") + 2
    assert f"declares one at line {line}." in hits[0].explanation


@pytest.mark.parametrize("body", [
    "    def unused():\n        return repo.create(payload)\n    return payload",
    "    async def unused():\n        return repo.create(payload)\n    return payload",
    "    class Unused:\n        def write(self):\n            return repo.create(payload)\n    return payload",
    "    unused = lambda: repo.create(payload)\n    return payload",
])
def test_unexecuted_nested_code_is_not_write_evidence(body):
    source = GUARDED + '\n@router.post("/items")\nasync def preview(payload):\n' + body + "\n"
    assert scan_auth_write(archive(source)) == []
    before_return, _ = source.rsplit("    return payload", 1)
    assert scan_auth_write(archive(before_return + "    return repo.create(payload)\n"))


def test_definition_time_default_is_not_a_handler_write():
    source = GUARDED + '\n@router.post("/items")\nasync def preview(payload=create_default()):\n    return payload\n'
    assert scan_auth_write(archive(source)) == []


@pytest.mark.parametrize("dependency", [
    "Depends(dependency=require_actor)",
    "Depends()",
    "Depends(dependency=handler)",
    "Security(require_actor)",
])
def test_uncertain_or_keyword_dependencies_suppress_target_findings(dependency):
    source = GUARDED + UNGUARDED.replace("payload, audit_repo", f"payload, actor={dependency}, audit_repo")
    assert scan_auth_write(archive(source)) == []


@pytest.mark.parametrize("dependency", ["Depends(settings)", "Depends()", "Depends(dependency=handler)"])
def test_unknown_dependencies_cannot_supply_an_identity_witness(dependency):
    source = GUARDED.replace("Depends(current_actor)", dependency) + UNGUARDED
    assert scan_auth_write(archive(source)) == []
    assert scan_auth_write(archive(source.replace(dependency, "Depends(require_actor)", 1)))


def test_keyword_identity_dependency_can_supply_a_witness():
    assert scan_auth_write(archive(GUARDED.replace("Depends(current_actor)",
                                               "Depends(dependency=require_actor)") + UNGUARDED))


def test_unexecuted_nested_guard_cannot_supply_a_sibling_witness():
    source = GUARDED.replace("actor=Depends(current_actor), ", "").replace(
        "    return audit_repo.update", "    def unused():\n        require_actor()\n    return audit_repo.update")
    assert scan_auth_write(archive(source + UNGUARDED)) == []


def test_unexecuted_nested_guard_does_not_hide_a_target_disagreement():
    source = GUARDED + UNGUARDED.replace(
        "    return audit_repo.create", "    def unused():\n        require_actor()\n    return audit_repo.create")
    assert scan_auth_write(archive(source))


@pytest.mark.parametrize("decorator", ['@audit_wrapper\n', '@router.put("/alias")\n'])
def test_handler_with_additional_decorators_is_not_a_sibling_witness(decorator):
    source = GUARDED.replace('@router.put("/audits/{audit_id}")',
                             decorator + '@router.put("/audits/{audit_id}")') + UNGUARDED
    assert scan_auth_write(archive(source)) == []
    assert scan_auth_write(archive(source.replace(decorator, "", 1)))


@pytest.mark.parametrize("shadow", [
    "APIRouter = unknown_constructor\n", "from another_package import APIRouter\n",
])
def test_shadowed_router_constructor_does_not_establish_a_router(shadow):
    source = (GUARDED + UNGUARDED).replace("router = APIRouter()", shadow + "router = APIRouter()")
    assert scan_auth_write(archive(source)) == []
    assert scan_auth_write(archive(source.replace(shadow, "", 1)))


def test_factory_argument_shadowing_the_constructor_stays_unresolved():
    body = (GUARDED + UNGUARDED).split("\n", 1)[1]
    source = "from fastapi import APIRouter, Depends\ndef build_router(APIRouter):\n" + "\n".join(
        "    " + line for line in body.splitlines())
    assert scan_auth_write(archive(source)) == []
    assert scan_auth_write(archive(source.replace("build_router(APIRouter)", "build_router(unused)")))


@pytest.mark.parametrize("imports,dependency", [
    ("from fastapi import Depends as Inject", "Inject(current_actor)"),
    ("from fastapi import Depends as Inject", "Inject(dependency=current_actor)"),
    ("from fastapi import Security as Permit", "Permit(current_actor)"),
    ("import fastapi as api", "api.Depends(current_actor)"),
    ("import fastapi as api", "api.Security(current_actor)"),
])
def test_fastapi_import_aliases_supply_identity_witnesses(imports, dependency):
    source = imports + "\n" + GUARDED.replace("Depends(current_actor)", dependency) + UNGUARDED
    hits = scan_auth_write(archive(source))
    assert len(hits) == 1
    assert "create(payload)" in source.splitlines()[hits[0].line - 1]
    fixed = source.replace("payload, audit_repo", f"payload, actor={dependency}, audit_repo")
    assert scan_auth_write(archive(fixed)) == []


def test_annotated_aliased_security_is_a_signature_guard():
    source = "from typing import Annotated\nfrom fastapi import Security as Permit\n" + GUARDED.replace(
        "actor=Depends(current_actor)", "actor: Annotated[Actor, Permit(current_actor)]") + UNGUARDED
    assert len(scan_auth_write(archive(source))) == 1


@pytest.mark.parametrize("shadow", [
    "Inject = ordinary_factory",
    "from another_package import Depends as Inject",
    "def Inject(value):\n    return value",
    "class Inject:\n    pass",
    "if use_alternative:\n    Inject = ordinary_factory",
    "try:\n    load_configuration()\nexcept Exception as Inject:\n    pass",
])
def test_rebound_dependency_alias_cannot_establish_an_identity_witness(shadow):
    source = "from fastapi import Depends as Inject\n" + shadow + "\n" + GUARDED.replace(
        "Depends(current_actor)", "Inject(current_actor)") + UNGUARDED
    assert scan_auth_write(archive(source)) == []
    assert len(scan_auth_write(archive(source.replace(shadow + "\n", "", 1)))) == 1


@pytest.mark.parametrize("shadow", ["api = ordinary_module", "api.Depends = ordinary_factory"])
def test_rebound_fastapi_module_does_not_establish_an_identity_witness(shadow):
    source = "import fastapi as api\n" + shadow + "\n" + GUARDED.replace(
        "Depends(current_actor)", "api.Depends(current_actor)") + UNGUARDED
    assert scan_auth_write(archive(source)) == []
    assert len(scan_auth_write(archive(source.replace(shadow + "\n", "", 1)))) == 1


@pytest.mark.parametrize("parameter", ["Inject", "**Inject", "*, Inject"])
def test_router_factory_parameter_cannot_inherit_a_dependency_alias(parameter):
    body = (GUARDED + UNGUARDED).split("\n", 1)[1].replace("Depends(current_actor)", "Inject(current_actor)")
    source = "from fastapi import APIRouter, Depends, Depends as Inject\n" + f"def build_router({parameter}):\n"
    source += "\n".join("    " + line for line in body.splitlines())
    assert scan_auth_write(archive(source)) == []
    assert len(scan_auth_write(archive(source.replace(f"build_router({parameter})", "build_router()")))) == 1


def test_unknown_aliased_dependency_still_suppresses_a_target_finding():
    source = "from fastapi import Depends as Inject\n" + GUARDED + UNGUARDED.replace(
        "payload, audit_repo", "payload, guard=Inject(handler), audit_repo")
    assert scan_auth_write(archive(source)) == []
    assert len(scan_auth_write(archive(source.replace("Inject(handler)", "Inject(get_storage_repo)")))) == 1


def test_nested_alias_rebinding_does_not_change_the_enclosing_router_guard():
    source = "from fastapi import Depends as Inject\n" + GUARDED.replace(
        "Depends(current_actor)", "Inject(current_actor)") + UNGUARDED
    source += "\ndef unrelated():\n    Inject = another_factory\n    return Inject\n"
    assert len(scan_auth_write(archive(source))) == 1


def test_imported_fastapi_module_itself_is_not_a_dependency_constructor():
    source = "import fastapi as Inject\n" + GUARDED.replace(
        "Depends(current_actor)", "Inject(current_actor)") + UNGUARDED
    assert scan_auth_write(archive(source)) == []
    actual_dependency = source.replace("import fastapi as Inject", "from fastapi import Depends as Inject")
    assert len(scan_auth_write(archive(actual_dependency))) == 1


@pytest.mark.parametrize("constructor", ["Depends", "Inject"])
def test_constructing_a_dependency_marker_in_the_body_does_not_enforce_it(constructor):
    source = "from fastapi import Depends as Inject\n" + GUARDED.replace(
        "actor=Depends(current_actor), ", "").replace(
            "    return audit_repo.update", f"    marker = {constructor}(current_actor)\n    return audit_repo.update")
    assert scan_auth_write(archive(source + UNGUARDED)) == []
    declaration = f"actor={constructor}(current_actor), audit_repo=Depends(get_audit_repo)"
    fixed_witness = source.replace("audit_repo=Depends(get_audit_repo)", declaration)
    assert len(scan_auth_write(archive(fixed_witness + UNGUARDED))) == 1


NONE_GUARD = "def Guard(dependency):\n    return None\n"


def none_guard_routes():
    guarded = GUARDED.replace("Depends(current_actor)", "fastapi.Depends(current_actor)")
    target = UNGUARDED.replace("payload, audit_repo", "payload, actor=Guard(current_actor), audit_repo")
    return guarded + target


def test_shadowed_dependency_alias_returning_literal_none_does_not_hide_a_write_gap():
    source = "import fastapi\nfrom fastapi import Depends as Guard\n" + NONE_GUARD + none_guard_routes()
    hits = scan_auth_write(archive(source))
    assert len(hits) == 1
    assert "create(payload)" in source.splitlines()[hits[0].line - 1]


@pytest.mark.parametrize("helper", [
    "def Guard(dependency):\n    return fastapi.Depends(dependency)\n",
    "@wrap_dependency\ndef Guard(dependency):\n    return None\n",
    "def Guard(dependency):\n    check_access()\n    return None\n",
    NONE_GUARD + "Guard = configured_guard\n",
    NONE_GUARD + "if use_guard:\n    Guard = configured_guard\n",
])
def test_rebound_dependency_wrappers_remain_unknown_target_guards(helper):
    source = "import fastapi\nfrom fastapi import Depends as Guard\n" + helper + none_guard_routes()
    assert scan_auth_write(archive(source)) == []
    assert len(scan_auth_write(archive(source.replace(helper, NONE_GUARD)))) == 1


def test_later_none_helper_cannot_erase_an_already_evaluated_dependency_default():
    source = "import fastapi\nfrom fastapi import Depends as Guard\n" + none_guard_routes() + "\n" + NONE_GUARD
    assert scan_auth_write(archive(source)) == []
