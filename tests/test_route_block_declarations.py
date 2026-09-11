"""Block discovery must preserve scope and conditional registration evidence."""
import io
import textwrap
import zipfile

import pytest

from app.scan.auth_read import scan_auth_read
from app.scan.auth_write import scan_auth_write
from app.scan.outbound_url import scan_outbound_url
from app.scan.path_traversal import scan_path_traversal

BASE = "from fastapi import APIRouter, Depends\nrouter = APIRouter()\nrepo = Repository()\n"
READ_PROTECTED = '''@router.get("/notes")
def protected(actor=Depends(current_actor)):
    return repo.list()
'''
READ_OPEN = '''@router.get("/notes/{note_id}")
def get_note(note_id):
    return repo.get(note_id)
'''
WRITE_PROTECTED = '''@router.post("/notes")
def protected(actor=Depends(current_actor)):
    return repo.create()
'''
WRITE_OPEN = '''@router.delete("/notes/{note_id}")
def delete_note(note_id):
    return repo.delete(note_id)
'''
OUTBOUND = '''@router.get("/proxy")
def proxy(host: str):
    return httpx.get(f"http://{host}/")
'''
PATH = '''@router.get("/download")
def download(name: str):
    return open(name).read()
'''


def scan(scanner, source):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("repo/app/routes.py", source)
    data.seek(0)
    return scanner(data)


def indent(source):
    return textwrap.indent(source, "    ")


@pytest.mark.parametrize("scanner,protected,opened", [
    (scan_auth_read, READ_PROTECTED, READ_OPEN),
    (scan_auth_write, WRITE_PROTECTED, WRITE_OPEN),
])
@pytest.mark.parametrize("block,depth", [
    ("if enabled:\n    pass\nelse:\n", 1),
    ("try:\n    pass\nexcept Exception:\n", 1),
    ("try:\n    pass\nfinally:\n", 1),
    ("match mode:\n    case 'public':\n", 2),
])
def test_auth_routes_are_discovered_in_each_block_arm(scanner, protected, opened, block, depth):
    source = BASE + protected + block + textwrap.indent(opened, "    " * depth)
    assert len(scan(scanner, source)) == 1


@pytest.mark.parametrize("scanner,protected,opened", [
    (scan_auth_read, READ_PROTECTED, READ_OPEN),
    (scan_auth_write, WRITE_PROTECTED, WRITE_OPEN),
])
@pytest.mark.parametrize("choice", ["if", "match"])
def test_auth_witness_must_be_compatible_with_the_target_registration(scanner, protected, opened, choice):
    if choice == "if":
        source = BASE + "if enabled:\n" + indent(protected) + "else:\n" + indent(opened)
    else:
        source = BASE + "match mode:\n    case 'protected':\n" + indent(indent(protected))
        source += "    case 'public':\n" + indent(indent(opened))
    assert scan(scanner, source) == []
    # An independently registered witness restores the actual sibling evidence.
    independent = protected.replace("def protected(", "def always_protected(")
    assert len(scan(scanner, source + independent)) == 1


@pytest.mark.parametrize("block,depth", [
    ("for {name} in values:\n", 1),
    ("with context() as {name}:\n", 1),
    ("try:\n    pass\nexcept Exception as {name}:\n", 1),
    ("match obj:\n    case {{'value': {name}}}:\n", 2),
])
@pytest.mark.parametrize("name", ["httpx", "router"])
def test_outbound_block_header_cannot_borrow_the_shadowed_import(block, depth, name):
    body = textwrap.indent(OUTBOUND, "    " * depth)
    source = BASE + "import httpx\n" + block.format(name=name) + body
    assert scan(scan_outbound_url, source) == []
    control = BASE + "import httpx\n" + block.format(name="unrelated") + body
    assert len(scan(scan_outbound_url, control)) == 1


def test_an_import_in_one_branch_invalidates_the_client_after_the_block():
    source = BASE + "import httpx\nif enabled:\n    import safe_client as httpx\n" + OUTBOUND
    assert scan(scan_outbound_url, source) == []
    assert len(scan(scan_outbound_url, source.replace(" as httpx", " as other_client"))) == 1


@pytest.mark.parametrize("binding", [
    "def open(name):\n    return safe_file\n",
    "class open:\n    pass\n",
])
def test_path_route_in_block_cannot_treat_a_local_definition_as_builtin_open(binding):
    source = BASE + "if enabled:\n" + indent(binding + PATH)
    assert scan(scan_path_traversal, source) == []
    assert len(scan(scan_path_traversal, source.replace("def open(", "def unrelated(").replace(
        "class open:", "class unrelated:"))) == 1


@pytest.mark.parametrize("block", [
    "try:\n    pass\nexcept Exception as open:\n",
    "match obj:\n    case {'reader': open}:\n",
])
def test_path_block_header_cannot_borrow_builtin_open(block):
    body = indent(indent(PATH)) if block.startswith("match") else indent(PATH)
    assert scan(scan_path_traversal, BASE + block + body) == []
    assert len(scan(scan_path_traversal, BASE + block.replace("open", "reader") + body)) == 1


def test_path_discovery_reaches_a_block_inside_a_router_factory():
    source = "from fastapi import APIRouter\ndef create_router():\n    router = APIRouter()\n"
    source += "    if enabled:\n" + indent(indent(PATH))
    assert len(scan(scan_path_traversal, source)) == 1


def test_nested_handler_locals_do_not_rebind_the_module_router():
    source = BASE + READ_PROTECTED + "if enabled:\n" + indent(READ_OPEN.replace(
        "    return repo.get", "    router = unrelated\n    return repo.get"))
    assert len(scan(scan_auth_read, source)) == 1


@pytest.mark.parametrize("scanner,protected,opened", [
    (scan_auth_read, READ_PROTECTED, READ_OPEN),
    (scan_auth_write, WRITE_PROTECTED, WRITE_OPEN),
])
def test_auth_routes_in_alternative_except_handlers_do_not_supply_a_witness(scanner, protected, opened):
    source = BASE + "try:\n    configure()\nexcept ValueError:\n" + indent(protected)
    source += "except TypeError:\n" + indent(opened)
    assert scan(scanner, source) == []
    assert len(scan(scanner, source + protected.replace("def protected(", "def independent("))) == 1


def test_auth_route_cannot_borrow_router_shadowed_by_mapping_rest():
    source = BASE + READ_PROTECTED + "match obj:\n    case {**router}:\n" + indent(indent(READ_OPEN))
    assert scan(scan_auth_read, source) == []
    assert len(scan(scan_auth_read, source.replace("{**router}", "{**rest}"))) == 1


@pytest.mark.parametrize("scanner,protected,opened", [
    (scan_auth_read, READ_PROTECTED, READ_OPEN),
    (scan_auth_write, WRITE_PROTECTED, WRITE_OPEN),
])
@pytest.mark.parametrize("loop", ["for enabled in [True, False]:\n", "while more_modes():\n"])
@pytest.mark.parametrize("choice", ["if", "match", "except"])
def test_repeated_choices_can_register_both_routes_on_one_router(scanner, protected, opened, loop, choice):
    if choice == "if":
        declarations = "if enabled:\n" + indent(protected) + "else:\n" + indent(opened)
    elif choice == "match":
        declarations = "match enabled:\n    case True:\n" + indent(indent(protected))
        declarations += "    case False:\n" + indent(indent(opened))
    else:
        declarations = "try:\n    configure()\nexcept ValueError:\n" + indent(protected)
        declarations += "except TypeError:\n" + indent(opened)
    assert len(scan(scanner, BASE + loop + indent(declarations))) == 1
    # Removing repetition restores mutually exclusive registration.
    assert scan(scanner, BASE + declarations) == []


@pytest.mark.parametrize("scanner,protected,opened", [
    (scan_auth_read, READ_PROTECTED, READ_OPEN),
    (scan_auth_write, WRITE_PROTECTED, WRITE_OPEN),
])
def test_loop_does_not_erase_exclusivity_of_an_enclosing_choice(scanner, protected, opened):
    source = BASE + "if enabled:\n    for mode in modes:\n" + indent(indent(protected))
    source += "else:\n" + indent(opened)
    assert scan(scanner, source) == []
    assert len(scan(scanner, source + protected.replace("def protected(", "def independent("))) == 1
