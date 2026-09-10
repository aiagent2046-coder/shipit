"""The escape hunt's dump must be reviewable, or it is not evidence.

A dump that has been masked cannot be parsed, and a body nobody can parse cannot
be judged -- which turns "19 candidates" into a number built on bodies a reviewer
skips. Measured before this test existed: 6 of 19 dumped bodies in one round and
3 of 12 in another were unreadable after the masker rewrote every run of 24+
word characters, so an identifier such as `provide_storage_interface` came back
as `prov...[25 chars]`.

The test asserts the property that makes the artifact useful, in the shape that
cannot be satisfied by accident: what lands on disk is byte-identical to the
escape body, long identifiers included, and it still parses as Python when the
body does.
"""
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

BODY = '''from fastapi import APIRouter, Depends


def build_router():
    router = APIRouter()

    @router.get("/x")
    async def handler(
        value: str,
        storage_interface=Depends(provide_storage_interface),
        record_repository=Depends(fetch_record_repository),
    ):
        return value
'''


def load_hunt():
    """Import the script by path: it is a script, not a package module."""
    path = REPO_ROOT / "scripts" / "hunt_detector_escapes.py"
    spec = importlib.util.spec_from_file_location("hunt_detector_escapes", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["hunt_detector_escapes"] = module
    spec.loader.exec_module(module)
    return module


hunt = load_hunt()


def an_escape(body: str):
    return hunt.Escape(
        rule_id="python-route-write-auth-consistency", case="a-case", variation_index=0,
        target_file="app/routes.py", body_sha="deadbeefcafe", body_chars=len(body),
        fired_rules=[], body=body,
    )


def a_result(escape):
    return hunt.RuleResult(rule_id=escape.rule_id, case=escape.case,
                           target_file=escape.target_file, baseline_ok=True, escapes=[escape])


def test_dumped_body_is_verbatim_and_still_parses(tmp_path):
    hunt.dump_escapes([a_result(an_escape(BODY))], tmp_path)
    written = list(tmp_path.glob("*.py"))
    assert len(written) == 1
    text = written[0].read_text()
    assert text == BODY, "the dump must be the body, not a rewrite of it"
    assert "provide_storage_interface" in text, "long identifiers are what the masker ate"
    ast.parse(text)  # the whole point: a reviewable body parses


def test_a_masked_dump_would_fail_this_suite(tmp_path):
    """Guards the guard: the property is about the WRITE path, so a harness that
    masks its own artifact once more must fail here rather than pass quietly."""
    masked = BODY.replace("provide_storage_interface", "prov...[25 chars]")
    hunt.dump_escapes([a_result(an_escape(masked))], tmp_path)
    text = next(tmp_path.glob("*.py")).read_text()
    assert text == masked  # the write is faithful --
    with pytest.raises(SyntaxError):
        ast.parse(text)  # -- and a masked body is exactly what cannot be read
