"""Invariant probes must preserve observable behavior, not just parse."""

from scripts.metamorphic_probe import scan_entries
from tests.metamorphic_variants import TRANSFORMS, py_rename_locals, variant_entries


def test_python_keyword_api_and_module_names_survive_local_rename():
    source = '''local = 20
def calculate(value):
    local = value + 1
    holder_1 = 4
    return local + holder_1
result = (calculate(value=3), local)
'''
    rewritten = py_rename_locals(source)
    assert rewritten and rewritten != source
    before, after = {}, {}
    exec(source, before)
    exec(rewritten, after)
    assert before["result"] == after["result"] == (8, 20)


def test_python_parameters_without_private_locals_are_not_applicable():
    assert py_rename_locals("def f(value):\n    return value\nf(value=3)\n") is None


def test_js_shorthand_cookie_flag_stays_safe_after_rename():
    source = '''function send(res, token) {
  const httpOnly = true;
  res.cookie("session", token, { httpOnly, secure: true, sameSite: "lax" });
}
'''
    transform = next(t for t in TRANSFORMS if t.lang == "js" and t.id == "rename_locals")
    variant = variant_entries({"src/app.js": source}, transform)
    assert variant.status == "applied"
    for entries in ({"src/app.js": source}, variant.entries):
        assert not any(f["rule_id"] == "insecure-session-cookie-attributes"
                       for f in scan_entries(entries))


def test_js_export_names_and_regexp_are_not_renamed():
    source = 'export const published = 1;\nconst pattern = /pattern/;\nconsole.log(pattern);\n'
    transform = next(t for t in TRANSFORMS if t.lang == "js" and t.id == "rename_locals")
    variant = variant_entries({"src/app.js": source}, transform)
    assert variant.status == "applied"
    assert "export const published = 1" in variant.entries["src/app.js"]
    assert "/pattern/" in variant.entries["src/app.js"]
