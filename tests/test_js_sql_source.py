"""Source proofs are conservative, bounded, and independent of value parameters."""
import hashlib

import pytest

from app.scan import js_sql_source as source


def analyze(code, line=None, method=None):
    raw = code.encode()
    if line is None:
        line = next(i for i, text in enumerate(code.splitlines(), 1) if "db.query(" in text)
    result = source.analyze_source(raw, "src/пример.ts", line, method)
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["runtime_verified"] is False
    return result


def test_fixed_module_helper_with_typed_literal_argument():
    result = analyze('''export function visibility(index: number): string {
  return `(owner_id = $${index} OR public = true)`
}
db.query(`SELECT * FROM events WHERE ${visibility(3)}`, [id, tenant, user]);''')
    assert result["verdict"] == "fixed_sql_fragments"
    assert result["parameter_argument"] == "present"
    assert {"line": 1, "kind": "fixed_helper", "reason": "single_return_literal_args"} in result["fragments"]


@pytest.mark.parametrize("code", [
    'db.query(`SELECT ${req.query.name}`, [req.query.name])',
    'db.query("SELECT " + value)',
    'export function f(x) {return `${x}`}\ndb.query(`SELECT ${f(input)}`)',
    'export function f(x) {return `${x}`}\nf = evil;\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {return `${x}`}\nfunction run(f) {db.query(`SELECT ${f(3)}`)}',
    'export function f(x) {return `${x}`}\nfunction run() {const f = evil; db.query(`SELECT ${f(3)}`)}',
    'export function f(...x) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x = input) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function* f(x) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export async function f(x) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {sideEffect(); return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {return `${g(x)}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {return `${x}`}\ndb.query(`SELECT ${f(...values)}`)',
    'export function f(x) {return `${x}`}\ndb.query(`SELECT ${f(3, 4)}`)',
    'export function f(x) {return `${x}`}\ndb.query(`SELECT ${f()}`)',
    'export function f({x}) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'function f(x) {return `${x}`}\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {return `${x}`}\nglobalThis.f = evil;\ndb.query(`SELECT ${f(3)}`)',
    'export function f(x) {return `${x}`}\neval(code);\ndb.query(`SELECT ${f(3)}`)',
    r'export function f(x) {return `${x}`} function g(\u0066) {db.query(`SELECT ${f(3)}`)}',
    'let fragment = "fixed";\ndb.query(`SELECT ${fragment}`)',
    'const fragment = "fixed";\nfunction f(fragment) {db.query(`SELECT ${fragment}`)}',
    'const fragment = "fixed";\nfragment = input;\ndb.query(`SELECT ${fragment}`)',
    'const fragment = "fixed";\nfunction f() {var fragment; db.query(`SELECT ${fragment}`)}',
    '{ const fragment = "fixed"; }\ndb.query(`SELECT ${fragment}`)',
    'const first = "fixed"; const second = first;\ndb.query(`SELECT ${second}`)',
    'const fragment = {toString() {return input}};\ndb.query(`SELECT ${fragment}`)',
])
def test_uncertain_input_never_promoted(code):
    result = analyze(code)
    assert result["verdict"] == "dynamic_sql_unresolved"
    assert result["reason"] == "unresolved_expression"


@pytest.mark.parametrize("query", ['"SELECT " + "1"', '`SELECT ${3}`', '`SELECT ${"fixed"}`'])
def test_primitive_assembly(query):
    assert analyze(f'db.query({query})')["verdict"] == "fixed_sql_fragments"


def test_one_hop_const_unicode():
    result = analyze('const фрагмент = "id";\ndb.query(`SELECT ${фрагмент}`)')
    assert result["verdict"] == "fixed_sql_fragments"
    assert result["parameter_argument"] == "absent"


def test_sink_method_does_not_disambiguate_same_line():
    result = analyze('db.query(`SELECT ${value}`); db.execute(`SELECT ${other}`)', method="query")
    assert result["reason"] == "ambiguous_sink"


def test_tagged_template_is_not_sink():
    assert analyze('db.query`SELECT ${value}`', line=1)["reason"] == "sink_not_found"


def test_unrelated_sink_method_rejected():
    assert analyze('db.query(`SELECT ${value}`)', method="execute")["reason"] == "sink_not_found"


def test_invalid_encoding_and_syntax():
    assert source.analyze_source(b'\xff', 'x.ts', 1)["reason"] == "invalid_utf8"
    assert analyze('db.query(`SELECT ${`)', line=1)["reason"] == "parse_error"


@pytest.mark.parametrize(("limit", "value", "reason"), [
    ("MAX_FILE_BYTES", 5, "file_limit"),
    ("MAX_NODES", 3, "node_limit"),
    ("MAX_DEPTH", 2, "depth_limit"),
])
def test_budgets(monkeypatch, limit, value, reason):
    monkeypatch.setattr(source, limit, value)
    assert analyze('db.query(`SELECT ${value}`)')["reason"] == reason


def test_second_argument_is_not_parameterization_proof():
    result = analyze('db.query(`SELECT ${untrusted}`, [])')
    assert result["parameter_argument"] == "present"
    assert result["verdict"] == "dynamic_sql_unresolved"


def test_both_conditional_arms_must_have_fixed_syntax():
    assert analyze('db.query(flag ? `SELECT ${3}` : `SELECT ${4}`)')["verdict"] == "fixed_sql_fragments"
    assert analyze('db.query(flag ? `SELECT ${3}` : input)')["verdict"] == "dynamic_sql_unresolved"


def test_condition_mutating_helper_blocks_proof():
    code = 'export function f(x) {return `${x}`}\ndb.query((f = evil) ? `SELECT ${f(3)}` : `SELECT ${f(4)}`)'
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


@pytest.mark.parametrize("binding", ["{sql}", "{sql = input}", "{nested: {sql}}", "[sql]", "{x: sql}"])
def test_destructured_parameter_cannot_shadow_fixed_const(binding):
    code = f'const sql = "SELECT safe";\nfunction f({binding}) {{db.query("SELECT " + sql);}}'
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


@pytest.mark.parametrize("binding", ["{helper}", "{helper = other}", "{nested: {helper}}", "[helper]"])
def test_destructured_parameter_cannot_shadow_fixed_helper(binding):
    code = ('export {}; function helper(x) {return x;}\n'
            f'function f({binding}) {{db.query("SELECT " + helper("safe"));}}')
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


@pytest.mark.parametrize("condition", ["x = evil()", "x++", "x += evil()", "sideEffect(x)"])
def test_helper_condition_cannot_mutate_bound_literal_parameter(condition):
    code = (f'export {{}}; function helper(x) {{return ({condition}) ? x : x;}}\n'
            'db.query("SELECT " + helper("safe"));')
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


def test_destructuring_assignment_cannot_replace_helper():
    code = ('export {}; function helper(x) {return x;}\n'
            '({helper} = input);\ndb.query("SELECT " + helper("safe"));')
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


@pytest.mark.parametrize("declaration", [
    "class sql { static toString() {return input;} }",
    "abstract class sql { static toString() {return input;} }",
    "enum sql { injected }",
    "namespace sql { export const injected = true; }",
])
def test_typescript_runtime_declarations_shadow_const(declaration):
    code = f'const sql = "safe";\nfunction f(input) {{{declaration} db.query("SELECT " + sql);}}'
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


def test_named_class_expression_shadows_const_inside_method():
    code = ('const sql = "safe";\nconst wrapper = class sql {'
            'static toString() {return input;} method() {db.query("SELECT " + sql);}};')
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


def test_class_declaration_shadows_helper():
    code = ('export {}; function helper(x) {return x;}\n'
            'function f(input) {class helper {} db.query("SELECT " + helper("safe"));}')
    assert analyze(code)["verdict"] == "dynamic_sql_unresolved"


def test_erased_type_alias_does_not_shadow_value():
    code = 'type sql = string; const sql = "safe";\ndb.query("SELECT " + sql);'
    assert analyze(code)["verdict"] == "fixed_sql_fragments"



def test_shared_work_budget_discards_partial_proof(monkeypatch):
    monkeypatch.setattr(source, "MAX_WORK", 2)
    result = analyze('db.query("SELECT " + "fixed")')
    assert result["verdict"] == "unavailable"
    assert result["reason"] == "work_limit"
    assert result["fragments"] == []


def test_repeated_helper_expansion_is_bounded_without_time_assertions():
    code = ('export function f(x) {return `' + '${x}' * 5000 + '`;}\n'
            'db.query(`SELECT ' + '${f(1)}' * 2000 + '`);')
    assert len(code.encode()) < source.MAX_FILE_BYTES
    result = analyze(code)
    assert result["verdict"] == "unavailable"
    assert result["reason"] == "work_limit"
    assert result["fragments"] == []
