"""Executable source-only boundaries for autonomous SQL input evidence."""

import ast
import json
import textwrap

import pytest

from app.scan.sql_input_evidence import analyze_query_input


HEADER = 'from fastapi import FastAPI, Request\nimport psycopg\napp = FastAPI()\n'
SETUP = 'conn = psycopg.connect(dsn)\ncur = conn.cursor()\n'


def route(body, *, parameters='name: str', path='/users', prefix=HEADER, decorator='@app.get'):
    return prefix + f'{decorator}({path!r})\ndef load({parameters}):\n' + textwrap.indent(body, '    ')


def collect(source, *, index=0, limit=50_000):
    tree = ast.parse(source)
    sinks = sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == 'execute'),
                   key=lambda node: (node.lineno, node.col_offset))
    work = 0

    def spend(amount=1):
        nonlocal work
        work += amount
        if work > limit:
            raise RuntimeError('budget exhausted')

    return analyze_query_input(tree, sinks[index], spend=spend)


def test_http_value_has_trace_and_declared_type_without_exposing_sql():
    result = collect(route(SETUP + 'cur.execute(f"SELECT secret_column FROM users WHERE name = \'{name}\'")\n'))
    assert result['status'] == 'established'
    assert result['parts'] == ["SELECT secret_column FROM users WHERE name = '", 0, "'"]
    source, flow = result['facts']
    assert source['sources'] == [{'parameter': 'name', 'channel': 'query', 'span': [5, 9, 5, 18]}]
    assert flow['locations']
    assert result['constraints'][0]['type'] == 'str'
    public = json.dumps({key: value for key, value in result.items() if key != 'parts'})
    assert 'SELECT' not in public and 'secret_column' not in public


@pytest.mark.parametrize('header, decorator', [
    ('import fastapi as f\nimport psycopg\napp = f.FastAPI()\n', '@app.get'),
    ('from fastapi import APIRouter as Router\nimport psycopg\napp = Router()\n', '@app.get'),
    (HEADER + 'api = app\n', '@api.post'),
])
def test_resolved_framework_imports_and_router_aliases(header, decorator):
    assert collect(route(SETUP + 'cur.execute(f"SELECT {name}")\n', prefix=header,
                         decorator=decorator))['status'] == 'established'


def test_assembled_query_keeps_origin_when_input_is_reassigned():
    result = collect(route(SETUP + 'q = f"SELECT \'{name}\'"\nname = "replacement"\ncur.execute(q)\n'))
    assert result['status'] == 'established'
    assert result['parts'] == ["SELECT '", 0, "'"]
    assert result['facts'][0]['sources'][0]['parameter'] == 'name'


def test_rebinding_used_input_removes_old_http_origin():
    result = collect(route(SETUP + 'name = "replacement"\ncur.execute(f"SELECT \'{name}\'")\n'))
    assert result['status'] == 'unknown'
    assert result['reason'] == 'no_dynamic_input'


def test_typed_path_and_query_slots_keep_individual_constraints():
    result = collect(route(SETUP + 'cur.execute(f"SELECT {item_id} WHERE name = \'{name}\'")\n',
                           parameters='item_id: int, name: str', path='/users/{item_id}'))
    assert result['status'] == 'established'
    assert [source['channel'] for source in result['facts'][0]['sources']] == ['path', 'query']
    assert [(item['slot'], item['type']) for item in result['constraints']] == [(0, 'int'), (1, 'str')]


def test_explicit_int_conversion_is_recorded_without_claiming_business_type():
    result = collect(route(SETUP + 'number = int(name)\ncur.execute(f"SELECT {number}")\n'))
    assert result['status'] == 'established'
    assert [item['kind'] for item in result['constraints']] == ['declared_type', 'int_conversion']
    assert not any('intended' in key for item in result['constraints'] for key in item)


def test_request_query_read_and_immutable_alias_snapshot():
    result = collect(route(SETUP + 'request_alias = request\nvalue = request_alias.query_params["private_key"]\n'
                           'q = "SELECT \'" + value + "\'"\nrequest = None\ncur.execute(q)\n',
                           parameters='request: Request'))
    assert result['status'] == 'established'
    assert result['constraints'][0]['kind'] == 'request_string'
    assert 'private_key' not in json.dumps(result['facts'])


def test_connection_cursor_with_context_managers():
    result = collect(route('with psycopg.connect(dsn) as conn:\n'
                           '    with conn.cursor() as cur:\n'
                           '        cur.execute(f"SELECT \'{name}\'")\n'))
    assert result['status'] == 'established'


@pytest.mark.parametrize('body, parameters', [
    (SETUP + 'cur.execute(f"SELECT {name} {unknown}")\n', 'name: str'),
    (SETUP + 'cur.execute(f"SELECT {name}")\n', 'name'),
    (SETUP + 'name = wrap(name)\ncur.execute(f"SELECT {name}")\n', 'name: str'),
    (SETUP + 'int = custom\ncur.execute(f"SELECT {int(name)}")\n', 'name: str'),
    (SETUP + 'cur.execute(f"SELECT {int(name)}")\nint = custom\n', 'name: str'),
    (SETUP + 'request = replacement\ncur.execute(f"SELECT {request.query_params[\'name\']}")\n', 'request: Request'),
    (SETUP + 'escape(request)\ncur.execute(f"SELECT {request.query_params[\'name\']}")\n', 'request: Request'),
    (SETUP + 'store.value = name\ncur.execute(f"SELECT {name}")\n', 'name: str'),
    (SETUP + 'cur.execute(f"SELECT {name}")\n', 'name: str = compute()'),
    (SETUP + 'cur.execute(f"SELECT {name}")\n', 'name: str = Depends(provider)'),
])
def test_unproven_paths_never_emit_request_or_flow_facts(body, parameters):
    result = collect(route(body, parameters=parameters))
    assert result['status'] != 'established'
    assert result['facts'] == []
    assert result['constraints'] == []


@pytest.mark.parametrize('statement', [
    'if condition:\n    name = other\n',
    'for name in values:\n    pass\n',
    'try:\n    name = other\nexcept Exception:\n    pass\n',
    'match value:\n    case name:\n        pass\n',
])
def test_control_flow_before_sink_cannot_reuse_old_parameter(statement):
    result = collect(route(SETUP + statement + 'cur.execute(f"SELECT {name}")\n'))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


def test_sink_inside_conditional_is_explicitly_unsupported():
    result = collect(route(SETUP + 'if condition:\n    cur.execute(f"SELECT {name}")\n'))
    assert result['status'] == 'unsupported'
    assert result['parts'] is None


@pytest.mark.parametrize('source', [
    route(SETUP + 'cur.execute(f"SELECT {name}")\n', prefix=HEADER + 'FastAPI = replacement\n'),
    route(SETUP + 'cur.execute(f"SELECT {name}")\n', prefix=HEADER + 'app = replacement\n'),
    route(SETUP + 'cur.execute(f"SELECT {name}")\n', prefix=HEADER + 'str = custom_type\n'),
    route(SETUP + 'cur.execute(f"SELECT {name}")\n', decorator='@unknown'),
    route(SETUP + 'cur.execute(f"SELECT {name}")\n').replace('@app.get', '@wrapper\n@app.get'),
    route(SETUP + 'cur.execute(f"SELECT {name}")\n').replace('def load', 'async def load'),
])
def test_route_or_type_identity_must_be_resolved(source):
    assert collect(source)['status'] != 'established'


def test_unknown_http_origin_can_still_provide_a_supported_sql_template():
    result = collect('def load(name):\n    cur.execute(f"SELECT \'{name}\'")\n')
    assert result['status'] == 'unknown'
    assert result['parts'] == ["SELECT '", 0, "'"]
    assert result['facts'] == []


@pytest.mark.parametrize('query', ['"SELECT %s" % name', '"SELECT {}".format(name)',
                                   'f"SELECT {name!r}"', 'f"SELECT {name:>20}"'])
def test_unsupported_formatting_does_not_invent_query_structure(query):
    result = collect(route(SETUP + f'cur.execute({query})\n'))
    assert result['status'] != 'established'
    assert result['parts'] is None or result['parts'] == [0]


def test_exact_call_identity_selects_corresponding_query():
    source = route(SETUP + 'cur.execute(f"SELECT \'{name}\'"); cur.execute(f"SELECT {unknown}")\n')
    assert collect(source, index=0)['status'] == 'established'
    assert collect(source, index=1)['status'] != 'established'


def test_budget_exception_propagates_to_shared_coordinator():
    with pytest.raises(RuntimeError, match='budget exhausted'):
        collect(route(SETUP + 'cur.execute(f"SELECT {name}")\n'), limit=1)


def test_expanding_template_is_bounded():
    source = route(SETUP + 'q = name\n' + 'q = q + q\n' * 20 + 'cur.execute(q)\n')
    assert collect(source)['status'] == 'unsupported'


def test_request_get_has_no_unconditional_string_constraint():
    result = collect(route(SETUP + 'cur.execute(f"SELECT {request.query_params.get(\'name\')}")\n',
                           parameters='request: Request'))
    assert result['status'] == 'established'
    assert result['constraint_status'] == 'unknown'
    assert result['constraints'] == []


@pytest.mark.parametrize('extra', [
    'def alter():\n    app.__setattr__("route_class", custom)\n',
    'def expose():\n    return app\n',
    'def expose():\n    registry["framework"] = FastAPI\n',
    'def alter():\n    builtins.__dict__["int"] = custom\n',
])
def test_deferred_framework_escape_or_namespace_mutation_revokes_binding(extra):
    result = collect(route(SETUP + 'cur.execute(f"SELECT {name}")\n') + extra)
    assert result['status'] == 'unknown'
    assert result['facts'] == []


def test_router_must_exist_when_the_decorator_is_evaluated():
    source = route(SETUP + 'cur.execute(f"SELECT {name}")\n',
                   prefix='from fastapi import FastAPI\nimport psycopg\n') + 'app = FastAPI()\n'
    assert collect(source)['status'] == 'unknown'


def test_container_expression_cannot_hide_a_mutating_call():
    result = collect(route(SETUP + 'discard = [modify(request)]\n'
                           'cur.execute(f"SELECT {request.query_params[\'name\']}")\n',
                           parameters='request: Request'))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


def test_sink_lookup_requires_same_ast_object_not_equal_source_location():
    source = route(SETUP + 'cur.execute(f"SELECT {name}")\n')
    tree = ast.parse(source)
    foreign_sink = next(node for node in ast.walk(ast.parse(source))
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'execute')
    result = analyze_query_input(tree, foreign_sink, spend=lambda amount=1: None)
    assert result['status'] == 'unknown'
    assert result['reason'] == 'sink_not_in_tree'


@pytest.mark.parametrize('change', [
    'def other(value: mutate()):\n    pass\n',
    'def other(value: unknown.descriptor):\n    pass\n',
])
def test_other_function_annotation_effects_invalidate_framework_identity(change):
    result = collect(route(SETUP + 'cur.execute(f"SELECT {name}")\n') + change)
    assert result['status'] == 'unknown'


def test_unused_descriptor_annotation_does_not_manufacture_framework_proof():
    result = collect(route(SETUP + 'cur.execute(f"SELECT {name}")\n',
                           parameters='name: str, unused: unknown.descriptor'))
    assert result['status'] == 'unknown'


def test_independent_supported_routes_and_pure_defaults_can_share_a_module():
    source = route(SETUP + 'cur.execute(f"SELECT {name}")\n')
    source += '\n@app.get("/other")\ndef other(value: str = "default"):\n    return value\n'
    assert collect(source)['status'] == 'established'


def supported_route(source, *, limit=50_000):
    from app.scan.sql_input_evidence import is_supported_fastapi_route

    tree = ast.parse(source)
    fn = next(node for node in ast.walk(tree)
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == 'load')
    work = 0

    def spend(amount=1):
        nonlocal work
        work += amount
        if work > limit:
            raise RuntimeError('budget exhausted')

    return is_supported_fastapi_route(tree, fn, spend=spend)


def test_route_helper_accepts_supported_binding_without_a_sql_sink():
    assert supported_route(route('return name\n'))


@pytest.mark.parametrize('source', [
    route('return name\n', decorator='@unknown'),
    route('return name\n').replace('@app.get', '@wrapper\n@app.get'),
    route('return name\n', parameters='name: str = Depends(provider)'),
    route('return name\n', parameters='name: str = compute()'),
    route('return name\n', prefix=HEADER + 'app = replacement\n'),
    route('return name\n', prefix=HEADER + 'FastAPI = replacement\n'),
    route('return name\n').replace('def load', 'async def load'),
    HEADER + 'def outer():\n' + textwrap.indent(route('return name\n', prefix=''), '    '),
    route('return name\n', prefix='from fastapi import FastAPI\n') + 'app = FastAPI()\n',
])
def test_route_helper_rejects_unresolved_bindings_metadata_and_scopes(source):
    assert supported_route(source) is False


def test_route_helper_obeys_shared_work_budget():
    with pytest.raises(RuntimeError, match='budget exhausted'):
        supported_route(route('return name\n'), limit=1)


def test_route_helper_requires_the_actual_function_node():
    from app.scan.sql_input_evidence import is_supported_fastapi_route

    source = route('return name\n')
    tree = ast.parse(source)
    foreign = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef))
    assert is_supported_fastapi_route(tree, foreign, spend=lambda amount=1: None) is False


def test_public_slot_count_cannot_exceed_acquisition_schema():
    result = collect(route(SETUP + 'cur.execute(f"' + '{name}' * 65 + '")\n'))
    assert result['status'] == 'unsupported'
    assert result['reason'] == 'input_evidence_limit'
    assert result['facts'] == []


def test_public_flow_locations_cannot_exceed_acquisition_schema():
    result = collect(route(SETUP + 'value = name\n' + 'value = value\n' * 65
                           + 'cur.execute(f"SELECT {value}")\n'))
    assert result['status'] == 'unsupported'
    assert result['reason'] == 'input_evidence_limit'
    assert result['facts'] == []
