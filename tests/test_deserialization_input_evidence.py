"""Source-proof boundaries for a bytes Body reaching an exact pickle call."""

import ast
import json
import textwrap

import pytest

from app.scan.deserialization_input_evidence import analyze_deserialization_input


HEADER = 'from fastapi import FastAPI, Body\nimport pickle\napp = FastAPI()\n'


def route(body='return pickle.loads(data)\n', *, parameters='data: bytes = Body(...)',
          header=HEADER, decorator='@app.post("/load")', asynchronous=False):
    return (header + decorator + '\n' + ('async ' if asynchronous else '')
            + f'def load({parameters}):\n' + textwrap.indent(body, '    '))


def collect(source, *, index=0, spend=None):
    tree = ast.parse(source)
    calls = sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and (isinstance(node.func, ast.Attribute) and node.func.attr == 'loads'
                         or isinstance(node.func, ast.Name) and node.func.id in {'loads', 'restore'})),
                   key=lambda node: (node.lineno, node.col_offset))
    return analyze_deserialization_input(tree, calls[index], spend=spend)


def test_body_source_and_alias_path_contain_only_structural_facts():
    result = collect(route('payload = data\ncopy: bytes = payload\nreturn pickle.loads(copy)\n',
                           parameters='data: bytes = Body(..., description="SECRET_SCHEMA")'))
    assert result['status'] == 'established'
    source, flow = result['facts']
    assert source['id'] == 'request_input_source'
    assert source['method'] == 'fastapi_ast_binding'
    assert source['sources'] == [{'parameter': 'data', 'channel': 'body', 'span': [5, 9, 5, 20]}]
    assert flow['id'] == 'local_input_flow'
    assert flow['method'] == 'python_ast_straight_line'
    assert {position[0] for position in flow['locations']} == {5, 6, 7, 8}
    serialized = json.dumps(result)
    assert 'SECRET_SCHEMA' not in serialized and '/load' not in serialized
    assert all(key not in serialized for key in ('attacker_control', 'input_trust_boundary',
                                                'loader_runtime_contract', 'runtime_verified'))


@pytest.mark.parametrize('header, parameters, body', [
    ('import fastapi as api\nimport pickle\napp = api.FastAPI()\n',
     'data: bytes = api.Body(...)', 'return pickle.loads(data)\n'),
    ('from fastapi import APIRouter as Router, Body as B\nfrom pickle import loads as restore\n'
     'app = Router(prefix="/v1")\n',
     'data: bytes = B()', 'return restore(data)\n'),
    (HEADER + 'from typing import Annotated as A\n',
     'data: A[bytes, Body()]', 'return pickle.loads(data)\n'),
    (HEADER + 'import typing as t\n',
     'data: t.Annotated[bytes, Body(media_type="application/octet-stream")]',
     'return pickle.loads(data)\n'),
    (HEADER + 'from typing_extensions import Annotated\n',
     'data: Annotated[bytes, Body(...)]', 'return pickle.loads(data)\n'),
    (HEADER + 'import builtins\n', 'data: builtins.bytes = Body(default=...)',
     'return pickle.loads(data)\n'),
    (HEADER, '*, data: bytes = Body(...)', 'return pickle.loads(data)\n'),
    (HEADER, 'data: bytes = Body(...), extra: int = 1', 'return pickle.loads(data)\n'),
])
def test_explicit_resolved_body_forms(header, parameters, body):
    result = collect(route(body, header=header, parameters=parameters))
    assert result['status'] == 'established'
    assert result['facts'][0]['sources'][0]['channel'] == 'body'


def test_async_handler_with_direct_synchronous_load_is_supported():
    assert collect(route(asynchronous=True))['status'] == 'established'


def test_alias_keeps_original_bytes_after_parameter_is_overwritten():
    result = collect(route('payload = data\ndata = b"local"\nreturn pickle.loads(payload)\n'))
    assert result['status'] == 'established'
    assert result['facts'][0]['sources'][0]['parameter'] == 'data'


@pytest.mark.parametrize('parameters', [
    'data: bytes',
    'data: bytes = b"fixed"',
    'data: str = Body(...)',
    'data = Body(...)',
    'data: "bytes" = Body(...)',
    'data: bytes = fake.Body(...)',
    'data: bytes = Body(default_factory=make_body)',
    'data: bytes = Body(b"fallback")',
    'data: bytes = Body(..., description=side_effect())',
    'data: bytes = Body(..., **options)',
    'data: bytes = Body(..., default=...)',
    'data: bytes = Body(...), other: bytes = Body(...)',
    'data: bytes = Body(...), *args',
    'data: bytes = Body(...), **kwargs',
    'data: bytes = Body(...), /',
    'data: bytes = Body(...), unused: custom.descriptor = None',
    'data: bytes = Body(...), unused: int = factory()',
])
def test_unresolved_or_ambiguous_body_metadata_does_not_emit_facts(parameters):
    result = collect(route(parameters=parameters))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('annotation', [
    'Annotated[str, Body()]',
    'Annotated[bytes, Body(), CustomValidator()]',
    'Annotated[bytes, UnknownBody()]',
    'Annotated[bytes, Body(default_factory=factory)]',
    'OtherAnnotated[bytes, Body()]',
])
def test_annotated_requires_exact_resolved_bytes_and_body(annotation):
    result = collect(route(header=HEADER + 'from typing import Annotated\n',
                           parameters=f'data: {annotation}'))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('body', [
    'data = b"replacement"\nreturn pickle.loads(data)\n',
    'data = other\nreturn pickle.loads(data)\n',
    'data = bytes(data)\nreturn pickle.loads(data)\n',
    'data = decode(data)\nreturn pickle.loads(data)\n',
    'observe(data)\nreturn pickle.loads(data)\n',
    'discard = [observe(data)]\nreturn pickle.loads(data)\n',
    'if condition:\n    data = other\nreturn pickle.loads(data)\n',
    'if condition:\n    return pickle.loads(data)\n',
    'for unused in things:\n    pass\nreturn pickle.loads(data)\n',
    'try:\n    pass\nexcept Exception:\n    pass\nreturn pickle.loads(data)\n',
    'with guard():\n    return pickle.loads(data)\n',
    'return wrapper(pickle.loads(data))\n',
    'return pickle.loads(data[:])\n',
    'return pickle.loads(data + b"suffix")\n',
    'return pickle.loads(data, encoding="utf-8")\n',
    'return pickle.loads(data, other)\n',
    'return pickle.loads(*data)\n',
    'return pickle.loads(data= data)\n',
    'del data\nreturn pickle.loads(data)\n',
    'data += b"suffix"\nreturn pickle.loads(data)\n',
    'data, other = other, data\nreturn pickle.loads(data)\n',
    'return None\nreturn pickle.loads(data)\n',
    'await operation()\nreturn pickle.loads(data)\n',
])
def test_unsupported_execution_paths_never_reuse_body_origin(body):
    result = collect(route(body))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('extra', [
    'Body = replacement\n',
    'app = replacement\n',
    'pickle = replacement\n',
    'bytes = custom_type\n',
    'pickle.loads = replacement\n',
    'def change():\n    global pickle\n    pickle = replacement\n',
    'def change():\n    app.__dict__["router"] = replacement\n',
    'def change():\n    setattr(pickle, "loads", replacement)\n',
    'from builtins import exec as execute\ndef change():\n    execute("bytes = custom")\n',
    'def change():\n    mutate(__builtins__)\n',
    'def change():\n    return app\n',
    'def change():\n    escape(Body)\n',
    'def change():\n    escape(pickle)\n',
    'def change():\n    import pickle as p\n    escape(p)\n',
    'import pickle as later\ndef change():\n    escape(later)\n',
    'def change(unused=modify()):\n    pass\n',
    'def change(unused: modify()):\n    pass\n',
    'def change(unused: descriptor.type):\n    pass\n',
    'from custom import *\n',
    'from . import pickle\n',
    'mutate_environment()\n',
])
def test_module_rebinding_mutation_and_escape_invalidate_provenance(extra):
    result = collect(route() + extra)
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('body', [
    'return pickle.loads(data)\npickle = replacement\n',
    'return pickle.loads(data)\nbytes = custom_type\n',
    'return pickle.loads(data)\ndef pickle():\n    pass\n',
    'return pickle.loads(data)\ntry:\n    pass\nexcept Exception as pickle:\n    pass\n',
    'return pickle.loads(data)\nmatch value:\n    case pickle:\n        pass\n',
])
def test_function_scope_shadowing_after_sink_still_revokes_binding(body):
    result = collect(route(body))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('decorator', [
    '@unknown("/load")', '@wrapper\n@app.post("/load")',
    '@app.post("/load", dependencies=[guard])', '@app.post(path)',
])
def test_unresolved_or_wrapped_handler_is_unknown(decorator):
    assert collect(route(decorator=decorator))['facts'] == []


@pytest.mark.parametrize('source', [
    route(decorator='@app.post("/load/{data}")'),
    route(header=HEADER.replace('FastAPI, Body', 'APIRouter, Body')
          .replace('FastAPI()', 'APIRouter(prefix="/load/{data:path}")')),
])
def test_body_parameter_conflicting_with_route_path_is_unknown(source):
    assert collect(source)['facts'] == []


def test_router_created_after_decorator_cannot_establish_source():
    source = route(header='from fastapi import FastAPI, Body\nimport pickle\n') + 'app = FastAPI()\n'
    assert collect(source)['facts'] == []


def test_unresolved_loader_import_does_not_match_by_spelling():
    assert collect(route(header=HEADER.replace('import pickle\n', '')))['facts'] == []
    assert collect(route(header=HEADER.replace('import pickle', 'import custom as pickle')))['facts'] == []


def test_undecorated_and_nested_handlers_are_unknown():
    assert collect(route(decorator=''))['facts'] == []
    nested = HEADER + 'def outer():\n' + textwrap.indent(route(header=''), '    ')
    assert collect(nested)['facts'] == []


def test_selected_ast_call_cannot_borrow_another_calls_input():
    source = route('pickle.loads(data)\npickle.loads(other)\n')
    assert collect(source, index=0)['status'] == 'established'
    assert collect(source, index=1)['facts'] == []
    tree = ast.parse(source)
    foreign = next(node for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == 'loads')
    result = analyze_deserialization_input(tree, foreign)
    assert result == {'status': 'unknown', 'reason': 'sink_not_in_tree', 'facts': []}


def test_shared_budget_exception_is_not_converted_to_missing_evidence():
    class Exhausted(RuntimeError):
        pass

    def spend(amount=1):
        raise Exhausted('shared budget reached')

    with pytest.raises(Exhausted, match='shared budget reached'):
        collect(route(), spend=spend)


def test_repeated_collection_is_deterministic_and_does_not_modify_ast():
    source = route('payload = data\nreturn pickle.loads(payload)\n')
    tree = ast.parse(source)
    sink = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == 'loads')
    before = ast.dump(tree, include_attributes=True)
    assert analyze_deserialization_input(tree, sink) == analyze_deserialization_input(tree, sink)
    assert ast.dump(tree, include_attributes=True) == before


@pytest.mark.parametrize('source', [
    route('payload = data\n' + 'payload = payload\n' * 130 + 'return pickle.loads(payload)\n'),
    route() + 'padding = ' + '+' * 110 + '1\n',
    route() + '\n'.join(f'padding_{index} = 1' for index in range(6_000)),
])
def test_source_depth_size_and_flow_growth_are_bounded(source):
    result = collect(source)
    assert result == {'status': 'unknown', 'reason': 'input_evidence_limit', 'facts': []}
