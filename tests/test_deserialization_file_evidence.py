"""Static file-input evidence and the boundaries that must leave it unknown."""

import ast
import json
import textwrap

import pytest

from app.scan.deserialization_file_evidence import analyze_deserialization_file_input


def loader(body=None, *, header='import pickle\n', parameters='path', name='read_checkpoint'):
    body = body or 'with open(path, "rb") as handle:\n    return pickle.load(handle)\n'
    return header + f'def {name}({parameters}):\n' + textwrap.indent(body, '    ')


def collect(source, *, index=0, spend=None):
    tree = ast.parse(source)
    calls = sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and (isinstance(node.func, ast.Attribute) and node.func.attr == 'load'
                         or isinstance(node.func, ast.Name) and node.func.id == 'restore')),
                   key=lambda node: (node.lineno, node.col_offset))
    return analyze_deserialization_file_input(tree, calls[index], spend=spend)


def test_direct_file_binding_has_exact_locations_and_no_trust_or_runtime_claims():
    result = collect(loader())
    assert result['status'] == 'established'
    source, flow = result['facts']
    assert source == {
        'id': 'file_input_source', 'method': 'python_ast_file_binding', 'sources': [{
            'function': 'read_checkpoint', 'parameter': 'path', 'handle': 'handle', 'mode': 'rb',
            'function_span': [2, 0, 4, 34], 'parameter_span': [2, 20, 2, 24],
            'open_span': [3, 9, 3, 25], 'handle_span': [3, 29, 3, 35],
        }],
    }
    assert flow == {'id': 'local_input_flow', 'method': 'python_ast_file_flow', 'locations': [
        [2, 20, 2, 24], [3, 9, 3, 25], [3, 29, 3, 35], [4, 15, 4, 34],
    ]}
    serialized = json.dumps(result)
    assert all(term not in serialized for term in ('attacker', 'trusted', 'request_input_source',
                                                   'runtime_verified', 'file_format', 'reachable'))


@pytest.mark.parametrize('header, parameters, call', [
    ('import pickle as p\n', 'path', 'p.load(handle)'),
    ('from pickle import load as restore\n', 'path', 'restore(handle)'),
    ('import pickle\n', 'path, /', 'pickle.load(handle)'),
    ('import pickle\n', '*, path', 'pickle.load(handle)'),
    ('import pickle\n', 'path: str', 'pickle.load(handle)'),
])
def test_resolved_imports_and_explicit_parameters(header, parameters, call):
    source = loader(f'with open(path, mode="rb") as handle:\n    return {call}\n',
                    header=header, parameters=parameters)
    assert collect(source)['status'] == 'established'


@pytest.mark.parametrize('header, opener', [
    ('import pickle\nimport builtins\n', 'builtins.open'),
    ('import pickle\nimport builtins as b\n', 'b.open'),
    ('import pickle\nfrom builtins import open as file_open\n', 'file_open'),
    ('import pickle\nfrom builtins import open\n', 'open'),
])
def test_explicit_builtin_open_imports(header, opener):
    assert collect(loader(f'with {opener}(path, "rb") as handle:\n    return pickle.load(handle)\n',
                          header=header))['status'] == 'established'


def test_returning_format_branch_records_only_the_file_binding():
    # Mirrors both real checkpoint readers: the earlier arm reuses handle, uses
    # local imports and loops, then returns. No interpretation of its predicate.
    source = loader('''if is_other_format(path):
    from other_format import safe_open
    with safe_open(path) as handle:
        metadata = handle.metadata()
    values = {}
    for key, value in metadata.items():
        values[key] = value
    return values
with open(path, "rb") as handle:
    return pickle.load(handle)
''', header='import pickle\nSUFFIX = ".SPECIAL_PRIVATE_FORMAT"\n'
             'def is_other_format(path):\n    return path.endswith(SUFFIX)\n')
    result = collect(source)
    assert result['status'] == 'established'
    assert result['facts'][0]['sources'][0]['parameter'] == 'path'
    assert not any(term in json.dumps(result) for term in ('SPECIAL_PRIVATE_FORMAT', 'is_other_format', 'metadata'))


@pytest.mark.parametrize('body', [
    'path = replacement\nwith open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'if condition:\n    path = replacement\n    return None\n'
    'with open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'with open(path, "rb") as handle:\n    handle = replacement\n    return pickle.load(handle)\n',
    'with open(path, "rb") as handle:\n    observe(handle)\n    return pickle.load(handle)\n',
    'with open(path, "rb") as handle:\n    return pickle.load(other)\n',
    'with open(path, "rb") as path:\n    return pickle.load(path)\n',
    'with open(convert(path), "rb") as handle:\n    return pickle.load(handle)\n',
    'with open(path, "rb") as handle:\n    return wrapper(pickle.load(handle))\n',
    'with open(path, "rb") as handle:\n    return pickle.load(handle, encoding="bytes")\n',
    'with open(path, "rb") as handle:\n    return pickle.load(*handle)\n',
    'with open(path, "rb") as handle:\n    return pickle.load(file=handle)\n',
    'with open(path, "rb") as handle, guard():\n    return pickle.load(handle)\n',
    'if condition:\n    with open(path, "rb") as handle:\n        return pickle.load(handle)\n',
    'if condition:\n    observe(path)\nwith open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'if condition:\n    return None\nelse:\n    observe(path)\n'
    'with open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'observe(path)\nwith open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'return None\nwith open(path, "rb") as handle:\n    return pickle.load(handle)\n',
    'with open(path, "rb") as handle:\n    return pickle.load(handle)\npath = replacement\n',
    'with open(path, "rb") as handle:\n    return pickle.load(handle)\n'
    'def nested():\n    return None\n',
])
def test_unsupported_paths_do_not_manufacture_input_facts(body):
    result = collect(loader(body))
    assert result['status'] == 'unknown'
    assert result['facts'] == []


@pytest.mark.parametrize('opening', [
    'open(path)', 'open(path, "r")', 'open(path, "wb")', 'open(path, "rb+")',
    'open(path, mode)', 'open(path, "rb", opener=custom)', 'open(path, "rb", **options)',
    'open(file=path, mode="rb")', 'custom.open(path, "rb")', 'open("fixed.pkl", "rb")',
])
def test_only_supported_read_open_and_parameter_forms_are_established(opening):
    assert collect(loader(f'with {opening} as handle:\n    return pickle.load(handle)\n'))['facts'] == []


@pytest.mark.parametrize('extra', [
    'open = replacement\n',
    'def open(path, mode):\n    return replacement\n',
    'pickle = replacement\n',
    'pickle.load = replacement\n',
    'def change():\n    global open\n    open = replacement\n',
    'def change():\n    pickle.load = replacement\n',
    'def change():\n    pickle.__dict__["load"] = replacement\n',
    'def change():\n    setattr(pickle, "load", replacement)\n',
    'def change():\n    escape(pickle)\n',
    'def change():\n    alias = pickle.load\n',
    'def change():\n    escape(open)\n',
    'def change():\n    import pickle as another\n    escape(another)\n',
    'import builtins\ndef change():\n    builtins.open = replacement\n',
    'from builtins import exec as execute\ndef change():\n    execute("open = replacement")\n',
    'def change():\n    mutate(__builtins__)\n',
    'def change():\n    globals()["open"] = replacement\n',
    'def change():\n    read_checkpoint.__globals__["open"] = replacement\n',
    'def change():\n    frame.f_builtins["open"] = replacement\n',
    'import sys\ndef change():\n    sys.modules["builtins"].open = replacement\n',
    'import sys\ndef change():\n    sys.modules["pickle"].load = replacement\n',
    'from sys import modules as registry\ndef change():\n    registry["pickle"].load = replacement\n',
    'import sys\ndef change():\n    alias = sys\n    alias.modules["pickle"].load = replacement\n',
    'def change():\n    __import__("builtins").open = replacement\n',
    'import importlib\ndef change():\n    importlib.import_module("pickle").load = replacement\n',
    'from importlib import import_module as get_module\n'
    'def change():\n    get_module("pickle").load = replacement\n',
    'def change():\n    import sys as s\n    s.modules["builtins"].open = replacement\n',
    'def change():\n    from sys import modules as registry\n    registry["pickle"].load = replacement\n',
    'def change():\n    from importlib import import_module as get_module\n'
    '    get_module("pickle").load = replacement\n',
    'def change(default=mutate()):\n    pass\n',
    '@wrapper\ndef change():\n    pass\n',
    'from unknown import *\n',
    'change_environment()\n',
])
def test_namespace_rebinding_mutation_and_escape_revoke_file_provenance(extra):
    assert collect(loader() + extra)['facts'] == []


@pytest.mark.parametrize('mutation', [
    'read_checkpoint.__builtins__["open"] = replacement',
    'namespace = read_checkpoint.__builtins__\nnamespace["open"] = replacement',
    'mutate(read_checkpoint.__builtins__)',
])
def test_function_builtins_access_revokes_file_provenance(mutation):
    # The helper can change open before the otherwise supported file binding.
    # Parse this fixture only: never mutate the test runner's builtins.
    source = loader('if change():\n    return None\n'
                    'with open(path, "rb") as handle:\n    return pickle.load(handle)\n')
    source += 'def change():\n' + textwrap.indent(mutation + '\nreturn False\n', '    ')
    assert collect(source) == {
        'status': 'unknown', 'reason': 'file_binding_not_established', 'facts': [],
    }


@pytest.mark.parametrize('shadow', [
    'open = replacement', 'pickle = replacement', 'from custom import open',
    'try:\n    pass\nexcept Exception as open:\n    pass',
    'match value:\n    case pickle:\n        pass',
])
def test_local_shadowing_after_sink_still_blocks_static_import_resolution(shadow):
    assert collect(loader('with open(path, "rb") as handle:\n    return pickle.load(handle)\n'
                          + shadow + '\n'))['facts'] == []


@pytest.mark.parametrize('header', ['', 'import custom as pickle\n', 'from io import open\nimport pickle\n'])
def test_custom_or_unresolved_imports_are_not_trusted_by_spelling(header):
    assert collect(loader(header=header))['facts'] == []


def test_nested_and_decorated_functions_are_unsupported():
    assert collect('import pickle\ndef outer():\n' + textwrap.indent(loader(header=''), '    '))['facts'] == []
    assert collect(loader(header='import pickle\n@wrapper\n'))['facts'] == []
    assert collect('import pickle\nclass Reader:\n' + textwrap.indent(loader(header=''), '    '))['facts'] == []


def test_selected_call_cannot_borrow_a_different_functions_binding():
    source = loader() + loader(name='read_other', parameters='other', header='')
    assert collect(source, index=0)['status'] == 'established'
    assert collect(source, index=1)['facts'] == []
    tree = ast.parse(loader())
    foreign = next(node for node in ast.walk(ast.parse(loader()))
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute))
    assert analyze_deserialization_file_input(tree, foreign) == {
        'status': 'unknown', 'reason': 'sink_not_in_tree', 'facts': [],
    }


def test_source_is_never_imported_or_executed_and_ast_is_unchanged():
    tree = ast.parse(loader(header='import module_that_does_not_exist\nimport pickle\n'))
    sink = next(node for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute))
    before = ast.dump(tree, include_attributes=True)
    first = analyze_deserialization_file_input(tree, sink)
    assert first['status'] == 'established'
    assert analyze_deserialization_file_input(tree, sink) == first
    assert ast.dump(tree, include_attributes=True) == before


def test_shared_budget_is_charged_and_its_exception_propagates():
    spent = 0

    class Exhausted(RuntimeError):
        pass

    def spend(amount=1):
        nonlocal spent
        spent += amount
        if spent > 50:
            raise Exhausted('shared budget reached')

    with pytest.raises(Exhausted, match='shared budget reached'):
        collect(loader(), spend=spend)
    assert spent > 50


@pytest.mark.parametrize('source', [
    loader() + 'padding = ' + '+' * 110 + '1\n',
    loader() + '\n'.join(f'padding_{index} = 1' for index in range(6_000)),
])
def test_source_depth_and_node_count_are_bounded(source):
    assert collect(source) == {'status': 'unknown', 'reason': 'input_evidence_limit', 'facts': []}


def test_work_limit_and_identifier_limit_are_bounded(monkeypatch):
    import app.scan.deserialization_file_evidence as module

    assert collect(loader(name='x' * 129))['facts'] == []
    monkeypatch.setattr(module, '_MAX_WORK', 40)
    assert collect(loader()) == {'status': 'unknown', 'reason': 'input_evidence_limit', 'facts': []}


def test_invalid_ast_types_are_rejected():
    assert analyze_deserialization_file_input(None, None) == {
        'status': 'unknown', 'reason': 'invalid_input_ast', 'facts': [],
    }
