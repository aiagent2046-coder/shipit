"""Bounded cost-related source observations, never cost or concurrency verdicts.

Resolve one direct named TypeScript import and record literal slice bounds in
its returned expression. Record query ordering and externally refreshed Python
loop state separately. Uploaded source is parsed, never imported or executed.
"""
from collections import Counter
import ast
import json
import math
import re
import posixpath
import stat
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan.react_async_context import (
    _bindings, _children, _definitions, _line, _name, _text, _walk,
)
from app.scan.secrets import is_non_production_path

MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 4_000_000
MAX_FILES = 200
MAX_NODES = 80_000
MAX_RECORDS = 64
MAX_CHECKS = 12
MAX_FUNCTIONS = 128
MAX_FUNCTION_WORK = 160_000
SCOPE = (
    "Cost-related source syntax only. One direct named import, literal slice bounds in a helper's "
    "returned expression, awaited database call order, returned-id branch syntax, and Python loops "
    "refreshing their length condition from another call. Only local relative imports or explicit "
    "nearest tsconfig.json @/* paths are resolved. Source order is not execution order across callbacks. "
    "Runtime bindings, built-in methods, transactions, database guarantees, retries, total prompt size, "
    "prices and duplicate charges are not verified. Request roles and conditional retry gates are source "
    "observations; correcting a public arithmetic expression does not establish a call-count bound. "
    "Missing observations do not prove missing limits. "
    "String values redacted; tests and vendor files excluded."
)


def _literal(node):
    text = _text(node)
    return text[1:-1] if node and node.type == 'string' and '\\' not in text and len(text) <= 512 else None


def _number(node):
    text = _text(node)
    return int(text) if node and node.type == 'number' and text.isascii() and text.isdigit() and len(text) < 8 else None


def _member_call(node, method):
    if node.type != 'call_expression' or node.child_by_field_name('optional_chain'):
        return False
    fn = node.child_by_field_name('function')
    return bool(fn and fn.type == 'member_expression' and not fn.child_by_field_name('optional_chain')
                and _text(fn.child_by_field_name('property')) == method)


def _consts(root, bindings):
    values = {}
    for stmt in _children(root):
        if stmt.type == 'export_statement':
            stmt = stmt.child_by_field_name('declaration')
        if not stmt or stmt.type != 'lexical_declaration' or not any(c.type == 'const' for c in stmt.children):
            continue
        for dec in _children(stmt):
            name = _name(dec.child_by_field_name('name'))
            value = _number(dec.child_by_field_name('value'))
            if name and value is not None and bindings[name] == 1:
                values[name] = value
    return values


def _resolve(path, spec, sources, configs):
    if spec.startswith(('./', '../')):
        stem = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
    elif spec.startswith('@/'):
        parent = posixpath.dirname(path)
        while True:
            config = posixpath.join(parent, 'tsconfig.json')
            if config in configs:
                if 'extends' in configs[config]:
                    return None
                options = configs[config].get('compilerOptions', {})
                paths = options.get('paths', {})
                if not isinstance(paths, dict):
                    return None
                targets = paths.get('@/*', [])
                if (not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str)
                        or not targets[0].endswith('/*') or targets[0].count('*') != 1):
                    return None
                base = options.get('baseUrl', '.')
                if not isinstance(base, str):
                    return None
                stem = posixpath.normpath(posixpath.join(parent, base, targets[0][:-1] + spec[2:]))
                break
            if not parent:
                return None
            parent = posixpath.dirname(parent)
    else:
        return None
    if stem.startswith(('../', '/')) or stem == '..':
        return None
    candidates = [stem] if stem.endswith(('.ts', '.tsx', '.js', '.jsx')) else [
        stem + ext for ext in ('.ts', '.tsx', '.js', '.jsx', '/index.ts', '/index.tsx')]
    found = [c for c in candidates if c in sources]
    return found[0] if len(found) == 1 else None


def _imports(root, bindings, path, sources, configs, limits):
    candidates, names = {}, Counter()
    for stmt in _children(root):
        if stmt.type != 'import_statement' or any(c.type == 'type' for c in stmt.children):
            continue
        spec = _literal(stmt.child_by_field_name('source'))
        target = _resolve(path, spec, sources, configs) if spec else None
        for n in _walk(stmt):
            if n.type == 'import_specifier':
                local = _name(n.child_by_field_name('alias') or n.child_by_field_name('name'))
                names[local] += 1
                if target and not any(c.type == 'type' for c in n.children):
                    candidates[local] = (target, _name(n.child_by_field_name('name')), _line(stmt))
            elif n.type in {'import_clause', 'namespace_import'}:
                for child in _children(n):
                    if child.type == 'identifier':
                        names[_name(child)] += 1
    result = {}
    for name, candidate in candidates.items():
        if name and not bindings[name] and names[name] == 1:
            result[name] = candidate
        else:
            limits.add('ambiguous_import_binding')
    return result


def _helper_slices(root, exported, argc, nodes, limits):
    bindings = _bindings(nodes)
    definitions = [(name, fn) for name, fn in _definitions(root) if name == exported
                   and fn.parent.type == 'export_statement'
                   and not any(c.type == 'default' for c in fn.parent.children)]
    if len(definitions) != 1 or bindings[exported] != 1:
        return None
    _, fn = definitions[0]
    fn_nodes = list(_walk(fn))
    local_bindings = _bindings(fn_nodes)
    params = _children(fn.child_by_field_name('parameters'))
    # No options object/spread values are evaluated. Only one supplied argument
    # and an omitted second parameter with a literal empty-object default.
    if argc != 1 or len(params) not in {1, 2}:
        return None
    defaults = set()
    if len(params) == 2:
        value = params[1].child_by_field_name('value')
        name = _name(params[1].child_by_field_name('pattern'))
        if not value or value.type != 'object' or _children(value) or not name or local_bindings[name] != 1:
            return None
        pattern = params[1].child_by_field_name('pattern')
        for use in fn_nodes:
            if use == pattern or use.type not in {'identifier', 'shorthand_property_identifier'} or _text(use) != name:
                continue
            member = use.parent
            fallback = member.parent
            # Omitted options may be read only as direct nullish defaults. An
            # alias, argument, shorthand, method call or nested member escapes
            # the empty-object premise; do not evaluate effects or follow aliases.
            if not (member.type == 'member_expression' and member.child_by_field_name('object') == use
                    and fallback.type == 'binary_expression' and fallback.child_by_field_name('left') == member
                    and _text(fallback.child_by_field_name('operator')) == '??'):
                limits.add('helper_options_binding_escaped')
                return None
        defaults.add(name)
    values = {k: v for k, v in _consts(root, bindings).items() if not local_bindings[k]}
    body = fn.child_by_field_name('body')
    values.update(_consts(body, local_bindings))
    default_values = {}
    for stmt in _children(body):
        if stmt.type != 'lexical_declaration' or not any(c.type == 'const' for c in stmt.children):
            continue
        for dec in _children(stmt):
            name, expr = _name(dec.child_by_field_name('name')), dec.child_by_field_name('value')
            if not name or local_bindings[name] != 1 or not expr or expr.type != 'binary_expression':
                continue
            left, right = expr.child_by_field_name('left'), expr.child_by_field_name('right')
            if (_text(expr.child_by_field_name('operator')) == '??' and left.type == 'member_expression'
                    and _name(left.child_by_field_name('object')) in defaults):
                value = _number(right) if _number(right) is not None else values.get(_name(right))
                if value is not None:
                    default_values[name] = value
    slices = []
    for ret in _children(body):
        if ret.type != 'return_statement':
            continue
        parts = _children(ret)
        if len(parts) != 1 or not any(_member_call(parts[0], m) for m in ('slice', 'map', 'filter')):
            continue
        for node in _walk(ret):
            if not _member_call(node, 'slice'):
                continue
            args = _children(node.child_by_field_name('arguments'))
            if len(args) != 2 or _number(args[0]) != 0:
                continue
            value = _number(args[1])
            if value is None:
                value = values.get(_name(args[1]), default_values.get(_name(args[1])))
            if value is not None:
                method = node.child_by_field_name('function').child_by_field_name('property')
                slices.append({'line': _line(method), 'end': value,
                               'uses_omitted_options_default': _name(args[1]) in default_values})
    if len(slices) > MAX_CHECKS:
        limits.add('helper_slice_limit')
    return (fn, slices[:MAX_CHECKS]) if slices else None


def _option(obj, key, expected):
    if not obj or obj.type != 'object' or any(c.type != 'pair' for c in _children(obj)):
        return False
    matching = [c.child_by_field_name('value') for c in _children(obj)
                if _text(c.child_by_field_name('key')) == key]
    return len(matching) == 1 and _text(matching[0]) == expected


def _query(awaited):
    parts = _children(awaited)
    node = parts[0] if len(parts) == 1 else None
    methods, table = [], None
    while node and node.type == 'call_expression':
        fn = node.child_by_field_name('function')
        if not fn or fn.type != 'member_expression' or fn.child_by_field_name('optional_chain'):
            break
        method = _text(fn.child_by_field_name('property'))
        args = _children(node.child_by_field_name('arguments'))
        methods.append((method, args))
        if method == 'from' and len(args) == 1:
            table = _literal(args[0])
        node = fn.child_by_field_name('object')
    return table, methods


def _result_binding(awaited, property_name):
    dec = awaited.parent
    if dec.type != 'variable_declarator':
        return ''
    pattern = dec.child_by_field_name('name')
    if not pattern or pattern.type != 'object_pattern':
        return ''
    for item in _children(pattern):
        if item.type == 'shorthand_property_identifier_pattern' and _text(item) == property_name:
            return _text(item)
        if item.type == 'pair_pattern' and _text(item.child_by_field_name('key')) == property_name:
            return _name(item.child_by_field_name('value'))
    return ''


def _query_checks(fn, nodes, limits):
    checks, queries = [], []
    bindings = _bindings(nodes)
    for node in nodes:
        if node.type == 'await_expression':
            table, methods = _query(node)
            if table:
                queries.append((node, table, methods))
                if len(queries) >= 64:
                    limits.add('query_limit_reached')
                    break
    for written, table, methods in queries:
        names = [m for m, _ in methods]
        if 'insert' in names:
            for counted, other, selections in queries:
                count = _result_binding(counted, 'count')
                if other != table or counted.start_byte <= written.end_byte or not count or bindings[count] != 1:
                    continue
                if not any(m == 'select' and len(a) >= 2 and _option(a[1], 'count', "'exact'")
                           or m == 'select' and len(a) >= 2 and _option(a[1], 'count', '"exact"')
                           for m, a in selections):
                    continue
                guards = [n for n in nodes if n.type == 'binary_expression'
                          and n.start_byte > counted.end_byte
                          and _name(n.child_by_field_name('left')) == count
                          and _text(n.child_by_field_name('operator')) == '<='
                          and _number(n.child_by_field_name('right')) == 1]
                if guards:
                    checks.append({'kind': 'awaited_insert_before_count', 'result': 'observed',
                        'insert_line': _line(written), 'count_line': _line(counted),
                        'count_le_one_line': _line(guards[0]),
                        'summary': f'Awaited insert at line {_line(written)} precedes exact-count source syntax '
                        f'at line {_line(counted)} and count <= 1 at line {_line(guards[0])}. '
                        'This order does not demonstrate duplicate paid calls.',
                        'detail': 'An awaited insert appears before an exact-count request for the same table '
                        'literal, followed by a same-binding count <= 1 comparison. Callback execution, '
                        'successful commits, concurrent interleavings and duplicate paid calls are not established.'})
        upsert = next((a for m, a in methods if m == 'upsert'), [])
        result = _result_binding(written, 'data')
        if (len(upsert) != 2 or not _option(upsert[1], 'ignoreDuplicates', 'true')
                or not result or bindings[result] != 1):
            continue
        for branch in nodes:
            if branch.type != 'if_statement' or branch.start_byte <= written.end_byte:
                continue
            cond = _children(branch.child_by_field_name('condition'))
            member = cond[0] if len(cond) == 1 else None
            if (not member or member.type != 'member_expression'
                    or _name(member.child_by_field_name('object')) != result
                    or _text(member.child_by_field_name('property')) != 'id'):
                continue
            calls = [n for n in _walk(branch.child_by_field_name('consequence')) if n.type == 'call_expression'
                     and _name(n.child_by_field_name('function'))]
            if calls:
                checks.append({'kind': 'upsert_returned_id_branch', 'result': 'observed',
                    'upsert_line': _line(written), 'guard_line': _line(branch), 'call_line': _line(calls[0]),
                    'summary': f'Upsert at line {_line(written)} specifies ignoreDuplicates: true; '
                    f'a returned-id branch at line {_line(branch)} contains a call at line {_line(calls[0])}. '
                    'Database guarantees and duplicate-call prevention remain unverified.',
                    'detail': 'Awaited upsert syntax includes ignoreDuplicates: true. A subsequent branch checks '
                    'the returned data binding id before a direct function call. Conflict keys, schema, SDK '
                    'semantics, callback effects and prevention of duplicate paid calls are not verified.'})
    return checks[:MAX_CHECKS]


def _request_roles(nodes):
    """Public endpoint/method syntax, not pricing or actual request execution."""
    checks = []
    for node in nodes:
        if node.type != 'call_expression' or _name(node.child_by_field_name('function')) not in {
                'fetch', 'fetchWithTimeout'}:
            continue
        args = _children(node.child_by_field_name('arguments'))
        if not args or args[0].type not in {'string', 'template_string'}:
            continue
        parts = _children(args[0])
        prefix = _text(parts[0]) if parts and parts[0].type == 'string_fragment' else ''
        role = ('model_metadata' if prefix.startswith('https://api.replicate.com/v1/models/') else
                'prediction' if re.match(r'https://api\.replicate\.com/v1/predictions(?:/|$)', prefix) else None)
        if not role:
            continue
        options = args[1] if len(args) == 2 else None
        method = 'GET' if len(args) == 1 else None
        if options and options.type == 'object' and all(p.type == 'pair' for p in _children(options)):
            methods = [p.child_by_field_name('value') for p in _children(options)
                       if _text(p.child_by_field_name('key')) == 'method']
            if not methods:
                method = 'GET'
            elif len(methods) == 1 and _literal(methods[0]) in {'GET', 'POST'}:
                method = _literal(methods[0])
        if method is None or (role == 'model_metadata' and method != 'GET'):
            continue
        operation = ('metadata GET' if role == 'model_metadata' else
                     'prediction creation POST' if method == 'POST' else 'prediction status GET')
        checks.append({'kind': 'request_operation_role', 'result': 'observed', 'line': _line(node),
                       'operation': operation,
                       'summary': f'Line {_line(node)} contains {operation} syntax. '
                       'HTTP request count is not a count of billable inference runs.',
                       'detail': 'Public endpoint and explicit/default method syntax only. Callee bindings, '
                       'request execution, provider pricing, latency and charges are not verified.'})
    return checks[:MAX_CHECKS]


def _retry_checks(nodes):
    """Record a conditional retry gate, without evaluating arbitrary errors."""
    from app.scan import guard_context as g
    checks = []
    for handler in nodes:
        if handler.type != 'catch_clause':
            continue
        own = list(g._walk(handler.child_by_field_name('body'), g._SKIP))
        constants = g._consts(handler.child_by_field_name('body'))
        for branch in own:
            if branch.type != 'if_statement':
                continue
            terms = g._or_terms(branch.child_by_field_name('condition'))
            flags = [g._name(t.child_by_field_name('argument')) for t in terms
                     if t and t.type == 'unary_expression' and g._text(t.child_by_field_name('operator')) == '!']
            for flag in flags:
                dec = constants.get(flag)
                if not dec or dec.end_byte >= branch.start_byte:
                    continue
                dependencies = g._or_terms(dec.child_by_field_name('value'))
                if len(dependencies) < 2 or not all(g._name(n) in constants for n in dependencies):
                    continue
                body = g._children(branch.child_by_field_name('consequence'))
                if not body or body[-1].type != 'throw_statement':
                    continue
                # A terminal throw branch is evidence that retry is conditional.
                # Dynamic error messages may match abort detection even for Error.
                checks.append({'kind': 'conditional_retry_gate', 'result': 'observed',
                    'line': g._line(branch),
                    'summary': f'Catch at line {g._line(handler)} has a retry predicate; '
                    f'a negated-predicate branch at line {g._line(branch)} ends by throwing. '
                    'A thrown error does not by itself establish a full-flow retry.',
                    'detail': 'Named local predicates and a terminal throw are present. Check the actual error '
                    'type, status and message against every predicate, including abort-message matching. '
                    'Retry count, callback execution and duplicate paid work remain unverified.'})
    return checks[:MAX_CHECKS]


def arithmetic_context(finding):
    """Evaluate a tiny public arithmetic form, never eval model or source code."""
    text = str(finding.get('explanation', ''))[:16000]
    pattern = r'C\((\d{1,3}),\s*(\d{1,3})\)\s*[×*]\s*(\d{1,3})(?: teams)?\s*[×*]\s*(\d{1,3})(?: turns)?\s*=\s*(\d{1,9})'
    result = []
    for match in re.finditer(pattern, text):
        n, k, groups, turns, claimed = map(int, match.groups())
        if not 0 <= k <= n <= 100 or groups > 100 or turns > 100:
            continue
        value = math.comb(n, k) * groups * turns
        if value > 1_000_000_000 or value == claimed:
            continue
        result.append({'kind': 'cost_context', 'result': 'observed', 'checks': [{
            'kind': 'arithmetic_mismatch', 'result': 'contradicted', 'claimed': claimed, 'computed': value,
            'summary': f'The stated C({n},{k}) × {groups} × {turns} equals {value}, not {claimed}. '
            'This corrects only arithmetic; it does not establish a maximum call count or billable cost.'}]})
        if len(result) >= 2:
            break
    return result


def _python_records(data, path, limits):
    try:
        tree = ast.parse(data)
        nodes = list(ast.walk(tree))
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        limits.add('unparseable_python')
        return [], False
    if len(nodes) > MAX_NODES:
        limits.add('node_budget_reached')
        return [], False
    records = []
    for loop in nodes:
        test = loop.test if isinstance(loop, ast.While) else None
        if not (isinstance(test, ast.Compare) and isinstance(test.left, ast.Call)
                and isinstance(test.left.func, ast.Name) and test.left.func.id == 'len'
                and len(test.left.args) == 1 and isinstance(test.left.args[0], ast.Name)):
            continue
        name = test.left.args[0].id
        refreshes = [n for n in loop.body if isinstance(n, ast.Assign) and len(n.targets) == 1
                     and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name
                     and isinstance(n.value, ast.Call)]
        ignored = [n for n in loop.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
        if refreshes and ignored:
            called = {n.func.id for n in ast.walk(loop) if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Name)}
            records.append({'file': path, 'line': loop.lineno, 'line_end': loop.end_lineno,
                'scope': '<while>',
                'helper_candidates': [{'line': fn.lineno, 'line_end': fn.end_lineno}
                    for fn in tree.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and fn.name in called][:MAX_CHECKS],
                'checks': [{'kind': 'python_external_loop_progress', 'result': 'observed',
                    'refresh_lines': [n.lineno for n in refreshes[:MAX_CHECKS]],
                    'ignored_call_result_lines': [n.lineno for n in ignored[:MAX_CHECKS]],
                    'summary': f'While condition at line {loop.lineno} depends on externally refreshed length. '
                    f'Standalone call results at lines {", ".join(str(n.lineno) for n in ignored[:MAX_CHECKS])} '
                    'are unused; progress and financial consequences remain unverified.',
                    'detail': 'A while condition uses len of a variable refreshed by a direct call in the loop. '
                    'Listed standalone calls have unused return values. Loop progress, call effects and '
                    'built-in bindings are not verified; this alone does not establish an infinite loop or charges.'}]})
            if len(records) > MAX_RECORDS:
                limits.add('record_limit_reached')
                return records[:MAX_RECORDS], True
    return records, True


def collect_cost_context(fileobj):
    records, limits, sources, configs = [], set(), {}, {}
    attempted = used = excluded = python_parsed = 0
    with zipfile.ZipFile(fileobj) as archive:
        infos = archive.infolist()
        counts = Counter(i.filename for i in infos)
        for info in sorted(infos, key=lambda i: i.filename):
            path = info.filename
            if info.is_dir() or not (path.endswith(('.py', '.ts', '.tsx', '.js', '.jsx'))
                                     or path == 'tsconfig.json' or path.endswith('/tsconfig.json')):
                continue
            if (stat.S_ISLNK(info.external_attr >> 16) or is_non_production_path(path)
                    or any(p in path.split('/') for p in ('vendor', 'node_modules', '.venv', 'venv'))):
                excluded += 1
                continue
            if counts[path] != 1 or posixpath.normpath(path) != path or path.startswith(('/', '../')):
                limits.add('ambiguous_archive_path')
                continue
            if attempted >= MAX_FILES or used + info.file_size > MAX_TOTAL_BYTES:
                limits.add('scan_budget_reached')
                break
            if info.file_size > MAX_FILE_BYTES or len(path) > 512:
                limits.add('file_size_or_path_limit')
                continue
            attempted += 1
            used += info.file_size
            data = archive.read(info)
            if path.endswith('tsconfig.json'):
                configs[path] = {}  # An unreadable nearer config must not fall back to a parent alias.
                try:
                    config = json.loads(data)
                    if isinstance(config, dict) and isinstance(config.get('compilerOptions', {}), dict):
                        configs[path] = config
                except (ValueError, UnicodeError, RecursionError):
                    limits.add('unsupported_tsconfig')
                continue
            if path.endswith('.py'):
                found, parsed = _python_records(data, path, limits)
                python_parsed += int(parsed)
                records.extend(found)
                if len(records) > MAX_RECORDS:
                    limits.add('record_limit_reached')
                    records = records[:MAX_RECORDS]
                continue
            try:
                data.decode('utf-8', errors='strict')
            except UnicodeError:
                limits.add('invalid_utf8_typescript')
                continue
            parser = Parser(Language(tree_sitter_typescript.language_tsx()
                            if path.endswith(('.tsx', '.jsx')) else tree_sitter_typescript.language_typescript()))
            root = parser.parse(data).root_node
            if root.has_error:
                limits.add('unparseable_typescript')
                continue
            nodes = []
            for node in _walk(root):
                nodes.append(node)
                if len(nodes) > MAX_NODES:
                    break
            if len(nodes) > MAX_NODES:
                limits.add('node_budget_reached')
                continue
            sources[path] = (root, nodes)
    helper_cache = {}
    for path, (root, nodes) in sources.items():
        imports = _imports(root, _bindings(nodes), path, sources, configs, limits)
        local_helpers, function_nodes = {}, {}
        bindings = _bindings(nodes)
        definitions = list(_definitions(root))
        if len(definitions) > MAX_FUNCTIONS:
            limits.add('function_limit_reached')
            definitions = definitions[:MAX_FUNCTIONS]
        work = 0
        for name, definition in definitions:
            helper_nodes = list(_walk(definition))
            work += len(helper_nodes)
            if work > MAX_FUNCTION_WORK:
                limits.add('function_work_limit_reached')
                break
            function_nodes[(definition.start_byte, definition.end_byte)] = helper_nodes
            if bindings[name] == 1:
                local_helpers[name] = _request_roles(helper_nodes) + _retry_checks(helper_nodes)
        for scope, fn in definitions:
            if not scope or (fn.start_byte, fn.end_byte) not in function_nodes:
                continue
            fn_nodes = function_nodes[(fn.start_byte, fn.end_byte)]
            checks = _query_checks(fn, fn_nodes, limits)
            checks.extend(local_helpers.get(scope, []))
            for call in fn_nodes:
                if call.type == 'call_expression':
                    for check in local_helpers.get(_name(call.child_by_field_name('function')), []):
                        linked = {**check, 'helper_call_line': _line(call),
                                  'detail': check['detail'] + ' Same-file named-call candidate only; '
                                  'runtime binding and execution order are not established.'}
                        if len(checks) < MAX_CHECKS:
                            checks.append(linked)
            for call in fn_nodes:
                if call.type != 'call_expression' or _name(call.child_by_field_name('function')) not in imports:
                    continue
                target, exported, import_line = imports[_name(call.child_by_field_name('function'))]
                args = _children(call.child_by_field_name('arguments'))
                if any(a.type == 'spread_element' for a in args):
                    continue
                key = (target, exported, len(args))
                if key not in helper_cache:
                    helper_cache[key] = _helper_slices(sources[target][0], exported, key[2], sources[target][1], limits)
                helper = helper_cache[key]
                if helper:
                    definition, slices = helper
                    checks.append({'kind': 'imported_helper_slice_bounds', 'result': 'observed',
                        'line': _line(call), 'import_line': import_line, 'helper_file': target,
                        'helper_line': _line(definition), 'helper_scope': exported, 'slices': slices,
                        'summary': f'Call at line {_line(call)} links to a helper whose returned expression '
                        'contains slice bounds: ' + ', '.join(
                            f'0..{s["end"]} at helper line {s["line"]}' for s in slices) +
                        '. These are source bounds, not proof of total prompt size or cost.',
                        'detail': 'This direct named import resolves to a helper with literal numeric slice '
                        'bounds in its returned expression. Omitted options defaults are listed separately. '
                        'Other prompt inputs, appended suffixes, transformations, runtime method bindings and '
                        'the total size or cost of a model request are not verified.'})
                    if len(checks) >= MAX_CHECKS:
                        limits.add('checks_per_function_limit')
                        break
            if checks:
                records.append({'file': path, 'line': _line(fn), 'line_end': fn.end_point[0] + 1,
                                'scope': scope, 'checks': checks[:MAX_CHECKS]})
            if len(records) >= MAX_RECORDS:
                limits.add('record_limit_reached')
                break
        if len(records) >= MAX_RECORDS:
            break
    return {'records': records[:MAX_RECORDS], 'scope': SCOPE, 'limitations': sorted(limits),
            'parsed_files': len(sources) + python_parsed, 'attempted_files': attempted, 'excluded_files': excluded}


def cost_finding_context(finding, facts):
    start, end = finding.get('line_start'), finding.get('line_end')
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        return []
    contexts = [{'kind': 'cost_context', 'result': 'observed', **record}
                for record in (facts.get('cost_context') or {}).get('records', [])
                if record['file'] == finding.get('file') and (
                    record['line'] <= start <= end <= record['line_end'] or
                    any(c['line'] <= start <= end <= c['line_end']
                        for c in record.get('helper_candidates', [])))][:4]
    return contexts + arithmetic_context(finding)
