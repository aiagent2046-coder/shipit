"""Secret-named assignments containing a non-cryptographic random call.

Python AST requires an unambiguous local/inherited random import. Rebinding,
parameters and member replacement invalidate that provenance. JS/TS syntax
recognizes calls to an unshadowed Math.random, including template substitutions,
and resolves exactly one helper hop: a name declared once as a function whose
single return draws Math.random is itself a draw at call sites inside its
declaring scope (function declarations may be hoisted; declarators must
precede the call). Parameters, reassignment, conditional or multiple returns,
nested helper chains, Python helpers, dynamic aliases and cross-file
provenance invalidate that hop. Comments and literal text never count as draws.
No uploaded source is executed.
"""
from __future__ import annotations

import ast
import zipfile

from app.scan.rule_coverage import remaining_findings
from collections import Counter
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage
from app.scan.xss import _nodes, _parser, _text

RULE_ID = "insecure-randomness"
_FILE_SUFFIXES = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_NODES = 20_000
_MAX_DEPTH = 100
_SECRET_WORDS = (
    "token", "secret", "password", "passwd", "passcode", "otp", "reset", "recovery", "nonce",
    "salt", "credential", "apikey", "api_key", "confirmation", "verification",
)
_METHODS = {"random", "randint", "randrange", "choice", "getrandbits", "uniform", "sample"}
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _secret(name):
    return any(word in name.lower() for word in _SECRET_WORDS)


def _ast_nodes(tree):
    pending, nodes = [(tree, 0)], []
    while pending:
        node, depth = pending.pop()
        if len(nodes) >= _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError("syntax_limit")
        nodes.append(node)
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return nodes


def _target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for child in target.elts for name in _target_names(child)]
    return []


def _qualified(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, bindings)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _python_draw(value, bindings):
    if value is None or isinstance(value, _SCOPES):
        return False
    if isinstance(value, _COMPREHENSIONS):
        local = bindings.copy()
        for gen in value.generators:
            if _python_draw(gen.iter, local):
                return True
            for name in _target_names(gen.target):
                local.pop(name, None)
            if any(_python_draw(condition, local) for condition in gen.ifs):
                return True
        values = [value.key, value.value] if isinstance(value, ast.DictComp) else [value.elt]
        return any(_python_draw(child, local) for child in values)
    if isinstance(value, ast.Call) and _qualified(value.func, bindings) in {
        f"random.{method}" for method in _METHODS
    }:
        return True
    return any(_python_draw(child, bindings) for child in ast.iter_child_nodes(value))


def _python_evidence(text):
    tree = ast.parse(text)
    _ast_nodes(tree)
    found = []

    def scope(body, inherited, parameters=(), method_globals=None):
        counts, imports, imports_at, nodes, nested = Counter(parameters), {}, {}, [], []
        pending = list(body)
        while pending:
            node = pending.pop()
            if isinstance(node, _SCOPES):
                if not isinstance(node, ast.Lambda):
                    counts[node.name] += 1
                    nested.append(node)
                continue
            nodes.append(node)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    counts[name] += 1
                    if alias.name == "random":
                        imports[name], imports_at[name] = "random", (node.lineno, node.col_offset)
            elif isinstance(node, ast.ImportFrom):
                if any(alias.name == "*" for alias in node.names):
                    # Unknown star exports can shadow an imported source.
                    return
                for alias in node.names:
                    name = alias.asname or alias.name
                    counts[name] += 1
                    if node.module == "random" and not node.level:
                        imports[name], imports_at[name] = f"random.{alias.name}", (node.lineno, node.col_offset)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                counts[node.id] += 1
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                counts.update(node.names)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                counts[node.name] += 1
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                counts[node.name] += 1
            elif isinstance(node, ast.MatchMapping) and node.rest:
                counts[node.rest] += 1
            pending.extend(ast.iter_child_nodes(node))
        bindings = {name: origin for name, origin in inherited.items() if counts[name] == 0}
        bindings.update({name: origin for name, origin in imports.items() if counts[name] == 1})
        # Conditional imports are unresolved rather than treated as guaranteed.
        for node in nodes:
            if isinstance(node, (ast.If, ast.Try, ast.TryStar, ast.For, ast.While, ast.Match)):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        for alias in child.names:
                            bindings.pop(alias.asname or alias.name.split(".")[0], None)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                base = node
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name) and base.id in bindings:
                    origin = bindings[base.id]
                    bindings = {name: value for name, value in bindings.items()
                                if value != origin and not value.startswith(origin + ".")}
        for node in nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            local = {name: value for name, value in bindings.items()
                     if name not in imports_at or imports_at[name] < (node.lineno, node.col_offset)}
            if _python_draw(node.value, local):
                for target in targets:
                    for name in _target_names(target):
                        if _secret(name):
                            found.append((node.lineno, name))
        for node in nested:
            if isinstance(node, ast.ClassDef):
                # Class bodies execute assignments, but class namespace bindings
                # are not lexical globals for methods or a nested class body.
                class_globals = method_globals if method_globals is not None else bindings
                scope(node.body, class_globals, method_globals=class_globals)
            else:
                args = node.args
                parameters = [arg.arg for arg in (
                    *args.posonlyargs, *args.args, *args.kwonlyargs,
                    *([args.vararg] if args.vararg else []),
                    *([args.kwarg] if args.kwarg else []))]
                scope(node.body, method_globals if method_globals is not None else bindings, parameters)

    scope(tree.body, {})
    return sorted(set(found))


def _plain_draw(value):
    """A Math.random call anywhere in the expression, without helper hops."""
    if value is None or value.type in {"arrow_function", "function_expression", "function_declaration"}:
        return False
    if value.type == "call_expression":
        callee = value.child_by_field_name("function")
        if callee is not None and callee.type == "member_expression":
            if (_text(callee.child_by_field_name("object")) == "Math" and
                    _text(callee.child_by_field_name("property")) == "random"):
                return True
    return any(_plain_draw(child) for child in value.named_children)


def _return_draws(body):
    """A body whose single statement is a return of a Math.random draw."""
    if body is None:
        return False
    if body.type != "statement_block":
        return _plain_draw(body)  # arrow function with an expression body
    statements = [child for child in body.named_children if child.type != "comment"]
    if len(statements) != 1 or statements[0].type != "return_statement":
        return False
    values = [child for child in statements[0].named_children if child.type != "comment"]
    return len(values) == 1 and _plain_draw(values[0])


def _scope_of(node):
    """The scope a declaration lives in; an export statement is transparent."""
    scope = node.parent
    if scope is not None and scope.type == "export_statement":
        scope = scope.parent
    return scope


def _helpers(nodes):
    """Names proven to be functions whose only return is a Math.random draw.

    One hop, lexical: a name qualifies when it is declared exactly once -- a
    function declaration, or a declarator bound to an arrow/function expression
    -- is never a parameter, catch, loop, class or import binding, is never
    reassigned, and its body has a single return drawing Math.random. Returns
    name -> (declaring scope, order anchor); the anchor is None for hoisted
    function declarations and the declarator otherwise. Helpers calling other
    helpers stay unresolved: exactly one hop is supported.
    """
    declared, invalid = {}, set()
    for node in nodes:
        if node.type in {"function_declaration", "variable_declarator"}:
            name = node.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                key = _text(name)
                if key in declared:
                    invalid.add(key)
                declared[key] = node
            elif name is not None:
                invalid.update(_text(n) for n in _nodes(name)
                               if n.type in {"identifier", "shorthand_property_identifier_pattern"})
        elif node.type in {"formal_parameters", "import_clause", "catch_clause"}:
            invalid.update(_text(n) for n in _nodes(node) if n.type == "identifier")
        elif node.type == "for_in_statement":
            target = node.child_by_field_name("left")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target)
                               if n.type in {"identifier", "shorthand_property_identifier_pattern"})
        elif node.type == "arrow_function":
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                invalid.add(_text(parameter))
        elif node.type == "class_declaration":
            invalid.add(_text(node.child_by_field_name("name")))
        elif node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target) if n.type == "identifier")
    helpers = {}
    for name, declaration in declared.items():
        if name in invalid:
            continue
        if declaration.type == "function_declaration":
            if _return_draws(declaration.child_by_field_name("body")):
                helpers[name] = (_scope_of(declaration), None)
        else:
            value = declaration.child_by_field_name("value")
            if (value is not None and value.type in {"arrow_function", "function_expression"}
                    and _return_draws(value.child_by_field_name("body"))):
                helpers[name] = (_scope_of(declaration.parent), declaration)
    return helpers


def _helper_reaches(helper, call):
    """The call sits inside the helper's declaring scope, after its declarator."""
    scope, order = helper
    parent = call.parent
    while parent is not None:
        if parent == scope:
            return order is None or order.end_byte <= call.start_byte
        parent = parent.parent
    return False


def _js_evidence(root, nodes):
    # Without full symbol resolution, any local Math binding/mutation makes its
    # provenance unknown. This deliberately under-reports instead of assigning
    # cryptographic properties to a custom object with the same spelling.
    for node in nodes:
        if node.type in {"formal_parameters", "import_clause", "catch_clause"}:
            if any(_text(child) == "Math" for child in _nodes(node)):
                return []
        if node.type in {"variable_declarator", "function_declaration", "class_declaration"}:
            name = node.child_by_field_name("name")
            if name is not None and any(_text(child) == "Math" for child in _nodes(name)):
                return []
        if node.type == "arrow_function" and _text(node.child_by_field_name("parameter")) == "Math":
            return []
        if node.type == "for_in_statement":
            target = node.child_by_field_name("left")
            if target is not None and any(_text(child) == "Math" for child in _nodes(target)):
                return []
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            if target is not None and any(_text(child) == "Math" for child in _nodes(target)):
                return []

    helpers = _helpers(nodes)

    def draw(value):
        if value is None or value.type in {"arrow_function", "function_expression", "function_declaration"}:
            return False
        if value.type == "call_expression":
            callee = value.child_by_field_name("function")
            if callee is not None and callee.type == "member_expression":
                if (_text(callee.child_by_field_name("object")) == "Math" and
                        _text(callee.child_by_field_name("property")) == "random"):
                    return True
            if callee is not None and callee.type == "identifier":
                helper = helpers.get(_text(callee))
                if helper is not None and _helper_reaches(helper, value):
                    return True
        return any(draw(child) for child in value.named_children)

    found = []
    for node in nodes:
        if node.type == "variable_declarator":
            target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            target, value = node.child_by_field_name("left"), node.child_by_field_name("right")
        else:
            continue
        if target is not None and target.type == "member_expression":
            target = target.child_by_field_name("property")
        if target is not None and target.type in {"identifier", "property_identifier"}:
            name = _text(target)
            if _secret(name) and draw(value):
                found.append((node.start_point[0] + 1, name))
    return found


def scan_insecure_randomness(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    # Fail the complete check if JS support is unavailable: never label Python-
    # only output as a complete mixed-language check.
    parsers = {False: _parser(False), True: _parser(True)}
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=_FILE_SUFFIXES,
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            try:
                text = raw.decode("utf-8")
                if info.filename.endswith(".py"):
                    evidence = _python_evidence(text)
                else:
                    root = parsers[info.filename.endswith((".jsx", ".tsx"))].parse(raw).root_node
                    if root.has_error:
                        accounting.skip("parse_error")
                        continue
                    evidence = _js_evidence(root, _nodes(root))
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            except (SyntaxError, RecursionError):
                accounting.skip("parse_error")
                continue
            except ValueError:
                accounting.skip("syntax_limit")
                continue
            for line_no, name in evidence:
                if len(findings) >= remaining_findings(_MAX_FINDINGS):
                    accounting.skip("finding_limit")
                    accounting.finish()
                    return findings
                findings.append(_finding(info.filename, line_no, name))
            accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, line: int, name: str) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="A secret-looking value is generated from a non-cryptographic random source",
        severity="high",
        confidence=0.7,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} draws a value into {name!r} from a non-cryptographic source "
            "(Math.random or Python's random module). That source is predictable, so a token, "
            "reset link, OTP or nonce built from it can be guessed or replayed -- the classic "
            "account-takeover vector. Whether the value is actually used as a secret, and whether "
            "anything else re-randomizes it, are NOT verified; the rule reads only that a "
            "secret-named value came from a predictable draw."
        ),
        fix_hint=(
            "Use a cryptographically secure source: crypto.getRandomValues in JS/TS, or Python's "
            "secrets module (secrets.token_hex / secrets.token_urlsafe). Never derive a token, "
            "password, reset link, OTP, nonce or salt from Math.random or the random module."
        ),
    )
