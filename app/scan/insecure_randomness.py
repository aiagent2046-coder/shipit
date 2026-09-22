"""Secret-named assignments containing a non-cryptographic random call.

Python AST requires an unambiguous local/inherited random import. Rebinding,
parameters and member replacement invalidate that provenance. JS/TS syntax
recognizes calls to an unshadowed Math.random, including template substitutions,
array and object destructuring bindings paired by exact slot or key
correspondence -- a default expression is the binding's value when the
slot or key is absent or provably undefined. Comments are ignored;
spreads, rest patterns and computed keys make correspondence unresolved.
The rule also resolves exactly one helper hop: a name declared once as a function whose
single return draws Math.random is itself a draw at call sites inside its
declaring scope (function declarations may be hoisted; declarators must
precede the call). Parameters, destructuring, reassignment, generator, enum,
namespace and import-alias declarations, conditional or multiple returns,
deferred bodies (a returned or assigned closure, generator, object/class
method or class has not drawn yet), nested helper chains, Python helpers,
dynamic aliases and cross-file provenance invalidate that hop. Comments and
literal text never count as draws. No uploaded source is executed.
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
# Names bound by object destructuring in JS/TS grammar trees.
_BINDING_NAMES = {"identifier", "shorthand_property_identifier_pattern"}
# Bodies that do not run when the surrounding expression is evaluated: entering
# one would count a draw that has not happened yet. A class is included whole:
# instance fields initialize at construction (static and computed keys may run
# earlier, but the conservative silence is deliberate under-reporting).
_DEFERRED_BODIES = {
    "arrow_function", "function_expression", "function_declaration",
    "generator_function", "generator_function_declaration", "method_definition",
    "class", "class_declaration", "abstract_class", "abstract_class_declaration",
}


def _secret(name):
    return any(word in name.lower() for word in _SECRET_WORDS)


def _ast_nodes(tree):
    pending, nodes = [(tree, 0)], []
    while pending:
        node, depth = pending.pop()
        if len(nodes) >= _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError("ast_limit")
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


def _js_statically_true(node) -> bool:
    """`if (true) {...}` with no else -- the tree-sitter twin of
    app.scan.scope_statements.statically_true (a literal-true guard is not
    conditional; its consequence always runs)."""
    if node is None or node.type != "if_statement":
        return False
    if node.child_by_field_name("alternative") is not None:
        return False
    condition = node.child_by_field_name("condition")
    if condition is None:
        return False
    text = _text(condition).strip()
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    return text == "true"


def _js_certain_try(node) -> bool:
    """try { X } finally {} with no catch: X runs as the flat form does.

    The tree-sitter twin of app.scan.scope_statements.certain_try -- a
    handler-less try guards nothing (its finalizer cannot swallow the
    outcome). MEASURED: try-wrapping silenced the helper variants of the
    metamorphic probe."""
    if node is None or node.type != "try_statement":
        return False
    if node.child_by_field_name("handler") is not None:
        return False
    finalizer = node.child_by_field_name("finalizer")
    if finalizer is None:
        return True
    # The finalizer field is the whole `finally_clause`; its trivial form is a
    # single empty statement_block inside it.
    bodies = finalizer.named_children
    return len(bodies) == 1 and not any(bodies[0].named_children)


def _plain_draw(value):
    """A Math.random call anywhere in the expression, without helper hops."""
    if value is None or value.type in _DEFERRED_BODIES:
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
    # A literal-true guard is no condition: `if (true) { return Math.random() }`
    # returns the draw the same way the flat form does -- and so does a
    # handler-less try around it. MEASURED: wrapping the return silenced three
    # helper cases of the metamorphic probe per wrapper form.
    while len(statements) == 1:
        wrapped = statements[0]
        if wrapped.type == "if_statement" and _js_statically_true(wrapped):
            inner = wrapped.child_by_field_name("consequence")
        elif _js_certain_try(wrapped):
            inner = wrapped.child_by_field_name("body")
        else:
            break
        if inner is None:
            return False
        statements = ([child for child in inner.named_children if child.type != "comment"]
                      if inner.type == "statement_block" else [inner])
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
    -- is never a parameter, catch, loop, destructuring, import, class, enum,
    namespace, generator or reassignment binding, and its body has a single
    return drawing Math.random. Returns name -> (declaring scope, order
    anchor); the anchor is None for hoisted function declarations and the
    declarator otherwise. Helpers calling other helpers stay unresolved:
    exactly one hop is supported.
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
                               if n.type in _BINDING_NAMES)
        elif node.type in {"generator_function_declaration", "import_alias"}:
            # A generator never runs its body on call, and a TS import alias
            # binds the name locally: both shadow a same-named helper.
            name = node.child_by_field_name("name")
            if name is None and node.type == "import_alias" and node.named_children:
                name = node.named_children[0]
            if name is not None and name.type == "identifier":
                invalid.add(_text(name))
        elif node.type in {"class_declaration", "abstract_class_declaration", "enum_declaration",
                           "internal_module", "generator_function", "function_expression"}:
            # Class/enum/namespace names and the inner names of function and
            # generator expressions are bindings that can shadow the helper.
            name = node.child_by_field_name("name")
            if name is not None:
                invalid.add(_text(name))
        elif node.type in {"formal_parameters", "import_clause", "catch_clause"}:
            invalid.update(_text(n) for n in _nodes(node) if n.type in _BINDING_NAMES)
        elif node.type == "for_in_statement":
            target = node.child_by_field_name("left")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target) if n.type in _BINDING_NAMES)
        elif node.type == "arrow_function":
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                invalid.add(_text(parameter))
        elif node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target) if n.type in _BINDING_NAMES)
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


def _pattern_binding_names(node):
    """Binding names a declarator name or pattern binds.

    Values inside defaults are not bindings: `Math.random()` in a default
    expression does not bind Math, while `const [Math] = xs` does. Walking
    the whole pattern here would silence the entire file over a value that
    merely mentions Math.
    """
    if node is None:
        return
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        yield _text(node)
    elif node.type == "assignment_pattern":
        yield from _pattern_binding_names(node.child_by_field_name("left"))
    elif node.type == "object_assignment_pattern":
        yield from _pattern_binding_names(node.child_by_field_name("left"))
    elif node.type == "pair_pattern":
        yield from _pattern_binding_names(node.child_by_field_name("value"))
    elif node.type in {"required_parameter", "optional_parameter"}:
        yield from _pattern_binding_names(node.child_by_field_name("pattern"))
    elif node.type in {"array_pattern", "object_pattern", "rest_pattern"}:
        for child in node.named_children:
            yield from _pattern_binding_names(child)


def _js_evidence(root, nodes):
    # Without full symbol resolution, any local Math binding/mutation makes its
    # provenance unknown. This deliberately under-reports instead of assigning
    # cryptographic properties to a custom object with the same spelling.
    for node in nodes:
        if node.type in {"formal_parameters", "catch_clause"}:
            if any(text == "Math" for child in node.named_children
                   for text in _pattern_binding_names(child)):
                return []
        if node.type == "import_clause":
            if any(_text(child) == "Math" for child in _nodes(node)):
                return []
        if node.type in {"variable_declarator", "function_declaration", "class_declaration"}:
            name = node.child_by_field_name("name")
            if name is not None and any(text == "Math" for text in _pattern_binding_names(name)):
                return []
        if node.type == "arrow_function" and _text(node.child_by_field_name("parameter")) == "Math":
            return []
        if node.type == "for_in_statement":
            target = node.child_by_field_name("left")
            if target is not None and any(text == "Math"
                                          for text in _pattern_binding_names(target)):
                return []
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            if target is not None:
                if target.type in {"array_pattern", "object_pattern"}:
                    if any(text == "Math" for text in _pattern_binding_names(target)):
                        return []
                elif any(_text(child) == "Math" for child in _nodes(target)):
                    return []

    helpers = _helpers(nodes)

    def draw(value):
        if value is None or value.type in _DEFERRED_BODIES:
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

    def slots(container):
        """Slot index per element, counting commas; holes keep their position.

        Comments are not slots -- a trailing comment would otherwise take
        over the position of the real element -- and neither is a spread,
        which pairs with no single slot.
        """
        positions, position = {}, 0
        for child in container.children:
            if child.type == ",":
                position += 1
            elif child.is_named and child.type not in {"comment", "spread_element", "rest_pattern"}:
                positions[child.start_byte] = position
        return positions

    def key_text(key):
        if key is None:
            return None
        if key.type == "property_identifier":
            return _text(key)
        if key.type == "string":
            text = _text(key)
            return text[1:-1] if len(text) >= 2 and text[0] == text[-1] else None
        return None

    def definitely_undefined(source):
        """A source expression whose value is certainly JavaScript undefined."""
        return (source is not None and source.type == "unary_expression"
                and bool(source.children) and source.children[0].type == "void")

    def source_or_default(element, default):
        return default if element is None or definitely_undefined(element) else element

    def destructure_hits(pattern, value, line, out):
        """Secret-named bindings whose destructuring source draws.

        Correspondence must be provable: array slots pair by comma position
        (holes keep theirs), object keys by literal key text with the last
        pair per key winning. A binding receives the element when its slot
        or key is present and the pattern's default otherwise, because a
        default only applies when the value is undefined. Comments, spreads,
        rest patterns, computed keys and containers that are not array or
        object literals have no provable correspondence and stay silent.
        """
        if pattern is None or value is None:
            return

        def hits(bound, source):
            if (bound is not None and source is not None
                    and _secret(_text(bound)) and draw(source)):
                out.append((line, _text(bound)))

        if pattern.type == "array_pattern" and value.type == "array":
            # A spread contributes a runtime-dependent number of slots. Even
            # syntactic elements after it therefore have no exact index, and a
            # default may or may not run. Keep the entire correspondence
            # unresolved instead of inventing positions.
            if any(child.type == "spread_element" for child in value.named_children):
                return
            positions = slots(value)
            elements = {positions[child.start_byte]: child
                        for child in value.named_children
                        if child.start_byte in positions}
            pattern_slots = slots(pattern)
            for child in pattern.named_children:
                element = elements.get(pattern_slots.get(child.start_byte))
                if child.type == "identifier":
                    hits(child, element)
                elif child.type == "assignment_pattern":
                    bound, default = (child.child_by_field_name("left"),
                                      child.child_by_field_name("right"))
                    source = source_or_default(element, default)
                    if bound is not None and bound.type == "identifier":
                        hits(bound, source)
                    elif bound is not None and bound.type in {"array_pattern", "object_pattern"}:
                        destructure_hits(bound, source, line, out)
                elif child.type in {"array_pattern", "object_pattern"}:
                    destructure_hits(child, element, line, out)
        elif pattern.type == "object_pattern" and value.type == "object":
            elements = {}
            for child in value.named_children:
                if child.type == "comment":
                    continue
                # Spreads, methods, shorthand properties and computed keys can
                # replace an earlier literal key. Unless every source member is
                # an ordinary literal-key pair, "last pair wins" is unproven.
                if child.type != "pair":
                    return
                key = key_text(child.child_by_field_name("key"))
                if key is None:
                    return
                elements[key] = child.child_by_field_name("value")
            for child in pattern.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    hits(child, elements.get(_text(child)))
                elif child.type == "pair_pattern":
                    key = key_text(child.child_by_field_name("key"))
                    if key is None:
                        continue
                    bound, default = child.child_by_field_name("value"), None
                    if bound is not None and bound.type == "assignment_pattern":
                        default = bound.child_by_field_name("right")
                        bound = bound.child_by_field_name("left")
                    element = elements.get(key)
                    source = source_or_default(element, default)
                    if bound is not None and bound.type == "identifier":
                        hits(bound, source)
                    elif bound is not None and bound.type in {"array_pattern", "object_pattern"}:
                        destructure_hits(bound, source, line, out)
                elif child.type == "object_assignment_pattern":
                    left, default = (child.child_by_field_name("left"),
                                     child.child_by_field_name("right"))
                    element = elements.get(_text(left)) if left is not None else None
                    source = source_or_default(element, default)
                    if left is not None and left.type == "shorthand_property_identifier_pattern":
                        hits(left, source)

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
        elif target is not None and target.type in {"array_pattern", "object_pattern"}:
            destructure_hits(target, value, node.start_point[0] + 1, found)
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
            except ValueError as exc:
                if exc.args != ("ast_limit",):
                    raise
                accounting.skip("ast_limit")
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
