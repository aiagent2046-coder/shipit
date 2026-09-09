"""Bounded Zod input/output evidence from archive bytes, never model metadata.

This proves a declared default-strip schema and a particular parsed-output
write, not an API rejection contract or whole-program safety. Unsupported
schema effects, aliases and data flows remain unknown. Submitted code is not
executed. Only the independently checked Zod 3.25.76 contract is supported.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import posixpath
import re
import stat
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g
from app.scan.secrets import is_non_production_path

KIND = "zod_unknown_keys_in_write"
CLAIM = "Unknown input keys survive Zod validation into the recorded write payload."
MAX_BYTES = 2_000_000
MAX_FILE_BYTES = 300_000
MAX_FILES = 256
MAX_NODES = 80_000
# This is intentionally a supported-contract pin, not a guess about every Zod
# version or alternative import path. See the review document for the source.
SUPPORTED_VERSION = "3.25.76"
_ATOMIC = re.compile(r"Unknown (?:input )?(?:keys|fields) reach (?:the )?cited write payload\.?", re.I)
_SELECTOR = re.compile(r"(?:unknown|extra|undeclared|additional)\s+(?:input\s+)?(?:keys|fields)", re.I)
_STORAGE = re.compile(r"(?:unknown|extra|undeclared|additional)\s+(?:input\s+)?(?:keys|fields) "
                      r"(?:are |can be )?(?:silently )?(?:accepted and )?(?:potentially )?"
                      r"(?:stored|persisted|saved)(?: in (?:the )?database)?[.]?", re.I)
_COMPOUND = re.compile(r"\b(?:also|separately|additionally|independent|future|later|authorization|"
                       r"authentication|denial.of.service|SQL injection|reject|strict|contract)\b|;", re.I)


def selected(finding):
    narrative = "\n".join(str(finding.get(k) or "")[:8000] for k in
                          ("title", "explanation", "observation", "required_conditions"))
    return bool(_SELECTOR.search(narrative) and (
        re.search(r"\b(?:zod|schema|validation|parsed)\b|\.strict", narrative, re.I)
        or _ATOMIC.fullmatch(str(finding.get("title", "")))))


def _result(result="not_checked", detail="No complete, unambiguous Zod-to-write path was established.", **extra):
    return {"kind": KIND, "claim": CLAIM, "result": result, "detail": detail, **extra}


def _literal(node):
    return bool(node and all(n.type in {"string", "string_fragment", "number", "true", "false", "null",
                                      "array", "unary_expression"} for n in g._walk(node)))


def _module_root(node):
    while node and node.parent:
        node = node.parent
    return node


def _own_function(node):
    node = node.parent
    while node and node.type not in g._FUNCTIONS:
        node = node.parent
    return node


def _string(node):
    text = g._text(node)
    return text[1:-1] if node and node.type == "string" and "\\" not in text else ""


def _imports(root):
    result = {}
    for statement in root.named_children:
        if statement.type != "import_statement" or re.match(r"import\s+type\b", g._text(statement)):
            continue
        source = _string(statement.child_by_field_name("source"))
        for node in g._walk(statement):
            if node.type == "import_specifier" and not any(c.type == "type" for c in node.children):
                name = g._text(node.child_by_field_name("name"))
                local = g._text(node.child_by_field_name("alias") or node.child_by_field_name("name"))
                if local in result:
                    return {}
                result[local] = (source, name)
    return result


def _zod_imports_stable(root):
    """Any unmodelled runtime Zod import/escape can change the shared contract."""
    bindings = []
    for statement in root.named_children:
        if statement.type != "import_statement" or _string(statement.child_by_field_name("source")) != "zod":
            continue
        if re.match(r"import\s+type\b", g._text(statement)):
            continue
        imports = [n for n in g._walk(statement) if n.type == "import_specifier"]
        if not imports or any(g._text(n.child_by_field_name("name")) != "z"
                              or n.child_by_field_name("alias") for n in imports):
            return False
        bindings.append("z")
    if not bindings:
        return True
    nodes = list(g._walk(root))
    if len(bindings) != 1 or g._bindings(nodes)["z"]:
        return False
    for node in nodes:
        if node.type != "identifier" or g._text(node) != "z":
            continue
        parent = node.parent
        if parent.type in {"import_specifier", "nested_type_identifier"}:
            continue
        if (parent.type == "member_expression" and parent.child_by_field_name("object") == node
                and parent.parent.type == "call_expression"):
            continue
        return False
    return True


def _schema(node, zname, depth=0):
    """An explicit tree of object keys; every leaf is closed, never any/record."""
    if not node or depth > 16:
        return None
    node = g._unwrap(node)
    if node.type != "call_expression":
        return None
    fn = g._member(node.child_by_field_name("function"))
    if not fn:
        return None
    obj, method = fn.child_by_field_name("object"), g._text(fn.child_by_field_name("property"))
    args = g._children(node.child_by_field_name("arguments"))
    if g._name(obj) == zname:
        if method == "object" and len(args) == 1 and args[0].type == "object":
            result = {}
            for pair in g._children(args[0]):
                if pair.type != "pair":
                    return None
                key = pair.child_by_field_name("key")
                name = g._text(key) if key.type == "property_identifier" else _string(key)
                value = _schema(pair.child_by_field_name("value"), zname, depth + 1)
                if not name or name in result or value is None:
                    return None
                result[name] = value
            return result
        if method in {"string", "number", "boolean"} and not args:
            return "scalar"
        if method == "enum" and len(args) == 1 and args[0].type == "array" and _literal(args[0]):
            return "scalar"
        if method == "array" and len(args) == 1:
            value = _schema(args[0], zname, depth + 1)
            return [value] if value is not None else None
        if method == "union" and len(args) == 1 and args[0].type == "array":
            variants = [_schema(n, zname, depth + 1) for n in g._children(args[0])]
            # Heterogeneous object unions are deliberately not resolved.
            if variants and all(v == "scalar" or v == ["scalar"] for v in variants):
                return "scalar_or_array"
        return None
    value = _schema(obj, zname, depth + 1)
    if value is None:
        return None
    if method in {"optional", "nullable"} and not args:
        return value
    if method in {"min", "max", "int", "uuid", "url"} and value == "scalar" and all(_literal(a) for a in args):
        return value
    # No transforms, preprocessors, catchalls, passthrough, object composition,
    # defaults, coercion, user callbacks or mutations are treated as strip.
    return None


def _schema_top(node, zname):
    obj, args = g._method(node, "object")
    return _schema(node, zname) if g._name(obj) == zname and len(args) == 1 else None


def _terminal_failure(guard, name):
    if guard.type != "if_statement" or guard.child_by_field_name("alternative"):
        return False
    condition = g._unwrap(guard.child_by_field_name("condition"))
    if (not condition or condition.type != "unary_expression"
            or g._text(condition.child_by_field_name("operator")) != "!"):
        return False
    member = g._member(condition.child_by_field_name("argument"), "success")
    if not member or g._name(member.child_by_field_name("object")) != name:
        return False
    body = guard.child_by_field_name("consequence")
    parts = g._children(body) if body.type == "statement_block" else [body]
    return bool(parts and parts[-1].type in {"return_statement", "throw_statement"}
                and all(p.type in {"lexical_declaration", "expression_statement"} for p in parts[:-1]))


def _helper(root, name):
    """Exactly a generic safeParse helper with a terminal failure and data return."""
    functions = [n for n in g._walk(root) if n.type == "function_declaration"
                 and g._name(n.child_by_field_name("name")) == name]
    if len(functions) != 1:
        return False
    fn = functions[0]
    if g._bindings(list(g._walk(root)))[name] != 1:
        return False
    params = g._bound(fn.child_by_field_name("parameters"))
    if len(params) != 2:
        return False
    body = fn.child_by_field_name("body")
    statements = g._children(body)
    parses = []
    for dec in g._consts(body).values():
        receiver, args = g._method(dec.child_by_field_name("value"), "safeParse")
        if g._name(receiver) == params[0] and len(args) == 1:
            parses.append(dec)
    if len(parses) != 1:
        return False
    dec = parses[0]
    result_name = g._name(dec.child_by_field_name("name"))
    returns = [n for n in g._walk(body, g._SKIP) if n.type == "return_statement"]
    if len(returns) != 1 or returns[0] != statements[-1]:
        return False
    member = g._member(g._children(returns[0])[0], "data") if g._children(returns[0]) else None
    if not member or g._name(member.child_by_field_name("object")) != result_name:
        return False
    between = [s for s in statements if dec.end_byte < s.start_byte < returns[0].start_byte]
    if len(between) != 1 or not _terminal_failure(between[0], result_name):
        return False
    # No reassignment, escaping or mutation of result/schema. Type references
    # do not count as runtime uses. The schema parameter is called once only.
    nodes = list(g._walk(body))
    bindings = g._bindings(nodes)
    if bindings[result_name] != 1 or bindings[params[0]]:
        return False
    for n in nodes:
        if n.type == "identifier" and g._text(n) == result_name:
            parent = n.parent
            if parent == dec or (parent.type == "member_expression"
                                 and g._text(parent.child_by_field_name("property")) in {"success", "error", "data"}):
                continue
            return False
        if (n.type == "identifier" and g._text(n) == params[0]
                and n != (dec.child_by_field_name("value").child_by_field_name("function")
                          .child_by_field_name("object"))):
            return False
    return True


def _clean_expr(node, clean):
    """Return checked input shape, or None. Never infer unknown alias types."""
    node = g._unwrap(node)
    if not node:
        return None
    if node.type in {"identifier", "shorthand_property_identifier"}:
        return clean.get(g._text(node))
    member = g._member(node)
    if member:
        value = _clean_expr(member.child_by_field_name("object"), clean)
        return value.get(g._text(member.child_by_field_name("property"))) if isinstance(value, dict) else None
    if node.type == "binary_expression" and g._text(node.child_by_field_name("operator")) == "??":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return _clean_expr(left, clean) if _literal(right) else None
    obj, args = g._method(node, "trim")
    return "scalar" if obj and not args and _clean_expr(obj, clean) == "scalar" else None


def _names(node):
    return {g._text(n) for n in g._walk(node) if n.type in {"identifier", "shorthand_property_identifier"}}


def _parse_binding(call, fn):
    value = call.parent if call.parent and call.parent.type == "await_expression" else call
    parent = value.parent
    if parent and parent.type == "variable_declarator" and parent.child_by_field_name("value") == value:
        if parent.parent.type == "lexical_declaration" and any(n.type == "const" for n in parent.parent.children):
            return g._name(parent.child_by_field_name("name")), parent, 1
    if parent and parent.type == "assignment_expression" and parent.child_by_field_name("right") == value:
        name = g._name(parent.child_by_field_name("left"))
        body = fn.child_by_field_name("body")
        declarations = [n for s in g._children(body) if s.type == "lexical_declaration"
                        for n in g._children(s) if n.type == "variable_declarator"
                        and g._name(n.child_by_field_name("name")) == name and not n.child_by_field_name("value")]
        statement = parent.parent
        block = statement.parent if statement and statement.type == "expression_statement" else None
        attempt = block.parent if block and block.type == "statement_block" else None
        if not (len(declarations) == 1 and attempt and attempt.type == "try_statement"
                and attempt.parent == body and not attempt.child_by_field_name("finalizer")
                and g._children(block) == [statement]):
            return None
        handler = attempt.child_by_field_name("handler")
        parts = g._children(handler.child_by_field_name("body")) if handler else []
        if len(parts) == 1 and parts[0].type in {"return_statement", "throw_statement"}:
            return name, parent, 2
    return None


def _write_path(root, call, shape, mode, path):
    fn = _own_function(call)
    if not fn:
        return None
    body = fn.child_by_field_name("body")
    if not body or body.type != "statement_block":
        return None
    binding = _parse_binding(call, fn)
    if not binding or not binding[0]:
        return None
    name, dec, binding_count = binding
    nodes = list(g._walk(fn))
    if len(nodes) > 16000:
        return None
    counts = g._bindings(nodes)
    if counts[name] != binding_count:
        return None
    # Direct parse must be in the function's top-level block; safeParse's guard
    # must terminate before every recorded use of .data.
    if binding_count == 1 and dec.parent.parent != body:
        return None
    ready = dec.end_byte
    if mode == "safeParse":
        guards = [s for s in g._children(body) if s.start_byte > ready and _terminal_failure(s, name)]
        if len(guards) != 1:
            return None
        ready = guards[0].end_byte
        clean = {name: {"data": shape}}
        if any(g._member(n, "data") and g._name(n.child_by_field_name("object")) == name
               and n.start_byte < ready for n in nodes):
            return None
    else:
        clean = {name: shape}
    own = list(g._walk(body, g._SKIP))
    # Resolve only literal member projections and object destructuring into
    # immutable locals. Object-to-object aliases and computed members abstain.
    for n in own:
        if n.type != "variable_declarator" or n.start_byte <= ready:
            continue
        value, pattern = n.child_by_field_name("value"), n.child_by_field_name("name")
        if not value or not (_names(value) & set(clean)):
            continue
        if n.parent.type != "lexical_declaration" or not any(c.type == "const" for c in n.parent.children):
            return None
        value_shape = _clean_expr(value, clean)
        if pattern.type == "object_pattern" and isinstance(value_shape, dict):
            for item in g._children(pattern):
                key = g._text(item)
                if item.type != "shorthand_property_identifier_pattern" or key not in value_shape or counts[key] != 1:
                    return None
                clean[key] = value_shape[key]
        elif g._name(pattern) and value.type == "member_expression" and value_shape is not None:
            key = g._name(pattern)
            if counts[key] != 1:
                return None
            clean[key] = value_shape
        else:
            # A DB query result can be initialized by a call containing a
            # checked input: it does not alias or mutate the parsed object.
            if value.type not in {"await_expression", "call_expression"}:
                return None
    # Track request/raw-body aliases syntactically; no second raw input may be
    # smuggled into a payload alongside one checked field.
    call_args = g._children(call.child_by_field_name("arguments"))
    request_names = set(g._bound(fn.child_by_field_name("parameters")))
    raw = (_names(call_args[-1]) if call_args else set()) - request_names
    raw -= set(clean)
    for _ in range(8):
        previous_requests = set(request_names)
        for item in own:
            if item.type != "variable_declarator":
                continue
            value, pattern = item.child_by_field_name("value"), item.child_by_field_name("name")
            if g._name(value) in request_names:
                if g._name(pattern):
                    request_names.add(g._name(pattern))
                else:
                    raw.update(g._bound(pattern))
        if request_names == previous_requests:
            break
    else:
        return None
    def raw_access(value):
        for item in g._walk(value):
            receiver, _ = g._method(item, "json")
            if receiver and _names(receiver) & request_names:
                return True
            if item.type in {"member_expression", "subscript_expression"}:
                receiver = item.child_by_field_name("object")
                # Only the directly named headers projection is separated from
                # raw input. Computed access, body and unknown projections are
                # not guessed; request aliases are followed conservatively.
                if (g._name(receiver) in request_names and not (
                        item.type == "member_expression"
                        and g._text(item.child_by_field_name("property")) == "headers")):
                    return True
            # A bare request escaping into another helper has unknown output.
            if item.type == "arguments" and any(g._name(a) in request_names for a in g._children(item)):
                return True
        return False
    for _ in range(8):
        prior = set(raw)
        for item in own:
            if item.type == "variable_declarator":
                value = item.child_by_field_name("value")
                if value and item != dec and (_names(value) & raw or raw_access(value)):
                    raw.update(set(g._bound(item.child_by_field_name("name"))) - set(clean))
            elif item.type == "assignment_expression" and item != dec:
                value = item.child_by_field_name("right")
                if value and (_names(value) & raw or raw_access(value)):
                    raw.update(set(g._bound(item.child_by_field_name("left"))) - set(clean))
        if raw == prior:
            break
    else:
        return None
    if any(n.type == "spread_element" and _names(n) & (set(clean) | raw | request_names) for n in own):
        return None
    sinks = []
    sink_nodes = []
    for node in own:
        if node.start_byte <= ready:
            continue
        for method in ("update", "insert", "upsert"):
            receiver, args = g._method(node, method)
            if not receiver or not args:
                continue
            payload = args[0]
            if _names(payload) & (raw | request_names) or raw_access(payload):
                return None
            if not (_names(payload) & set(clean)):
                continue
            checked = _clean_expr(payload, clean)
            if checked is None:
                if payload.type != "object":
                    return None
                for pair in g._children(payload):
                    if pair.type == "shorthand_property_identifier":
                        if _clean_expr(pair, clean) is None:
                            return None
                        continue
                    if pair.type != "pair" or pair.child_by_field_name("key").type != "property_identifier":
                        return None
                    value = pair.child_by_field_name("value")
                    if _names(value) & set(clean):
                        if _clean_expr(value, clean) is None:
                            return None
                    elif not (_literal(value) or value.type == "member_expression" or value.type == "identifier"):
                        return None
            sink_nodes.append(node)
            sinks.append({"file": path, "method": method, "line_start": g._line(node),
                          "line_end": node.end_point[0] + 1})
    if not sinks:
        return None
    for statement in g._children(body):
        if (statement.type in {"return_statement", "throw_statement"}
                and statement.start_byte < sink_nodes[-1].start_byte
                and not any(statement.start_byte <= sink.start_byte < statement.end_byte for sink in sink_nodes)):
            return None
    # Every use of the whole parsed object must be a read, not an escape to an
    # arbitrary function/object alias. Scalar projected values may be used in
    # comparisons and queries; they cannot carry additional object keys.
    for node in nodes:
        if node.start_byte <= ready or node.type not in {
                "identifier", "shorthand_property_identifier", "member_expression"}:
            continue
        value_shape = _clean_expr(node, clean)
        if not isinstance(value_shape, (dict, list)) and value_shape != "scalar_or_array":
            continue
        parent = node.parent
        in_payload = any(s.child_by_field_name("arguments").start_byte < node.start_byte
                         and node.end_byte < s.child_by_field_name("arguments").end_byte for s in sink_nodes)
        if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
            # Only declared projections, never object methods or computed keys.
            if _clean_expr(parent, clean) is None:
                return None
            continue
        if parent.type == "variable_declarator":
            pattern = parent.child_by_field_name("name")
            if (pattern == node or pattern.type == "object_pattern"
                    or (g._name(pattern) in clean and node.type == "member_expression")):
                continue
        if parent.type in {"arguments", "pair", "object"} and in_payload:
            continue
        return None
    return {"file": path, "parse_method": mode, "parse_line": g._line(call), "parsed_binding": name,
            "writes": sinks}


class ZodWriteVerifier:
    def __init__(self, archive):
        self.archive = archive
        self._files = None
        self._trees = {}
        self._proofs = {}
        self._error = None

    def _load(self):
        if self._files is not None or self._error:
            return
        try:
            with zipfile.ZipFile(self.archive) as archive:
                members = archive.infolist()
                names = [i.filename for i in members]
                if len(names) != len(set(names)) or len(names) > 10000:
                    raise ValueError("Archive entries are ambiguous or outside the bounded inventory.")
                selected_files = [i for i in members if not i.is_dir() and (
                    i.filename.endswith((".ts", ".tsx", ".js", ".jsx", "/package.json", "/package-lock.json",
                                         "/tsconfig.json", "/jsconfig.json"))
                    or i.filename in {"package.json", "package-lock.json", "tsconfig.json", "jsconfig.json"})
                    and not is_non_production_path(i.filename)]
                if len(selected_files) > MAX_FILES or sum(i.file_size for i in selected_files) > MAX_BYTES:
                    raise ValueError("Zod source inventory budget exhausted.")
                files = {}
                for info in selected_files:
                    path = PurePosixPath(info.filename)
                    if (path.is_absolute() or ".." in path.parts or "\\" in info.filename
                            or stat.S_ISLNK(info.external_attr >> 16)):
                        raise ValueError("Source path is not an unambiguous regular archive member.")
                    if info.file_size > MAX_FILE_BYTES:
                        raise ValueError("Zod source file budget exhausted.")
                    data = archive.read(info)
                    data.decode("utf-8", errors="strict")
                    files[info.filename] = data
                self._files = files
        except (ValueError, UnicodeError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
            self._error = str(exc)

    def _tree(self, path):
        if path not in self._trees:
            parser = Parser(Language(tree_sitter_typescript.language_tsx() if path.endswith((".tsx", ".jsx"))
                                     else tree_sitter_typescript.language_typescript()))
            tree = parser.parse(self._files[path]).root_node
            if tree.has_error or sum(1 for _ in g._walk(tree)) > MAX_NODES:
                raise ValueError("Source AST is incomplete or outside its node budget.")
            self._trees[path] = tree
        return self._trees[path]

    def _package(self, path):
        directory = posixpath.dirname(path)
        while True:
            package_path = posixpath.join(directory, "package.json")
            if package_path in self._files:
                return directory
            if not directory:
                return None
            directory = posixpath.dirname(directory)

    def _version(self, base):
        package_path = posixpath.join(base, "package.json")
        lock_path = posixpath.join(base, "package-lock.json")
        for config_path, contents in self._files.items():
            if not config_path.endswith(("tsconfig.json", "jsconfig.json")) or self._package(config_path) != base:
                continue
            config = json.loads(contents)
            options = config.get("compilerOptions", {})
            if config.get("extends") or options.get("baseUrl", ".") not in {".", ""}:
                return None
            for pattern in options.get("paths", {}):
                if (pattern in {"zod", "*"} or pattern.startswith("zod/")
                        or ("*" in pattern and "zod".startswith(pattern.split("*")[0]))):
                    return None
        if posixpath.join(base, "zod.ts") in self._files or posixpath.join(base, "zod/index.ts") in self._files:
            return None
        package = json.loads(self._files[package_path])
        lock = json.loads(self._files.get(lock_path, b"{}"))
        dependency = package.get("dependencies", {}).get("zod")
        if not isinstance(dependency, str) or not re.fullmatch(r"[~^]?3\.\d+\.\d+", dependency):
            return None
        requested = tuple(int(part) for part in dependency.lstrip("^~").split("."))
        checked = tuple(int(part) for part in SUPPORTED_VERSION.split("."))
        if requested > checked or (dependency.startswith("~") and requested[:2] != checked[:2]):
            return None
        packages = lock.get("packages", {})
        installed = packages.get("node_modules/zod", {})
        if (installed.get("version") != SUPPORTED_VERSION or installed.get("link")
                or installed.get("resolved", "").startswith(("file:", "git"))
                or any(p != "node_modules/zod" and p.endswith("/node_modules/zod") for p in packages)):
            return None
        # Exact declarations must agree with the lock; unsupported semver forms
        # and dependency alias/override mechanisms are not guessed.
        if (not dependency.startswith(("^", "~")) and dependency != SUPPORTED_VERSION
                or package.get("overrides") or package.get("resolutions")):
            return None
        return {"version": SUPPORTED_VERSION, "lock_file": lock_path,
                "lock_sha256": hashlib.sha256(self._files[lock_path]).hexdigest()}

    def _resolve(self, path, source, base):
        if source.startswith("."):
            candidate = posixpath.normpath(posixpath.join(posixpath.dirname(path), source))
        elif source.startswith("@/"):
            config = json.loads(self._files.get(posixpath.join(base, "tsconfig.json"), b"{}"))
            options = config.get("compilerOptions", {})
            if (config.get("extends") or options.get("paths", {}).get("@/*") != ["./*"]
                    or options.get("baseUrl", ".") != "."):
                return None
            candidate = posixpath.join(base, source[2:])
        else:
            return None
        candidates = [p for p in (candidate, candidate + ".ts", candidate + ".tsx", candidate + "/index.ts")
                      if p in self._files]
        return candidates[0] if len(candidates) == 1 and self._package(candidates[0]) == base else None

    def _prove_schema(self, path, name, base):
        key = (path, name)
        if key in self._proofs:
            return self._proofs[key]
        self._proofs[key] = None
        root = self._tree(path)
        imports = _imports(root)
        zbindings = [local for local, item in imports.items() if item == ("zod", "z") and local == "z"]
        constants = g._consts(root)
        dec = constants.get(name)
        nodes = list(g._walk(root))
        counts = g._bindings(nodes)
        if len(zbindings) != 1 or counts["z"] or counts[name] != 1 or dec is None:
            return None
        for node in nodes:
            if node.type != "identifier" or g._text(node) != "z":
                continue
            parent = node.parent
            if parent.type in {"import_specifier", "nested_type_identifier"}:
                continue
            if (parent.type == "member_expression" and parent.child_by_field_name("object") == node
                and parent.parent.type == "call_expression"):
                continue
            return None
        shape = _schema_top(dec.child_by_field_name("value"), "z")
        if not isinstance(shape, dict):
            return None
        paths = []
        for candidate, data in self._files.items():
            if not candidate.endswith((".ts", ".tsx", ".js", ".jsx")) or self._package(candidate) != base:
                continue
            # Module edges are checked before any symbol-name filter: namespace
            # computed access and export-star consumers need not spell the name.
            module = self._tree(candidate)
            if not _zod_imports_stable(module):
                return None
            local_imports = _imports(module)
            # Imports of the schema through aliases/namespaces are unresolved
            # consumers; do not silently skip possible cross-file mutation.
            for statement in module.named_children:
                if statement.type == "export_statement" and statement.child_by_field_name("source"):
                    source = _string(statement.child_by_field_name("source"))
                    if self._resolve(candidate, source, base) == path:
                        return None
                if statement.type != "import_statement":
                    continue
                source = _string(statement.child_by_field_name("source"))
                if self._resolve(candidate, source, base) != path:
                    continue
                for item in g._walk(statement):
                    if item.type == "namespace_import":
                        return None
                    if (item.type == "import_specifier" and g._text(item.child_by_field_name("name")) == name
                            and item.child_by_field_name("alias")):
                        return None
            local_names = ([name] if candidate == path else [
                local for local, (source, imported) in local_imports.items()
                if imported == name and local == name and self._resolve(candidate, source, base) == path])
            if not local_names:
                continue
            local_nodes = list(g._walk(module))
            local_counts = g._bindings(local_nodes)
            if candidate != path and local_counts[name]:
                return None
            calls = []
            for node in local_nodes:
                if node.type != "call_expression":
                    continue
                for method in ("safeParse", "parse"):
                    receiver, args = g._method(node, method)
                    if g._name(receiver) == name:
                        if len(args) != 1:
                            return None
                        calls.append((node, method))
                arguments = g._children(node.child_by_field_name("arguments"))
                if any(g._name(arg) == name for arg in arguments):
                    helper_name = g._name(node.child_by_field_name("function"))
                    imported = local_imports.get(helper_name)
                    helper_path = (self._resolve(candidate, imported[0], base) if imported else candidate)
                    helper_original = imported[1] if imported else helper_name
                    if (local_counts[helper_name] != (1 if helper_path == candidate else 0)
                            or len(arguments) != 2 or g._name(arguments[0]) != name or not helper_path
                            or not _helper(self._tree(helper_path), helper_original)):
                        return None
                    calls.append((node, "safeParse_helper"))
            # Reject runtime aliases, schema method composition and escapes.
            for node in local_nodes:
                if node.type != "identifier" or g._text(node) != name:
                    continue
                parent = node.parent
                if parent.type in {"import_specifier", "type_query"} or (candidate == path and parent == dec):
                    continue
                if any(call.start_byte <= node.start_byte <= node.end_byte <= call.end_byte for call, _ in calls):
                    continue
                return None
            for call, mode in calls:
                proof = _write_path(module, call, shape, mode, candidate)
                if not proof:
                    return None
                proof["source_sha256"] = hashlib.sha256(data).hexdigest()
                paths.append(proof)
        if not paths:
            return None
        result = {"schema_file": path, "schema_name": name, "schema_line": g._line(dec),
                  "schema_sha256": hashlib.sha256(self._files[path]).hexdigest(),
                  "unknown_keys": "strip", "paths": paths}
        self._proofs[key] = result
        return result

    def check(self, finding):
        if not selected(finding):
            return None
        self._load()
        if self._error:
            return _result(detail=self._error)
        path = finding.get("file")
        start, end = finding.get("line_start"), finding.get("line_end")
        if (not isinstance(path, str) or path not in self._files or not path.endswith((".ts", ".tsx", ".js", ".jsx"))
                or type(start) is not int or type(end) is not int
                or not 1 <= start <= end <= len(self._files[path].splitlines())):
            return _result(detail="The finding does not identify a valid source range.")
        try:
            base = self._package(path)
            version = self._version(base) if base is not None else None
            if not version:
                return _result(detail="A supported, unambiguous Zod dependency version was not established "
                               "from the lockfile.")
            root = self._tree(path)
            candidates = []
            for name, dec in g._consts(root).items():
                if g._line(dec) <= start <= end <= dec.end_point[0] + 1:
                    candidates.append((path, name))
            if not candidates:
                functions = [n for n in g._walk(root) if n.type in g._FUNCTIONS
                             and g._line(n) <= start <= end <= n.end_point[0] + 1]
                if len(functions) != 1:
                    return _result()
                imports = _imports(root)
                for node in g._walk(functions[0], g._SKIP):
                    if node.type != "call_expression":
                        continue
                    receiver, _ = g._method(node, "safeParse")
                    if receiver is None:
                        receiver, _ = g._method(node, "parse")
                    name = g._name(receiver)
                    args = g._children(node.child_by_field_name("arguments"))
                    if not name and args:
                        name = g._name(args[0])
                    if name in g._consts(root):
                        candidates.append((path, name))
                    elif name in imports:
                        imported_path = self._resolve(path, imports[name][0], base)
                        if imported_path:
                            candidates.append((imported_path, imports[name][1]))
            candidates = list(dict.fromkeys(candidates))
            proofs = [p for schema_path, name in candidates if (p := self._prove_schema(schema_path, name, base))]
            if len(proofs) != 1:
                return _result()
            proof = proofs[0]
            conditions = finding.get("required_conditions")
            positive_storage = [str(finding.get("explanation", "")), str(finding.get("observation", ""))]
            if isinstance(conditions, list):
                positive_storage.extend(c for c in conditions if isinstance(c, str))
            storage_claim = (any(_STORAGE.fullmatch(text.strip()) for text in positive_storage)
                             or bool(_ATOMIC.fullmatch(str(finding.get("title", "")))))
            detail = (f"Zod {SUPPORTED_VERSION} from the recorded package lock uses default strip for this explicit "
                      "object schema, including its declared nested object shapes. The checked parsed output reaches "
                      "the recorded explicit write payloads; undeclared input keys are absent "
                      "at those call boundaries. "
                      "The input may still be accepted: removing keys is different from rejecting a request. "
                      "An API contract requiring rejection, allowed-field authorization, future schema changes and "
                      "callee transformations, database behavior and other execution paths are not established "
                      "by this check.")
            return _result("contradicted" if storage_claim else "observed", detail,
                           target=proof["schema_name"], source_line_start=proof["schema_line"],
                           source_line_end=proof["schema_line"], zod_dependency=version, source_binding=proof)
        except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError, RuntimeError):
            return _result(detail="The schema, import, package configuration or write path was outside "
                           "the bounded check.")

    def whole_check(self, finding):
        if not _ATOMIC.fullmatch(str(finding.get("title", ""))):
            return None
        narrative = "\n".join(str(finding.get(k) or "")[:8000] for k in
                              ("explanation", "observation", "required_conditions"))
        conditions = finding.get("required_conditions")
        statements = [str(finding.get("explanation") or ""), str(finding.get("observation") or "")]
        if conditions is not None and not isinstance(conditions, list):
            return _result(detail="The whole-claim conditions are not a supported atomic narrative.")
        statements += conditions or []
        if (_COMPOUND.search(narrative) or finding.get("premises") or any(
                not isinstance(statement, str) or (statement.strip() and not _ATOMIC.fullmatch(statement.strip()))
                for statement in statements)):
            return _result(detail="Only the input-to-write premise is checked; the narrative has additional "
                           "claims or selectors.")
        proof = self.check(finding)
        if proof and proof.get("result") == "contradicted":
            # A schema declaration is shared context, not a uniquely selected
            # write. Whole-finding disposition requires one local write path.
            paths = proof["source_binding"]["paths"]
            if len(paths) != 1 or paths[0]["file"] != finding.get("file") or len(paths[0]["writes"]) != 1:
                return _result(detail="The cited whole claim does not select one local write path.")
            write = paths[0]["writes"][0]
            if not (write["line_start"] <= finding.get("line_start", 0)
                    <= finding.get("line_end", 0) <= write["line_end"]):
                return _result(detail="The cited whole claim does not select one local write path.")
        return proof
