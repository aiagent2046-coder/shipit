"""One-hop named-import error context from ZIP source, never outcome verification.

Only observed/not_checked records are emitted. Neither uploaded code nor a
module resolver is executed. Per-instance caches and finite budgets belong to
one audit. A checked call is not a statement about all callers or all throws.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import posixpath
import re
import stat
import zipfile
import zlib

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g
from app.scan.consequence_evidence import _function, _loc, _narrative
from app.scan.secrets import is_non_production_path

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_FILES = 64
MAX_CHECKS = 40
MAX_NODES = 40_000
MAX_TOTAL_NODES = 400_000
MAX_ARCHIVE_ENTRIES = 4096
MAX_CALLS = 128
MAX_TOTAL_CALLS = 512
MAX_CALLER_FILES = 16
MAX_RECORDS = 8
EXTENSIONS = (".ts", ".tsx", ".js", ".jsx")
KIND = "imported_call_error_boundary"
CLAIM = "The recorded direct named-import call has the bounded source error-boundary observations below."
LIMITS = (
    "Source context only; this does not settle the finding's narrative. Only recorded call sites and "
    "error paths were checked, not all callers, all throws or runtime module resolution. A non-awaited "
    "call's catch does not establish handling of a returned Promise rejection, even for a non-async helper. "
    "Nested callbacks, deferred promises, other operations, aliases, dynamic names and unrecorded paths "
    "are outside the observation. Rethrow and unsupported catch/finally paths are not recovery proofs."
)


def _result(detail, **extra):
    return {"kind": KIND, "claim": CLAIM, "result": "not_checked", "scope": "bounded_source_context",
            "detail": detail, **extra}


def _safe_path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith("/")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _source_path(path):
    return (_safe_path(path) and path.endswith(EXTENSIONS) and not is_non_production_path(path)
            and not set(path.split("/")) & {"vendor", "node_modules", ".git", "dist", "build"})


def _contains(outer, inner):
    return bool(outer and outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte)


def _owner(node):
    node = node.parent
    while node and node.type not in g._FUNCTIONS:
        if node.type in {"class", "class_declaration"}:
            return None
        node = node.parent
    return node


def _function_name(fn):
    return ((g._name(fn.parent.child_by_field_name("name"))
             if fn.parent and fn.parent.type == "variable_declarator" else "")
            or g._name(fn.child_by_field_name("name")))


def _await(call):
    parent, child = call.parent, call
    while parent and parent.type == "parenthesized_expression" and len(g._children(parent)) == 1:
        child, parent = parent, parent.parent
    return parent if parent and parent.type == "await_expression" and g._children(parent) == [child] else None


def _catch_behavior(handler):
    parameter = handler.child_by_field_name("parameter")
    if parameter is not None and not g._name(parameter):
        return {"result": "not_checked", "behavior": "unsupported_catch_parameter"}
    body = handler.child_by_field_name("body")
    statements = g._children(body)
    if len(statements) != 1:
        return {"result": "not_checked", "behavior": "unsupported_catch_body"}
    stmt = statements[0]
    values = g._children(stmt)
    value = g._unwrap(values[0]) if len(values) == 1 else None
    if stmt.type == "return_statement":
        # Only primitives without evaluation effects; literal values are redacted.
        allowed = {"null", "true", "false", "number", "string"}
        if not values or value and value.type in allowed:
            return {"result": "observed", "behavior": "literal_return",
                    "return_kind": value.type if value else "void", "return": _loc(stmt)}
    if (stmt.type == "throw_statement" and value and g._name(value)
            and g._name(value) == g._name(handler.child_by_field_name("parameter"))):
        return {"result": "observed", "behavior": "rethrow", "throw": _loc(stmt)}
    return {"result": "not_checked", "behavior": "unsupported_catch_body"}


def _boundary(call, fn):
    """Lexical containment stops at the owning function, including callbacks."""
    awaited = _await(call)
    unknown = {"result": "not_checked", "invocation": "direct_await" if awaited else "direct_call",
               "synchronous_throw": "not_checked", "promise_rejection": "not_checked"}
    ancestors, node = [], call.parent
    while node and node != fn:
        if node.type in g._FUNCTIONS:
            return {**unknown, "reason": "Nested function boundary"}
        if node.type == "try_statement":
            ancestors.append(node)
        node = node.parent
    # An outer finally can replace a catch return/throw. Even empty finally is
    # intentionally unsupported; no general completion-record analysis here.
    if any(n.child_by_field_name("finalizer") for n in ancestors):
        return {**unknown, "reason": "Enclosing finally is outside this check"}
    for attempt in ancestors:
        if not _contains(attempt.child_by_field_name("body"), call):
            continue
        handler = attempt.child_by_field_name("handler")
        if handler is None:
            continue
        behavior = _catch_behavior(handler)
        result = {**unknown, "try": _loc(attempt), "catch": _loc(handler), "catch_behavior": behavior}
        if behavior["result"] == "observed":
            result.update(result="observed", synchronous_throw="enters_recorded_catch",
                          promise_rejection="enters_recorded_catch" if awaited else "not_checked")
        else:
            result["reason"] = "Catch effects, conditional exits or deferred returns are outside this check"
        return result
    return {**unknown, "reason": "No own covering try/catch checked; absence elsewhere is not established"}


def _imports(root):
    """Only unaliased, value named imports. Return all local import spellings too."""
    imports, names = [], []
    for stmt in root.named_children:
        if stmt.type != "import_statement":
            continue
        clause = next((n for n in stmt.named_children if n.type == "import_clause"), None)
        if clause is None:
            continue
        for n in g._walk(clause):
            if n.type == "import_specifier":
                names.append(g._name(n.child_by_field_name("alias") or n.child_by_field_name("name")))
            elif n.type == "identifier" and n.parent.type in {"import_clause", "namespace_import"}:
                names.append(g._name(n))
        if any(n.type == "type" for n in stmt.children):
            continue
        specifier = g._literal(stmt.child_by_field_name("source"))
        if not specifier or len(specifier) > 512:
            continue
        for n in g._walk(clause):
            if (n.type == "import_specifier" and not n.child_by_field_name("alias")
                    and not any(child.type == "type" for child in n.children)):
                name = g._name(n.child_by_field_name("name"))
                if name:
                    imports.append({"name": name, "specifier": specifier, "node": stmt})
    return imports, Counter(names)


def _file_facts(root):
    nodes = list(g._walk(root))
    imports, names = _imports(root)
    conflicting = {g._text(n.child_by_field_name("name")) for n in nodes
                   if n.type in {"enum_declaration", "internal_module", "class", "class_declaration"}}
    dynamic = any((n.type in {"identifier", "type_identifier", "shorthand_property_identifier_pattern"}
                   and "\\" in g._text(n))
                  or n.type in {"with_statement", "import_alias"}
                  or (n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "eval")
                  for n in nodes)
    return imports, names, g._bindings(nodes), conflicting, dynamic


def _unambiguous(root, name, *, declaration=False, facts=None):
    _, names, bindings, conflicting, dynamic = facts or _file_facts(root)
    return (names[name] == (0 if declaration else 1) and bindings[name] == (1 if declaration else 0)
            and name not in conflicting and not dynamic)


def _exports(root):
    result = {}
    facts = _file_facts(root)
    if any(n.type == "export_statement" and n.child_by_field_name("declaration") is None
           for n in root.named_children):
        return result
    for stmt in root.named_children:
        if stmt.type != "export_statement" or any(n.type == "default" for n in stmt.children):
            continue
        dec = stmt.child_by_field_name("declaration")
        if not dec:
            continue
        functions = [dec] if dec.type == "function_declaration" else []
        if dec.type == "lexical_declaration" and any(n.type == "const" for n in dec.children):
            functions += [n.child_by_field_name("value") for n in dec.named_children
                          if n.type == "variable_declarator" and n.child_by_field_name("value")
                          and n.child_by_field_name("value").type in {"arrow_function", "function_expression"}]
        for fn in functions:
            name = _function_name(fn)
            if name and _unambiguous(root, name, declaration=True, facts=facts):
                result[name] = fn
    return result


def _json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Ambiguous JSON configuration")
        obj[key] = value
    return obj


class ImportedErrorVerifier:
    def __init__(self, archive):
        self.archive = archive
        self.remaining = MAX_TOTAL_BYTES
        self.remaining_nodes = MAX_TOTAL_NODES
        self.checks = self.reads = self.calls = 0
        self._cache = {}
        self._index = None
        self._results = {}

    def _entries(self):
        if self._index is None:
            with zipfile.ZipFile(self.archive) as archive:
                infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise ValueError("Archive entry budget exhausted")
            index = {}
            for info in infos:
                index.setdefault(info.filename, []).append(info)
            self._index = index
        return self._index

    def _read(self, path, *, parse=True):
        if path in self._cache:
            cached = self._cache[path]
            if isinstance(cached, str):
                raise ValueError(cached)
            return cached
        if self.reads >= MAX_FILES:
            raise ValueError("Per-audit source read/parse attempt budget exhausted")
        self.reads += 1
        try:
            matches = self._entries().get(path, [])
            if (not _safe_path(path) or len(matches) != 1 or matches[0].is_dir()
                    or stat.S_ISLNK(matches[0].external_attr >> 16)):
                raise ValueError("Source path missing, unsafe, symlinked or ambiguous")
            info = matches[0]
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise ValueError("Unsupported source ZIP compression")
            if not 0 < info.file_size <= min(MAX_FILE_BYTES, self.remaining):
                raise ValueError("Source byte budget exhausted")
            self.remaining -= info.file_size
            with zipfile.ZipFile(self.archive) as archive:
                data = archive.read(info)
            data.decode("utf-8", errors="strict")
            root = None
            if parse:
                language = (tree_sitter_typescript.language_typescript() if path.endswith(".ts")
                            else tree_sitter_typescript.language_tsx())
                root = Parser(Language(language)).parse(data).root_node
                if root.has_error:
                    raise ValueError("Source has parse errors")
                for count, _ in enumerate(g._walk(root), 1):
                    self.remaining_nodes -= 1
                    if count > MAX_NODES or self.remaining_nodes < 0:
                        raise ValueError("Source syntax node budget exhausted")
            value = data, root
            self._cache[path] = value
            return value
        except (ValueError, UnicodeError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            # Rejected paths consume an attempt once and cannot be retried to
            # bypass aggregate limits. Do not expose raw parser/source messages.
            reason = str(exc) if type(exc) is ValueError else "Source could not be read/parsed"
            self._cache[path] = reason
            raise ValueError(reason) from None

    def _binding(self, path, node=None):
        data, _ = self._read(path, parse=path.endswith(EXTENSIONS))
        return {"file": path, "source_sha256": hashlib.sha256(data).hexdigest(),
                **(_loc(node) if node else {"line_start": 1, "line_end": len(data.splitlines()),
                                         "span": [0, len(data)]})}

    def _config(self, caller):
        index = self._entries()
        directory, configs = posixpath.dirname(caller), []
        while True:
            configs = [posixpath.join(directory, name) for name in ("tsconfig.json", "jsconfig.json")
                       if posixpath.join(directory, name) in index]
            if configs or not directory:
                break
            directory = posixpath.dirname(directory)
        if len(configs) > 1:
            raise ValueError("Ambiguous local module configuration")
        if not configs:
            return directory, None, {}
        config_path = configs[0]
        config_data, _ = self._read(config_path, parse=False)
        config = json.loads(config_data, object_pairs_hook=_json_object)
        options = config.get("compilerOptions", {})
        if ("extends" in config or not isinstance(options, dict)
                or options.get("baseUrl", ".") not in (".", "./")
                or any(k in options for k in ("rootDirs", "moduleSuffixes", "customConditions"))):
            raise ValueError("Inherited or custom module resolution is outside this check")
        return directory, config_path, options

    def _resolve(self, caller, specifier):
        index = self._entries()
        directory, config_path, options = self._config(caller)
        resolution = {"kind": "relative_source_candidate"}
        if config_path:
            resolution["configuration"] = self._binding(config_path)
        if specifier.startswith(("./", "../")):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(caller), specifier))
        else:
            # A literal path mapping is evidence, not a guess based on '@'.
            if config_path is None:
                raise ValueError("No local path-mapping configuration checked")
            paths = options.get("paths", {})
            if not isinstance(paths, dict):
                raise ValueError("Invalid source path mappings")
            if specifier in paths or any(
                    key.count("*") == 1 and specifier.startswith(key.split("*")[0])
                    and specifier.endswith(key.split("*")[1]) and not key.endswith("/*") for key in paths):
                raise ValueError("Exact or unsupported competing path mapping is outside this check")
            mappings = [(key, values) for key, values in paths.items()
                        if key.endswith("/*") and key.count("*") == 1 and specifier.startswith(key[:-1])]
            if len(mappings) != 1:
                raise ValueError("Import path mapping missing or ambiguous")
            key, values = mappings[0]
            if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str)
                    or not values[0].startswith("./") or not values[0].endswith("/*")
                    or values[0].count("*") != 1):
                raise ValueError("Only a single literal local wildcard mapping is checked")
            mapped = values[0][:-1] + specifier[len(key) - 1:]
            base = posixpath.normpath(posixpath.join(directory, mapped))
            resolution = {"kind": "literal_config_source_candidate", "configuration": self._binding(config_path)}
        if not _safe_path(base):
            raise ValueError("Import resolves outside safe archive paths")
        candidates = ([base] if base.endswith(EXTENSIONS) else
                      [base + ext for ext in EXTENSIONS] + [base + "/index" + ext for ext in EXTENSIONS])
        candidates = [path for path in candidates if path in index]
        if len(candidates) != 1 or not _source_path(candidates[0]):
            raise ValueError("Source import target missing, unsupported or ambiguous")
        path = candidates[0]
        if base.endswith((".js", ".jsx")):
            stem = base.rsplit(".", 1)[0]
            if any(stem + suffix in index for suffix in (".ts", ".tsx", ".d.ts")):
                raise ValueError("JavaScript-to-TypeScript source substitution is ambiguous")
        self._read(path)
        return path, resolution

    def _operations(self, path, root, fn):
        body = fn.child_by_field_name("body")
        nodes = list(g._walk(body, g._SKIP)) if body else []
        # The observation is about direct syntax. No global fetch/runtime API
        # identity is assumed; a shadowed fetch binding is not labelled network.
        _, imported_names, bindings, conflicting, dynamic = _file_facts(root)
        native_fetch = (not bindings["fetch"] and not imported_names["fetch"]
                        and "fetch" not in conflicting and not dynamic)
        fetches, operations = {}, []
        for call in nodes:
            if (call.type != "call_expression" or not _await(call)
                    or any(child.type in {"optional_chain", "?."} for child in call.children)):
                continue
            name = g._name(call.child_by_field_name("function"))
            operation = None
            if name == "fetch" and native_fetch:
                operation = "direct_awaited_fetch_syntax"
                awaited = _await(call)
                dec = awaited.parent
                if dec and dec.type == "variable_declarator" and dec.child_by_field_name("value") == awaited:
                    local = g._name(dec.child_by_field_name("name"))
                    if (local and bindings[local] == 1 and not imported_names[local]
                            and local not in conflicting and not dynamic):
                        statement = dec.parent
                        block = statement.parent if statement else None
                        if (statement and statement.type in {"lexical_declaration", "variable_declaration"}
                                and block and block.type == "statement_block"):
                            fetches[local] = call, block
            else:
                callee = call.child_by_field_name("function")
                if callee and any(n.type in {"optional_chain", "?."} for n in callee.children):
                    continue
                receiver, args = g._method(call, "json")
                local = g._name(receiver)
                if (local in fetches and not args and fetches[local][0].end_byte < call.start_byte
                        and _contains(fetches[local][1], call)):
                    operation = "direct_awaited_response_json_syntax"
            if operation:
                operations.append({"operation": operation, "call": self._binding(path, call),
                                   "await": _loc(_await(call)), "error_boundary": _boundary(call, fn)})
                if len(operations) > MAX_RECORDS:
                    break
        return operations[:MAX_RECORDS], len(operations) > MAX_RECORDS

    def _record(self, caller, call, imported, target, fn, resolution, direction):
        caller_data, caller_root = self._read(caller)
        _, target_root = self._read(target)
        owner = _owner(call)
        if owner is None or not _unambiguous(caller_root, imported["name"]):
            raise ValueError("Imported call binding is shadowed, reassigned or outside a function")
        operations, truncated = self._operations(target, target_root, fn)
        boundary = _boundary(call, owner)
        observed = boundary["result"] == "observed" or any(
            o["error_boundary"]["result"] == "observed" for o in operations)
        binding = {"file": caller, "source_sha256": hashlib.sha256(caller_data).hexdigest(),
                   "direction": direction, "call": _loc(call),
                   "caller_function": {"name": _function_name(owner), **_loc(owner)},
                   "import": {"name": imported["name"], **_loc(imported["node"])},
                   "resolution": resolution,
                   "callee": {**self._binding(target, fn), "name": _function_name(fn),
                              "async_syntax": any(n.type == "async" for n in fn.children)},
                   "caller_error_boundary": boundary, "callee_operations": operations}
        return _result(LIMITS, result="observed" if observed else "not_checked", source_binding=binding), truncated

    def checks_for(self, finding):
        if not re.search(r"\b(?:errors?|throw\w*|reject\w*|catch\w*|fail\w*|network|stuck|spinner|busy)\b",
                         _narrative(finding), re.I):
            return []
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        valid_key = _source_path(path) and type(start) is int and type(end) is int
        key = (path, start, end) if valid_key else None
        if key in self._results:
            return deepcopy(self._results[key])
        results = self._checks_for(finding)
        if valid_key and len(self._results) < MAX_CHECKS:
            self._results[key] = deepcopy(results)
        return results

    def _checks_for(self, finding):
        if not re.search(r"\b(?:errors?|throw\w*|reject\w*|catch\w*|fail\w*|network|stuck|spinner|busy)\b",
                         _narrative(finding), re.I):
            return []
        if self.checks >= MAX_CHECKS:
            return [_result("Per-audit imported-call check budget exhausted. " + LIMITS)]
        self.checks += 1
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if (not _source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end):
            return [_result("Unsupported source path or coordinates. " + LIMITS)]
        results, omissions = [], set()
        local_calls = 0

        def check_call(caller, call, imported, target=None, expected_fn=None, direction="callee"):
            nonlocal local_calls
            if local_calls >= MAX_CALLS or self.calls >= MAX_TOTAL_CALLS:
                omissions.add("Direct call check budget exhausted")
                return
            local_calls += 1
            self.calls += 1
            try:
                resolved, resolution = self._resolve(caller, imported["specifier"])
                if target is not None and resolved != target:
                    return
                _, target_root = self._read(resolved)
                fn = _exports(target_root).get(imported["name"])
                if fn is None or expected_fn is not None and fn != expected_fn:
                    raise ValueError("No unambiguous direct named function export checked")
                record, truncated = self._record(caller, call, imported, resolved, fn, resolution, direction)
                results.append(record)
                if truncated:
                    omissions.add("Callee operation output budget exhausted")
            except ValueError as exc:
                omissions.add(str(exc))

        try:
            data, root = self._read(path)
            if end > len(data.splitlines()):
                return [_result("Source coordinates exceed the checked file. " + LIMITS)]
            imports, _ = _imports(root)
            fn = _function(root, start, end)
            all_calls = [n for n in g._walk(root) if n.type == "call_expression"
                         and not any(child.type in {"optional_chain", "?."} for child in n.children)]
            for call in all_calls:
                if not (g._line(call) <= end and start <= call.end_point[0] + 1 or fn and _owner(call) == fn):
                    continue
                name = g._name(call.child_by_field_name("function"))
                matches = [i for i in imports if i["name"] == name]
                if len(matches) == 1:
                    check_call(path, call, matches[0])
                if len(results) >= MAX_RECORDS:
                    omissions.add("Call context output budget reached; other calls not checked")
                    break
            # A finding inside an exported helper may concern its callers. Scan
            # only a bounded deterministic subset, prioritizing sibling files.
            exports = _exports(root)
            exported_name = next((name for name, exported in exports.items() if exported == fn), None)
            if exported_name and len(results) < MAX_RECORDS:
                paths = sorted((p for p in self._entries() if p != path and _source_path(p)),
                               key=lambda p: (posixpath.dirname(p) != posixpath.dirname(path), p))
                scanned = 0
                for caller in paths[:MAX_CALLER_FILES]:
                    scanned += 1
                    try:
                        _, caller_root = self._read(caller)
                        caller_imports, _ = _imports(caller_root)
                        matches = [i for i in caller_imports if i["name"] == exported_name]
                        if len(matches) != 1:
                            continue
                        for call in g._walk(caller_root):
                            if (call.type == "call_expression"
                                    and not any(child.type in {"optional_chain", "?."} for child in call.children)
                                    and g._name(call.child_by_field_name("function")) == exported_name):
                                check_call(caller, call, matches[0], target=path, expected_fn=fn, direction="caller")
                                if len(results) >= MAX_RECORDS:
                                    break
                    except ValueError as exc:
                        omissions.add(str(exc))
                    if len(results) >= MAX_RECORDS:
                        break
                if scanned < len(paths):
                    omissions.add("Bounded caller-file subset only; remaining archive callers not checked")
            if not results:
                omissions.add("No checked direct named-import error boundary at this source anchor")
        except (ValueError, TypeError, AttributeError, KeyError, UnicodeError, RecursionError,
                RuntimeError, OSError, zipfile.BadZipFile):
            omissions.add("Source, binding or parsing budget could not be checked")
        if omissions:
            results.append(_result("; ".join(sorted(omissions)) + ". " + LIMITS))
        return results
