"""Bounded operation context collected before model review. Never execute input.

Names are spellings, not resolved bindings. Same-file callers and preceding
exits are navigation evidence, not taint analysis or proof of protection.
Literal values are omitted; numeric experiments use our fixed public corpus.
"""
from __future__ import annotations

import ast
from decimal import Decimal
import stat
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan.secrets import is_non_production_path

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 8_000_000
MAX_FILES = 250
MAX_RECORDS = 64
SCOPE = (
    "Python subprocess calls and float(...):.2f formatting; JS/TS fetch calls. "
    "Arguments, same-file calls and preceding if/return syntax only. Names are not resolved; "
    "guards are not proven effective. Cross-file callers, input trust, runtime environment "
    "and harmful consequences are not checked. Literals omitted; tests/vendor excluded."
)


def numeric_examples() -> str:
    results = []
    for value in ("490.00", "990.00", "990.07", "333.33"):
        number = float(Decimal(value))
        results.append(f"{value} -> {number:.2f} (binary exact: "
                       f"{Decimal.from_float(number) == Decimal(value)})")
    return ("Fixed public examples for built-in float formatted as .2f: " + "; ".join(results)
            + ". These examples do not execute the uploaded expression, establish its bindings, "
            "test production prices or cover all numeric inputs.")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id[:128]
    if isinstance(node, ast.Attribute):
        return (_name(node.value) + "." + node.attr)[:256]
    return "<expression>"


def _shape(node: ast.AST) -> str:
    names = sorted({_name(n) for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))})
    return type(node).__name__ + "; names: " + ", ".join(names[:8])


def _python(data: bytes) -> list[dict]:
    tree = ast.parse(data)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    records = []

    def function(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    for node in ast.walk(tree):
        numeric = (isinstance(node, ast.FormattedValue) and isinstance(node.value, ast.Call)
                   and _name(node.value.func) == "float" and node.conversion == -1
                   and isinstance(node.format_spec, ast.JoinedStr)
                   and len(node.format_spec.values) == 1
                   and isinstance(node.format_spec.values[0], ast.Constant)
                   and node.format_spec.values[0].value == ".2f")
        subprocess = (isinstance(node, ast.Call) and _name(node.func) in {
            "subprocess.run", "subprocess.check_output", "subprocess.call", "subprocess.Popen"})
        if not (numeric or subprocess):
            continue
        call = node.value if numeric else node
        fn = function(node)
        detail = ["First argument: " + (_shape(call.args[0]) if call.args else "not recorded")]
        detail.extend(f"Keyword {kw.arg or '**'}: {_shape(kw.value)}" for kw in call.keywords[:8])
        if fn:
            # The value's immediate assignments are shown as syntax, never as
            # the definition reaching this use (branches/rebinding may differ).
            if call.args and isinstance(call.args[0], ast.Name):
                arg = call.args[0].id
                for stmt in fn.body:
                    if (isinstance(stmt, ast.Assign) and stmt.lineno < node.lineno
                            and any(isinstance(t, ast.Name) and t.id == arg for t in stmt.targets)):
                        detail.append(f"Earlier assignment at line {stmt.lineno}: {_shape(stmt.value)}")
            exits = [s for s in fn.body if isinstance(s, ast.If) and s.lineno < node.lineno
                     and any(isinstance(n, (ast.Return, ast.Raise)) for n in ast.walk(s))]
            detail.extend(f"Preceding if with exit syntax at line {s.lineno}: {_shape(s.test)}"
                          for s in exits[:4])
            callers = [c for c in calls if _name(c.func) == fn.name]
            detail.extend(f"Same-file call spelling at line {c.lineno}: "
                          + (_shape(c.args[0]) if c.args else "no positional argument") for c in callers[:8])
            detail.append("Caller list limited to 8 spellings in this file; binding/input trust not checked.")
        if numeric:
            detail.append(numeric_examples())
        records.append({"kind": "numeric_examples" if numeric else "python_subprocess_context",
                        "line": node.lineno, "scope": fn.name[:128] if fn else "<module>",
                        "call": "float(...):.2f" if numeric else _name(call.func),
                        "detail": "\n".join(detail)[:4000]})
        if len(records) > MAX_RECORDS:
            break
    return records


def _walk(node):
    todo = [node]
    while todo:
        item = todo.pop()
        yield item
        todo.extend(reversed(item.named_children))


def _text(node):
    return node.text.decode("utf-8")[:128] if node else ""


def _js_shape(node):
    if node is None:
        return "not recorded"
    # Only identifier nodes, never string/template fragments or credentials.
    names = sorted({_text(n) for n in _walk(node) if n.type == "identifier"})
    return node.type + "; names: " + ", ".join(names[:8])


def _javascript(data: bytes, path: str) -> list[dict]:
    language = (tree_sitter_typescript.language_tsx() if path.endswith((".jsx", ".tsx"))
                else tree_sitter_typescript.language_typescript())
    root = Parser(Language(language)).parse(data).root_node
    if root.has_error:
        raise ValueError("unparseable JS/TS")
    calls = [n for n in _walk(root) if n.type == "call_expression"]
    records = []
    for call in calls:
        if _text(call.child_by_field_name("function")) != "fetch":
            continue
        fn = call.parent
        while fn and fn.type not in {"function_declaration", "arrow_function", "function_expression",
                                     "method_definition"}:
            fn = fn.parent
        name = fn.child_by_field_name("name") if fn else None
        if fn and fn.type == "arrow_function" and fn.parent.type == "variable_declarator":
            name = fn.parent.child_by_field_name("name")
        # Patterns and computed/string method names may contain credentials.
        # Only a bare identifier is eligible for name-based caller lookup.
        if name and name.type != "identifier":
            name = None
        scope = _text(name) or ("<method>" if fn and fn.type == "method_definition"
                                else "<anonymous/module>")
        args = call.child_by_field_name("arguments")
        first = args.named_children[0] if args and args.named_children else None
        detail = ["First argument: " + _js_shape(first)]
        if name:
            callers = [c for c in calls if _text(c.child_by_field_name("function")) == scope]
            for c in callers[:8]:
                args = c.child_by_field_name("arguments")
                arg = args.named_children[0] if args and args.named_children else None
                detail.append(f"Same-file call spelling at line {c.start_point.row + 1}: {_js_shape(arg)}")
        detail.append("Caller list limited to 8 spellings in this file; binding, browser/server execution "
                      "and URL trust not checked. A fetch parameter alone does not establish SSRF.")
        records.append({"kind": "javascript_fetch_context", "line": call.start_point.row + 1,
                        "scope": scope, "call": "fetch", "detail": "\n".join(detail)})
        if len(records) > MAX_RECORDS:
            break
    return records


def collect_operation_context(fileobj) -> dict:
    records = []
    limits: set[str] = set()
    used = attempted = parsed = excluded = 0
    with zipfile.ZipFile(fileobj) as archive:
        infos = archive.infolist()
        counts: dict[str, int] = {}
        for info in infos:
            counts[info.filename] = counts.get(info.filename, 0) + 1
        for info in infos:
            path = info.filename
            if info.is_dir() or not path.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                continue
            if (is_non_production_path(path) or stat.S_ISLNK(info.external_attr >> 16)
                    or any(p in path.split("/") for p in ("vendor", "venv", ".venv", "node_modules"))):
                excluded += 1
                continue
            if counts[path] != 1:
                limits.add("ambiguous_archive_path")
                continue
            if len(path) > 512 or info.file_size > MAX_FILE_BYTES:
                limits.add("file_size_or_path_limit")
                continue
            if attempted >= MAX_FILES or used + info.file_size > MAX_TOTAL_BYTES:
                limits.add("scan_budget_reached")
                break
            attempted += 1
            used += info.file_size
            try:
                data = archive.read(info)
                found = _python(data) if path.endswith(".py") else _javascript(data, path)
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                limits.add("unparseable_source")
                continue
            parsed += 1
            records.extend({**r, "file": path} for r in found)
            if len(records) > MAX_RECORDS:
                records = records[:MAX_RECORDS]
                limits.add("record_limit_reached")
                break
    # Put wrapper inputs before routine tool invocations when the existing
    # prompt budget can hold only a prefix. No trust verdict follows from this.
    records.sort(key=lambda r: (0 if r["kind"] == "javascript_fetch_context" else
                               1 if "Keyword input:" in r["detail"] else
                               2 if r["kind"] == "numeric_examples" else 3))
    return {"scope": SCOPE, "records": records, "parsed_files": parsed, "excluded_files": excluded,
            "limitations": sorted(limits)}
