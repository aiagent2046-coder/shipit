"""Deterministic structural canonicalization and obfuscation-delta measurement.

Covers Python AST and JavaScript/TypeScript syntax (via bundled Tree-sitter when
present) plus bounded 2-pass cross-file constant & re-export unrolling without
executing code or calling a language model.
"""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import ctypes
import io
import os
import re
import stat
import subprocess
import sys
import zipfile
from hashlib import sha256
from pathlib import PurePosixPath

from app.foundation.ingest.validators import validate_zip
from app.scan.core.file_scope import BINARY_EVIDENCE_PATH

try:
    import tree_sitter_typescript
    from tree_sitter import Language, Parser

    _TS_PARSER = Parser(Language(tree_sitter_typescript.language_typescript()))
    _TSX_PARSER = Parser(Language(tree_sitter_typescript.language_tsx()))
except ImportError:
    _TS_PARSER = None
    _TSX_PARSER = None

MAX_SOURCE_BYTES = 256 * 1024
MAX_AST_NODES = 50_000
MAX_ARCHIVE_FILES = 1200
MAX_ARCHIVE_PARSED_BYTES = 12 * 1024 * 1024

DANGEROUS_MODULES = frozenset({
    "subprocess", "os", "pty", "socket", "ctypes", "cffi", "pickle", "marshal", "builtins", "importlib",
    "child_process", "node:child_process", "vm", "node:vm", "net", "node:net",
})
DANGEROUS_ATTRS = frozenset({
    "system", "popen", "Popen", "run", "call", "check_output", "execve", "execvp",
    "eval", "exec", "execSync", "spawn", "spawnSync", "execFile", "Function",
    "__import__", "compile", "loads", "CDLL", "PyDLL", "LoadLibrary", "dlopen", "connect",
})
SENSITIVE_LITERAL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:"
    r"subprocess|child_process|pty|ctypes|cffi|pickle|marshal|importlib|"
    r"execve|execvp|execSync|spawnSync|popen|Popen|check_output|__import__|dlopen|CDLL|PyDLL|"
    r"eval|exec|/bin/sh|/bin/bash|powershell|cmd\.exe"
    r")(?:$|[^A-Za-z0-9_])"
    r"|^(?:os|sys|vm|net|socket|system)$"
)
BROAD_EXCEPTIONS = frozenset({"Exception", "BaseException"})
FFI_MODULES = frozenset({"ctypes", "cffi"})
PY_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
EXCLUDED_PARTS = frozenset({
    "node_modules", ".git", ".next", "dist", "build", "vendor", "__pycache__", ".venv",
    "tests", "test", "fixtures", "benchmarks", "benchmark", "bench",
})

STDLIB_SURFACE_MODULES = {
    "sys": set(dir(sys)),
    "os": set(dir(os)),
    "builtins": set(dir(builtins)),
    "subprocess": set(dir(subprocess)),
    "ctypes": set(dir(ctypes)),
    "binascii": set(dir(binascii)),
    "base64": set(dir(base64)),
}

WEIGHTS = {
    "split_sensitive_literal": 3,
    "cross_file_const_assembly": 3,
    "split_ffi_library_path": 4,
    "encoded_sensitive_constant": 4,
    "dangerous_callable_alias": 2,
    "dynamic_getattr_sink": 4,
    "hallucinated_stdlib_getattr": 4,
    "dynamic_import_sink": 3,
    "computed_member_sink": 4,
    "constant_branch_guard": 1,
    "silent_exception_swallow": 1,
}


def _span(node: ast.AST) -> list[int]:
    return [
        getattr(node, "lineno", 1),
        getattr(node, "col_offset", 0),
        getattr(node, "end_lineno", getattr(node, "lineno", 1)),
        getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
    ]


def _ts_span(node) -> list[int]:
    return [
        node.start_point[0] + 1,
        node.start_point[1],
        node.end_point[0] + 1,
        node.end_point[1],
    ]


def _contains_sensitive_token(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) > 512:
        return False
    return bool(SENSITIVE_LITERAL_RE.search(stripped))


def _is_broad_except(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in BROAD_EXCEPTIONS:
        return True
    if isinstance(handler.type, ast.Tuple):
        return any(isinstance(elt, ast.Name) and elt.id in BROAD_EXCEPTIONS for elt in handler.type.elts)
    return False


def _try_decode_codec(raw_str: str, codec: str) -> tuple[str | None, str | None]:
    if not raw_str or len(raw_str) > 4096:
        return None, None
    try:
        if codec == "base64":
            return base64.b64decode(raw_str, validate=True).decode("utf-8", errors="strict"), "base64_constant"
        if codec == "hex":
            return bytes.fromhex(raw_str).decode("utf-8", errors="strict"), "hex_constant"
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None, None
    return None, None


def _fold_string_expr(
    node: ast.AST,
    env: dict[str, tuple[str, int]] | None = None,
    depth: int = 0,
) -> tuple[str | None, int]:
    if depth > 12:
        return None, 0
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, 0
    if isinstance(node, ast.Name) and env and node.id in env:
        val, prior_ops = env[node.id]
        return val, prior_ops + 1
    if isinstance(node, ast.JoinedStr):
        parts, ops = [], 0
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue) and val.conversion == -1 and val.format_spec is None:
                sub, sub_ops = _fold_string_expr(val.value, env, depth + 1)
                if sub is None:
                    return None, 0
                parts.append(sub)
                ops += sub_ops + 1
            else:
                return None, 0
        return "".join(parts), ops
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, l_ops = _fold_string_expr(node.left, env, depth + 1)
        right, r_ops = _fold_string_expr(node.right, env, depth + 1)
        if left is not None and right is not None:
            return left + right, l_ops + r_ops + 1
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and len(node.args) == 1 and not node.keywords):
        sep, s_ops = _fold_string_expr(node.func.value, env, depth + 1)
        seq = node.args[0]
        if sep is not None and isinstance(seq, (ast.List, ast.Tuple)) and 1 <= len(seq.elts) <= 64:
            items = []
            total_ops = s_ops + 1
            for elt in seq.elts:
                part, p_ops = _fold_string_expr(elt, env, depth + 1)
                if part is None:
                    return None, 0
                items.append(part)
                total_ops += p_ops
            return sep.join(items), total_ops
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "chr" and len(node.args) == 1 and not node.keywords
            and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is int
            and 0 <= node.args[0].value <= 0x10FFFF):
        return chr(node.args[0].value), 1
    if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
            and node.slice.lower is None and node.slice.upper is None
            and isinstance(node.slice.step, ast.UnaryOp) and isinstance(node.slice.step.op, ast.USub)
            and isinstance(node.slice.step.operand, ast.Constant) and node.slice.step.operand.value == 1):
        inner, i_ops = _fold_string_expr(node.value, env, depth + 1)
        if inner is not None:
            return inner[::-1], i_ops + 1
    return None, 0


def _decode_constant_call(
    call: ast.Call,
    env: dict[str, tuple[str, int]] | None = None,
) -> tuple[str | None, str | None]:
    if len(call.args) != 1 or call.keywords:
        return None, None
    arg = call.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, (str, bytes)):
        raw_str = arg.value.decode("ascii", errors="ignore") if isinstance(arg.value, bytes) else arg.value
    else:
        raw_str, _ = _fold_string_expr(arg, env)
    if not raw_str:
        return None, None
    fn = call.func
    method_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
    if method_name in {"b64decode", "urlsafe_b64decode"}:
        return _try_decode_codec(raw_str, "base64")
    if method_name == "fromhex":
        return _try_decode_codec(raw_str, "hex")
    return None, None


def analyze_python_obfuscation(
    source_bytes: bytes,
    *,
    file_path: str = "<memory>",
    external_env: dict[str, tuple[str, int]] | None = None,
) -> dict:
    digest = sha256(source_bytes).hexdigest()
    base = {
        "version": 1,
        "language": "python",
        "file": file_path,
        "source_sha256": digest,
        "status": "completed",
        "reason": "analyzed",
        "delta_score": 0,
        "signals": [],
        "ffi_targets": [],
        "sink_aliases": [],
    }
    if len(source_bytes) > MAX_SOURCE_BYTES:
        return {**base, "status": "partial", "reason": "source_limit"}
    try:
        text = source_bytes.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
        return {**base, "status": "unavailable", "reason": "parse_error"}

    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        return {**base, "status": "partial", "reason": "ast_node_limit"}

    parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    imported_modules: dict[str, str] = {}
    imported_symbols: dict[str, tuple[str, str]] = {}
    signals: list[dict] = []
    ffi_targets: list[dict] = []
    sink_aliases: list[dict] = []

    store_counts: dict[str, int] = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            store_counts[node.id] = store_counts.get(node.id, 0) + 1
    const_env: dict[str, tuple[str, int]] = dict(external_env or {})
    for _ in range(3):
        for node in nodes:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and store_counts.get(node.targets[0].id, 0) == 1):
                name = node.targets[0].id
                if name not in const_env:
                    val, ops = _fold_string_expr(node.value, const_env)
                    if val is not None and len(val) <= 512:
                        const_env[name] = (val, ops)

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                imported_modules[alias.asname or root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            root = node.module.split(".")[0]
            for alias in node.names:
                imported_symbols[alias.asname or alias.name] = (root, alias.name)

    for node in nodes:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
            signals.append({
                "kind": "constant_branch_guard",
                "polarity": "dead_branch" if not node.test.value else "trivial_branch",
                "span": _span(node),
            })
        elif isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], (ast.Pass, ast.Continue)) and _is_broad_except(node):
                signals.append({
                    "kind": "silent_exception_swallow",
                    "bare_except": node.type is None,
                    "span": _span(node),
                })

    for node in nodes:
        if isinstance(node, ast.Subscript):
            folded_rev, ops = _fold_string_expr(node, const_env)
            if folded_rev and ops >= 1 and _contains_sensitive_token(folded_rev):
                signals.append({"kind": "split_sensitive_literal", "ops": ops, "span": _span(node)})
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parent = parents.get(node)
            if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
                continue
            folded, ops = _fold_string_expr(node, const_env)
            if folded and ops >= 1 and _contains_sensitive_token(folded):
                signals.append({"kind": "split_sensitive_literal", "ops": ops, "span": _span(node)})
        elif isinstance(node, ast.Call):
            decoded, codec = _decode_constant_call(node, const_env)
            if decoded is not None and _contains_sensitive_token(decoded):
                signals.append({"kind": "encoded_sensitive_constant", "codec": codec, "span": _span(node)})

    for node in nodes:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            val = node.value
            if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                mod = imported_modules.get(val.value.id)
                if mod in DANGEROUS_MODULES and val.attr in DANGEROUS_ATTRS:
                    sink_aliases.append({"alias": target_name, "module": mod, "symbol": val.attr, "span": _span(node)})
                    signals.append({
                        "kind": "dangerous_callable_alias", "module": mod,
                        "symbol": val.attr, "span": _span(node),
                    })
            elif isinstance(val, ast.Name) and val.id in imported_symbols:
                mod, sym = imported_symbols[val.id]
                if mod in DANGEROUS_MODULES and sym in DANGEROUS_ATTRS:
                    sink_aliases.append({"alias": target_name, "module": mod, "symbol": sym, "span": _span(node)})
                    signals.append({
                        "kind": "dangerous_callable_alias", "module": mod,
                        "symbol": sym, "span": _span(node),
                    })

        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "getattr" and len(node.args) >= 2:
                resolved_attr, ops = _fold_string_expr(node.args[1], const_env)
                if resolved_attr in DANGEROUS_ATTRS:
                    signals.append({
                        "kind": "dynamic_getattr_sink", "symbol": resolved_attr,
                        "split_ops": ops, "span": _span(node),
                    })
                elif resolved_attr and len(node.args) == 2:
                    recv = node.args[0]
                    recv_mod = None
                    if isinstance(recv, ast.Name):
                        recv_mod = imported_modules.get(recv.id)
                    elif (isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name)
                          and recv.func.id == "__import__" and recv.args):
                        m_name, _ = _fold_string_expr(recv.args[0], const_env)
                        recv_mod = m_name.split(".")[0] if m_name else None
                    if recv_mod in STDLIB_SURFACE_MODULES and resolved_attr not in STDLIB_SURFACE_MODULES[recv_mod]:
                        signals.append({
                            "kind": "hallucinated_stdlib_getattr",
                            "module": recv_mod,
                            "missing_attr": resolved_attr[:64],
                            "span": _span(node),
                        })
            elif (
                (isinstance(fn, ast.Name) and fn.id == "__import__")
                or (isinstance(fn, ast.Name) and imported_symbols.get(fn.id) == ("importlib", "import_module"))
                or (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and imported_modules.get(fn.value.id) == "importlib" and fn.attr == "import_module")
            ) and node.args:
                resolved_mod, ops = _fold_string_expr(node.args[0], const_env)
                if resolved_mod and resolved_mod.split(".")[0] in DANGEROUS_MODULES:
                    signals.append({
                        "kind": "dynamic_import_sink", "module": resolved_mod.split(".")[0],
                        "split_ops": ops, "span": _span(node),
                    })
            elif isinstance(fn, ast.Attribute) and fn.attr == "join" and len(node.args) == 1:
                folded_join, ops = _fold_string_expr(node, const_env)
                if folded_join and ops >= 1 and _contains_sensitive_token(folded_join):
                    signals.append({"kind": "split_sensitive_literal", "ops": ops, "span": _span(node)})

            is_ffi_loader = False
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                mod = imported_modules.get(fn.value.id)
                if mod in FFI_MODULES and fn.attr in {"CDLL", "PyDLL", "LoadLibrary", "dlopen"}:
                    is_ffi_loader = True
                elif fn.attr == "dlopen":
                    is_ffi_loader = True
            elif isinstance(fn, ast.Name) and fn.id in imported_symbols:
                mod, sym = imported_symbols[fn.id]
                if mod in FFI_MODULES and sym in {"CDLL", "PyDLL", "LoadLibrary"}:
                    is_ffi_loader = True

            if is_ffi_loader and node.args:
                lib_path, ops = _fold_string_expr(node.args[0], const_env)
                if lib_path and ops >= 1:
                    signals.append({"kind": "split_ffi_library_path", "ops": ops, "span": _span(node)})
                ffi_targets.append({
                    "library_arg": lib_path if lib_path and len(lib_path) <= 256 else None,
                    "dynamic_path": lib_path is None,
                    "split_ops": ops,
                    "span": _span(node),
                })

    signals.sort(key=lambda item: (item["span"], item["kind"]))
    ffi_targets.sort(key=lambda item: item["span"])
    sink_aliases.sort(key=lambda item: (item["span"], item["alias"]))
    score = sum(WEIGHTS.get(sig["kind"], 1) for sig in signals)
    return {
        **base,
        "delta_score": score,
        "signals": signals[:128],
        "ffi_targets": ffi_targets[:32],
        "sink_aliases": sink_aliases[:64],
    }


def _ts_unquote(node, raw: bytes) -> str | None:
    if node.type == "string":
        text = raw[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        if len(text) >= 2 and text[0] in ("'", '"') and text[-1] == text[0]:
            return text[1:-1]
    elif node.type == "template_string" and all(c.type == "string_fragment" for c in node.named_children):
        text = raw[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        if len(text) >= 2 and text[0] == "`" and text[-1] == "`":
            return text[1:-1]
    return None


def _ts_fold_string(
    node,
    raw: bytes,
    env: dict[str, tuple[str, int]] | None = None,
    depth: int = 0,
) -> tuple[str | None, int]:
    if depth > 12:
        return None, 0
    lit = _ts_unquote(node, raw)
    if lit is not None:
        return lit, 0
    if node.type == "identifier" and env is not None:
        ident = raw[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        if ident in env:
            val, prior_ops = env[ident]
            return val, prior_ops + 1
    if node.type == "parenthesized_expression" and len(node.named_children) == 1:
        return _ts_fold_string(node.named_children[0], raw, env, depth + 1)
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and raw[op.start_byte:op.end_byte] == b"+":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                l_val, l_ops = _ts_fold_string(left, raw, env, depth + 1)
                r_val, r_ops = _ts_fold_string(right, raw, env, depth + 1)
                if l_val is not None and r_val is not None:
                    return l_val + r_val, l_ops + r_ops + 1
    return None, 0


def analyze_js_obfuscation(
    source_bytes: bytes,
    *,
    file_path: str = "<memory>",
    external_env: dict[str, tuple[str, int]] | None = None,
) -> dict:
    digest = sha256(source_bytes).hexdigest()
    base = {
        "version": 1,
        "language": "javascript",
        "file": file_path,
        "source_sha256": digest,
        "status": "completed",
        "reason": "analyzed",
        "delta_score": 0,
        "signals": [],
        "ffi_targets": [],
        "sink_aliases": [],
    }
    if len(source_bytes) > MAX_SOURCE_BYTES:
        return {**base, "status": "partial", "reason": "source_limit"}
    try:
        source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return {**base, "status": "unavailable", "reason": "parse_error"}
    if _TS_PARSER is None or _TSX_PARSER is None:
        return {**base, "status": "unavailable", "reason": "grammar_unavailable"}

    parser = _TSX_PARSER if file_path.endswith((".tsx", ".jsx")) else _TS_PARSER
    root = parser.parse(source_bytes).root_node
    if root.has_error and parser is _TS_PARSER:
        alt = _TSX_PARSER.parse(source_bytes).root_node
        if not alt.has_error:
            root = alt
    if root.has_error:
        return {**base, "status": "unavailable", "reason": "parse_error"}

    nodes = []
    stack = [root]
    while stack:
        curr = stack.pop()
        nodes.append(curr)
        if len(nodes) > MAX_AST_NODES:
            return {**base, "status": "partial", "reason": "ast_node_limit"}
        stack.extend(reversed(curr.children))

    js_env: dict[str, tuple[str, int]] = dict(external_env or {})
    for _ in range(3):
        for n in nodes:
            if n.type == "lexical_declaration" and source_bytes[n.start_byte:n.start_byte + 5] == b"const":
                for decl in n.named_children:
                    if decl.type != "variable_declarator":
                        continue
                    name_node = decl.child_by_field_name("name")
                    val_node = decl.child_by_field_name("value")
                    if name_node is not None and name_node.type == "identifier" and val_node is not None:
                        ident = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                        if ident not in js_env:
                            val, ops = _ts_fold_string(val_node, source_bytes, js_env)
                            if val is not None and len(val) <= 512:
                                js_env[ident] = (val, ops)

    signals: list[dict] = []
    ffi_targets: list[dict] = []

    for node in nodes:
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None and cond.type == "parenthesized_expression" and len(cond.named_children) == 1:
                inner = cond.named_children[0]
                if inner.type in ("true", "false"):
                    signals.append({
                        "kind": "constant_branch_guard",
                        "polarity": "dead_branch" if inner.type == "false" else "trivial_branch",
                        "span": _ts_span(node),
                    })
        elif node.type == "catch_clause":
            body = node.child_by_field_name("body")
            if body is not None and len(body.named_children) == 0:
                signals.append({
                    "kind": "silent_exception_swallow",
                    "bare_except": node.child_by_field_name("parameter") is None,
                    "span": _ts_span(node),
                })
        elif node.type == "binary_expression":
            if node.parent is not None and node.parent.type == "binary_expression":
                continue
            folded, ops = _ts_fold_string(node, source_bytes, js_env)
            if folded and ops >= 1 and _contains_sensitive_token(folded):
                signals.append({"kind": "split_sensitive_literal", "ops": ops, "span": _ts_span(node)})
        elif node.type == "subscript_expression":
            idx = node.child_by_field_name("index")
            if idx is not None:
                prop, ops = _ts_fold_string(idx, source_bytes, js_env)
                if prop in DANGEROUS_ATTRS:
                    signals.append({
                        "kind": "computed_member_sink", "symbol": prop,
                        "split_ops": ops, "span": _ts_span(node),
                    })
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn is None or args_node is None:
                continue
            args = args_node.named_children
            fn_text = source_bytes[fn.start_byte:fn.end_byte].decode("utf-8", errors="ignore")

            if fn_text == "atob" and len(args) == 1:
                raw_arg, _ = _ts_fold_string(args[0], source_bytes, js_env)
                decoded, codec = _try_decode_codec(raw_arg or "", "base64")
                if decoded and _contains_sensitive_token(decoded):
                    signals.append({"kind": "encoded_sensitive_constant", "codec": codec, "span": _ts_span(node)})
            elif fn_text == "Buffer.from" and len(args) >= 2:
                raw_arg, _ = _ts_fold_string(args[0], source_bytes, js_env)
                enc_arg, _ = _ts_fold_string(args[1], source_bytes, js_env)
                if enc_arg in ("base64", "hex"):
                    decoded, codec = _try_decode_codec(raw_arg or "", enc_arg)
                    if decoded and _contains_sensitive_token(decoded):
                        signals.append({"kind": "encoded_sensitive_constant", "codec": codec, "span": _ts_span(node)})
            elif fn_text in ("require", "import") and len(args) == 1:
                mod_name, ops = _ts_fold_string(args[0], source_bytes, js_env)
                if mod_name:
                    if ops >= 1 and mod_name in DANGEROUS_MODULES:
                        signals.append({
                            "kind": "dynamic_import_sink", "module": mod_name,
                            "split_ops": ops, "span": _ts_span(node),
                        })
                    if mod_name.endswith((".node", ".so")):
                        if ops >= 1:
                            signals.append({"kind": "split_ffi_library_path", "ops": ops, "span": _ts_span(node)})
                        ffi_targets.append({
                            "library_arg": mod_name[:256],
                            "dynamic_path": False,
                            "split_ops": ops,
                            "span": _ts_span(node),
                        })
            elif fn_text.endswith(".dlopen") and len(args) >= 2:
                lib_path, ops = _ts_fold_string(args[1], source_bytes, js_env)
                if lib_path and ops >= 1:
                    signals.append({"kind": "split_ffi_library_path", "ops": ops, "span": _ts_span(node)})
                ffi_targets.append({
                    "library_arg": lib_path[:256] if lib_path else None,
                    "dynamic_path": lib_path is None,
                    "split_ops": ops,
                    "span": _ts_span(node),
                })

    signals.sort(key=lambda item: (item["span"], item["kind"]))
    ffi_targets.sort(key=lambda item: item["span"])
    score = sum(WEIGHTS.get(sig["kind"], 1) for sig in signals)
    return {
        **base,
        "delta_score": score,
        "signals": signals[:128],
        "ffi_targets": ffi_targets[:32],
        "sink_aliases": [],
    }


def _eligible_source_path(path: str) -> str | None:
    if path == BINARY_EVIDENCE_PATH or path.endswith("/" + BINARY_EVIDENCE_PATH):
        return None
    parts = PurePosixPath(path).parts
    if any(part in EXCLUDED_PARTS for part in parts):
        return None
    lower = path.lower()
    if lower.endswith(PY_SUFFIXES):
        return "python"
    if lower.endswith(JS_SUFFIXES):
        return "javascript"
    return None


def _py_module_keys(path: str) -> tuple[str, ...]:
    no_ext = path[:-3] if path.endswith(".py") else path
    if no_ext.endswith("/__init__"):
        pkg = no_ext[:-9].replace("/", ".")
        return (pkg, no_ext.replace("/", ".")) if pkg else ("__init__",)
    dotted = no_ext.replace("/", ".")
    parts = dotted.split(".")
    if len(parts) >= 2 and parts[0] in {"src", "lib"}:
        return (dotted, ".".join(parts[1:]))
    return (dotted,)


def _resolve_relative_js_path(importer_path: str, spec: str, known_js_paths: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base_dir = PurePosixPath(importer_path).parent
    joined = PurePosixPath(base_dir / spec)
    norm_parts: list[str] = []
    for part in joined.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not norm_parts:
                return None
            norm_parts.pop()
        else:
            norm_parts.append(part)
    stem = "/".join(norm_parts)
    for cand in (stem, *(stem + ext for ext in JS_SUFFIXES), *(f"{stem}/index{ext}" for ext in JS_SUFFIXES)):
        if cand in known_js_paths:
            return cand
    return None


def _build_cross_file_const_envs(
    raw_by_path: dict[str, tuple[str, bytes]],
) -> dict[str, dict[str, tuple[str, int]]]:
    py_trees: dict[str, ast.Module] = {}
    py_mod_to_path: dict[str, str] = {}
    js_paths = {p for p, (lang, _) in raw_by_path.items() if lang == "javascript"}

    exports_by_file: dict[str, dict[str, tuple[str, int]]] = {p: {} for p in raw_by_path}
    imports_by_file: dict[str, list[tuple[str, str, str]]] = {p: [] for p in raw_by_path}

    for path, (lang, raw) in raw_by_path.items():
        if len(raw) > MAX_SOURCE_BYTES:
            continue
        if lang == "python":
            for m_key in _py_module_keys(path):
                py_mod_to_path.setdefault(m_key, path)
            try:
                py_trees[path] = ast.parse(raw.decode("utf-8"))
            except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
                continue

    for path, tree in py_trees.items():
        pkg_parts = PurePosixPath(path).parent.parts
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom):
                base_mod = stmt.module or ""
                if stmt.level > 0:
                    up = stmt.level - 1
                    prefix = pkg_parts[:-up] if up and up <= len(pkg_parts) else pkg_parts
                    full_mod = ".".join([*prefix, *([base_mod] if base_mod else [])])
                else:
                    full_mod = base_mod
                target_file = py_mod_to_path.get(full_mod)
                if target_file and target_file != path:
                    for alias in stmt.names:
                        if alias.name != "*":
                            imports_by_file[path].append((alias.asname or alias.name, target_file, alias.name))

    js_roots = {}
    if _TS_PARSER is not None and _TSX_PARSER is not None:
        for path in sorted(js_paths):
            raw = raw_by_path[path][1]
            if len(raw) > MAX_SOURCE_BYTES:
                continue
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            parser = _TSX_PARSER if path.endswith((".tsx", ".jsx")) else _TS_PARSER
            root = parser.parse(raw).root_node
            if not root.has_error:
                js_roots[path] = (root, raw)
                for child in root.named_children:
                    if child.type in ("import_statement", "export_statement"):
                        src_node = child.child_by_field_name("source")
                        if src_node is None:
                            continue
                        spec_str = _ts_unquote(src_node, raw)
                        target_js = _resolve_relative_js_path(path, spec_str, js_paths) if spec_str else None
                        if not target_js or target_js == path:
                            continue
                        for sub in child.named_children:
                            if sub.type in ("import_clause", "export_clause"):
                                stack = [sub]
                                while stack:
                                    cur = stack.pop()
                                    if cur.type in ("import_specifier", "export_specifier"):
                                        orig = cur.child_by_field_name("name")
                                        alias = cur.child_by_field_name("alias") or orig
                                        if orig is not None and alias is not None:
                                            o_b = raw[orig.start_byte:orig.end_byte]
                                            a_b = raw[alias.start_byte:alias.end_byte]
                                            o_txt = o_b.decode("utf-8", errors="ignore")
                                            a_txt = a_b.decode("utf-8", errors="ignore")
                                            imports_by_file[path].append((a_txt, target_js, o_txt))
                                            if child.type == "export_statement":
                                                re_key = f"__reexport__:{a_txt}"
                                                imports_by_file[path].append((re_key, target_js, o_txt))
                                    else:
                                        stack.extend(cur.named_children)

    external_envs: dict[str, dict[str, tuple[str, int]]] = {p: {} for p in raw_by_path}
    for _hop in range(4):
        for path, links in imports_by_file.items():
            for local_name, target_file, remote_sym in links:
                if remote_sym in exports_by_file.get(target_file, {}):
                    val, ops = exports_by_file[target_file][remote_sym]
                    if local_name.startswith("__reexport__:"):
                        exp_name = local_name.split(":", 1)[1]
                        exports_by_file[path][exp_name] = (val, ops + 1)
                    else:
                        external_envs[path][local_name] = (val, ops + 1)

        for path, tree in py_trees.items():
            local_env = dict(external_envs[path])
            top_stores: dict[str, int] = {}
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    nm = stmt.targets[0].id
                    top_stores[nm] = top_stores.get(nm, 0) + 1
            for stmt in tree.body:
                if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name)
                        and top_stores.get(stmt.targets[0].id) == 1):
                    nm = stmt.targets[0].id
                    val, ops = _fold_string_expr(stmt.value, local_env)
                    if val is not None and len(val) <= 512:
                        local_env[nm] = (val, ops)
                        exports_by_file[path][nm] = (val, ops)

        for path, (root, raw) in js_roots.items():
            local_env = dict(external_envs[path])
            for child in root.named_children:
                decl_parent = None
                is_exported = False
                if child.type == "lexical_declaration" and raw[child.start_byte:child.start_byte + 5] == b"const":
                    decl_parent = child
                elif child.type == "export_statement":
                    is_exported = True
                    for sub in child.named_children:
                        if sub.type == "lexical_declaration" and raw[sub.start_byte:sub.start_byte + 5] == b"const":
                            decl_parent = sub
                        elif sub.type == "export_clause":
                            for spec in sub.named_children:
                                if spec.type == "export_specifier":
                                    orig = spec.child_by_field_name("name")
                                    alias = spec.child_by_field_name("alias") or orig
                                    if orig is not None and alias is not None:
                                        o_txt = raw[orig.start_byte:orig.end_byte].decode("utf-8", errors="ignore")
                                        a_txt = raw[alias.start_byte:alias.end_byte].decode("utf-8", errors="ignore")
                                        if o_txt in local_env:
                                            exports_by_file[path][a_txt] = local_env[o_txt]
                if decl_parent is not None:
                    for decl in decl_parent.named_children:
                        if decl.type != "variable_declarator":
                            continue
                        n_node = decl.child_by_field_name("name")
                        v_node = decl.child_by_field_name("value")
                        if n_node is not None and n_node.type == "identifier" and v_node is not None:
                            ident = raw[n_node.start_byte:n_node.end_byte].decode("utf-8", errors="ignore")
                            val, ops = _ts_fold_string(v_node, raw, local_env)
                            if val is not None and len(val) <= 512:
                                local_env[ident] = (val, ops)
                                if is_exported:
                                    exports_by_file[path][ident] = (val, ops)

    return external_envs


def analyze_archive_code_dna(data: bytes) -> dict:
    """Scan eligible Python and JS/TS files in a ZIP archive with 2-pass cross-file unrolling."""
    validate_zip(io.BytesIO(data), len(data))
    archive_hash = sha256(data).hexdigest()
    files_analyzed = 0
    files_omitted = 0
    bytes_parsed = 0
    partial_files = 0
    flagged_files = []
    all_ffi_bridges = []
    raw_by_path: dict[str, tuple[str, bytes]] = {}

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = sorted(
            (str(PurePosixPath(info.filename.replace("\\", "/"))), info)
            for info in archive.infolist()
            if not info.is_dir() and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
        )
        for path, info in entries:
            lang = _eligible_source_path(path)
            if lang is None:
                continue
            if files_analyzed >= MAX_ARCHIVE_FILES or bytes_parsed + info.file_size > MAX_ARCHIVE_PARSED_BYTES:
                files_omitted += 1
                continue
            raw = archive.read(info)
            bytes_parsed += len(raw)
            files_analyzed += 1
            raw_by_path[path] = (lang, raw)

    cross_envs = _build_cross_file_const_envs(raw_by_path)

    for path, (lang, raw) in raw_by_path.items():
        ext_env = cross_envs.get(path) or None
        res = (analyze_python_obfuscation(raw, file_path=path, external_env=ext_env) if lang == "python"
               else analyze_js_obfuscation(raw, file_path=path, external_env=ext_env))
        if ext_env and res["signals"]:
            used_cross = any(
                sig.get("split_ops", 0) >= 1 or sig["kind"] in ("split_sensitive_literal", "split_ffi_library_path")
                for sig in res["signals"]
            )
            if used_cross and any(tok.encode("utf-8") in raw for tok in ext_env):
                res["signals"].append({"kind": "cross_file_const_assembly", "span": [1, 0, 1, 1]})
                res["delta_score"] += WEIGHTS["cross_file_const_assembly"]
        if res["status"] != "completed":
            partial_files += 1
        if res["delta_score"] > 0 or res["ffi_targets"]:
            flagged_files.append(res)
        for ffi in res["ffi_targets"]:
            all_ffi_bridges.append({"source_file": path, "source_sha256": res["source_sha256"], **ffi})

    status = "partial" if (files_omitted or partial_files) else "completed"
    return {
        "schema": 1,
        "archive_sha256": archive_hash,
        "status": status,
        "files_analyzed": files_analyzed,
        "files_omitted": files_omitted,
        "partial_files": partial_files,
        "max_delta_score": max((f["delta_score"] for f in flagged_files), default=0),
        "flagged_files": flagged_files,
        "ffi_bridges": all_ffi_bridges,
    }
