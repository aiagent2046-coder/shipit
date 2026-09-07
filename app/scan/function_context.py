"""Bounded full-file Python function inventory, collected before LLM review.

Cross-file matches are name candidates, NEVER resolved runtime bindings.
No uploaded code is executed. Source literals are omitted from the output.
"""
from __future__ import annotations

import ast
import builtins
from collections import Counter, defaultdict
import stat
import zipfile

from pglast import scan
from pglast.parser import ParseError

from app.scan.premise_context import update_predicates, transaction_templates
from app.scan.secrets import is_non_production_path
from app.scan.syntax_claims import completed_notification_function

MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 8_000_000
MAX_FILES = 300
MAX_FUNCTIONS = 4000
MAX_RECORDS = 64
MAX_LINKS = 4
MAX_NAME_MATCHES = 3
SCOPE = (
    "Full-file Python function syntax within explicit budgets. SQL token observations and "
    "completed-status return checks run before model review, independently of finding titles. "
    "Cross-file links are name candidates within the bounded index, not runtime binding proof. Dynamic SQL, "
    "indirect effects, lock effectiveness, input trust and harmful outcomes are not verified. "
    "UPDATE predicate shapes do not prove runtime parameter binding, affected rows or concurrency. "
    "Values redacted except fixed pending/completed status labels; test/vendor files excluded."
)
_LOCKS = {"pg_advisory_lock", "pg_try_advisory_lock", "pg_advisory_xact_lock",
          "pg_try_advisory_xact_lock", "pg_advisory_unlock"}


def _nodes(fn):
    todo = list(reversed(fn.body))
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            todo.extend(reversed(list(ast.iter_child_nodes(node))))


def _sql_tokens(text):
    """Lexer only: WHERE may belong to a subquery; never label an UPDATE safe."""
    try:
        tokens = scan(text)
    except (ParseError, ValueError):
        return []
    found = set()
    for token in tokens:
        if token.name in {"UPDATE", "WHERE", "INSERT", "SELECT", "DELETE"}:
            found.add(token.name)
        elif token.name == "IDENT":
            spelling = text[token.start:token.end + 1].lower()
            if spelling in _LOCKS:
                found.add(spelling)
    return sorted(found)


def _summary(fn, path, qualified):
    calls, queries = [], []
    for node in _nodes(fn):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else None)
        if name and len(name) <= 128:
            # Bare builtins are not candidates for unrelated class methods.
            # Shadowed builtins remain unresolved, not claimed to be builtin.
            if not (isinstance(node.func, ast.Name) and name in vars(builtins)):
                calls.append((name, node.lineno))
        if (name == "execute" and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            tokens = _sql_tokens(node.args[0].value)
            if tokens:
                queries.append({"line": node.lineno, "tokens": tokens})
                predicates = update_predicates(node.args[0].value)
                if predicates:
                    queries[-1]["updates"] = predicates
    guard = completed_notification_function(fn) if any(c[0] == "notify_operator" for c in calls) else None
    checks = transaction_templates(fn)
    for stmt in fn.body:
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Compare):
            names = sorted({n.id for n in ast.walk(stmt.value) if isinstance(n, ast.Name)})
            checks.append({"kind": "return_comparison", "result": "observed", "line": stmt.lineno,
                           "names": [n[:128] for n in names[:8]],
                           "operators": [type(op).__name__ for op in stmt.value.ops[:4]],
                           "detail": "Direct return comparison syntax; operands and enforcement not verified."})
    if queries:
        checks.append({"kind": "literal_sql_tokens", "result": "observed", "queries": queries[:8],
                       "detail": "Tokens in literal execute arguments; query execution, binding, "
                       "WHERE ownership/selectivity and lock effectiveness not checked."})
    if guard and guard["result"] == "contradicted":
        checks.append({"kind": "completed_status_return", "result": "observed",
                       "line_start": guard["line_start"], "line_end": guard["line_end"],
                       "detail": guard["detail"]})
    return {"file": path, "line": fn.lineno, "line_end": fn.end_lineno,
            "scope": qualified, "name": fn.name, "calls": calls, "checks": checks}


def collect_function_context(fileobj) -> dict:
    functions, limits = [], set()
    used = attempted = parsed = excluded = 0
    with zipfile.ZipFile(fileobj) as archive:
        infos = archive.infolist()
        counts = Counter(i.filename for i in infos)
        for info in sorted(infos, key=lambda i: i.filename):
            path = info.filename
            if info.is_dir() or not path.endswith(".py"):
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
                tree = ast.parse(archive.read(info))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                limits.add("unparseable_python")
                continue
            parsed += 1
            # Only module-level functions and direct class methods. Definitions
            # in conditionals/nested scopes need more binding context.
            definitions = [(n, n.name) for n in tree.body
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            definitions += [(n, cls.name + "." + n.name) for cls in tree.body if isinstance(cls, ast.ClassDef)
                            for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for fn, qualified in definitions:
                if len(functions) >= MAX_FUNCTIONS:
                    limits.add("function_limit_reached")
                    break
                if len(qualified) > 256:
                    limits.add("function_name_limit")
                    continue
                functions.append(_summary(fn, path, qualified))
            if "function_limit_reached" in limits:
                break
    by_name = defaultdict(list)
    for fn in functions:
        by_name[fn["name"]].append(fn)
    if any(len(by_name[name]) > MAX_NAME_MATCHES for fn in functions for name, _ in fn["calls"]):
        limits.add("ambiguous_name_matches")
    interesting = {id(fn) for fn in functions if fn["checks"]}
    # Add the direct callers of observed mechanisms (e.g. a budget helper
    # calling sum_anon_spend_today), then their callers (the worker).
    for _ in range(2):
        extra = {id(fn) for fn in functions if any(
            len(by_name[name]) <= MAX_NAME_MATCHES
            and any(id(target) in interesting for target in by_name[name]) for name, _ in fn["calls"])}
        interesting |= extra
    records = []
    for fn in functions:
        if id(fn) not in interesting:
            continue
        links = []
        seen = set()
        for name, line in fn["calls"]:
            matches = by_name[name]
            if len(matches) > MAX_NAME_MATCHES:
                limits.add("ambiguous_name_matches")
                continue
            for target in matches:
                key = (target["file"], target["line"])
                if (target["file"] == fn["file"] or not target["checks"] or key in seen):
                    continue
                seen.add(key)
                links.append({"call_line": line, "name": name, "file": target["file"],
                              "line": target["line"], "line_end": target["line_end"],
                              "scope": target["scope"], "checks": target["checks"],
                              "indexed_name_matches": len(matches),
                              "binding": "name_candidate_not_resolved"})
        def link_priority(link):
            tokens = {t for c in link["checks"] for q in c.get("queries", []) for t in q["tokens"]}
            return (0 if "UPDATE" in tokens else 1 if tokens & _LOCKS else 2,
                    link["call_line"], link["file"], link["line"])
        links.sort(key=link_priority)
        if len(links) > MAX_LINKS:
            limits.add("links_per_function_limit")
        records.append({k: fn[k] for k in ("file", "line", "line_end", "scope", "checks")} | {
            "candidates": links[:MAX_LINKS],
            "call_names": sorted({name for name, _ in fn["calls"]})[:16]})
    # Cross-file callers carry the target's observations, including functions
    # far beyond the LLM file prefix. Prefer these over isolated SQL routines.
    def priority(record):
        kinds = {c["kind"] for c in record["checks"]}
        target_tokens = {token for link in record["candidates"] for c in link["checks"]
                         for q in c.get("queries", []) for token in q["tokens"]}
        rank = (-1 if "transaction_template" in kinds else
                0 if "return_comparison" in kinds and record["candidates"] else
                1 if "completed_status_return" in kinds else
                2 if any("status_literal" in str(c) for c in record["candidates"]) else
                3 if target_tokens & _LOCKS else 4 if "UPDATE" in target_tokens else
                5 if record["candidates"] else 6)
        return rank, record["file"], record["line"]
    records.sort(key=priority)
    if len(records) > MAX_RECORDS:
        limits.add("record_limit_reached")
    return {"scope": SCOPE, "records": records[:MAX_RECORDS], "parsed_files": parsed,
            "excluded_files": excluded, "indexed_functions": len(functions), "limitations": sorted(limits)}
