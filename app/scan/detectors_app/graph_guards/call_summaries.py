"""Deterministic inter-procedural guard & taint summaries over Tarjan SCCs.

Pure-Python, zero native dependencies, bounded memory/CPU so server scans,
`drydock-local`, and Pyodide WASM produce identical results.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass
from typing import Iterable

from app.scan.detectors_app.graph_guards.cfg_builder import (
    CFGBuildLimitError,
    build_function_cfg,
)
from app.scan.detectors_app.graph_guards.guard_specs import (
    SQL_RUNNER_METHODS,
    classify_branch_guard,
    classify_standalone_guard_call,
    find_privileged_sink,
)

MAX_SUMMARY_FUNCTIONS = 2_500
MAX_CALLEE_CHAIN = 5

SANITIZER_CALLS = frozenset({
    "int",
    "float",
    "bool",
    "uuid",
    "UUID",
    "Decimal",
    "quote",
    "quote_plus",
    "escape",
    "html_escape",
})

UNTRUSTED_REQUEST_ATTRS = frozenset({
    "args",
    "query_params",
    "form",
    "values",
    "headers",
    "cookies",
    "json",
    "body",
    "data",
    "GET",
    "POST",
})

ROUTE_DECORATOR_METHODS = frozenset({
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "route",
    "api_route",
    "websocket",
})

SHELL_SINK_CALLS = frozenset({"system", "popen"})
SUBPROCESS_CALLS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
DESER_MODULES_AND_CALLS = frozenset({"loads", "load", "unsafe_load"})
SAFE_FRAMEWORK_PARAMS = frozenset({
    "self",
    "cls",
    "db",
    "session",
    "conn",
    "cursor",
    "cur",
    "background_tasks",
    "current_user",
    "user",
})


@dataclass(frozen=True)
class DelegatedSink:
    sink_label: str
    origin_file: str
    origin_line: int
    callee_chain: tuple[str, ...]


@dataclass(frozen=True)
class ParamSinkFlow:
    param_index: int
    param_name: str
    sink_kind: str  # "sql_exec" | "shell_exec" | "unsafe_deser"
    sink_label: str
    origin_file: str
    origin_line: int
    callee_chain: tuple[str, ...]


@dataclass(frozen=True)
class FunctionSummary:
    qual_id: str
    rel_file: str
    func_name: str
    lineno: int
    param_names: tuple[str, ...]
    must_guards: frozenset[str]
    unguarded_sinks: tuple[DelegatedSink, ...]
    param_to_return: frozenset[int]
    returns_untrusted_source: bool
    param_to_sinks: tuple[ParamSinkFlow, ...]


@dataclass
class ParsedFunctionUnit:
    qual_id: str
    module_key: str
    rel_file: str
    func_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    param_names: tuple[str, ...]
    is_method: bool
    imports_map: dict[str, str]


def module_key_from_path(rel_file: str) -> str:
    clean = rel_file.replace("\\", "/").strip("/")
    parts = clean.split("/")
    if len(parts) > 1 and ("-" in parts[0] and not parts[0].endswith(".py")):
        if any(p in {"app", "src", "api", "routes", "services", "backend", "server"} for p in parts[1:3]):
            parts = parts[1:]
    joined = "/".join(parts)
    if joined.endswith("/__init__.py"):
        joined = joined[: -len("/__init__.py")]
    elif joined.endswith(".py"):
        joined = joined[: -len(".py")]
    return joined.replace("/", ".")


def _call_name_parts(call: ast.Call) -> tuple[str | None, str | None]:
    fn = call.func
    if isinstance(fn, ast.Name):
        return (None, fn.id)
    if isinstance(fn, ast.Attribute):
        if isinstance(fn.value, ast.Name):
            return (fn.value.id, fn.attr)
        return (None, fn.attr)
    return (None, None)


def resolve_callee_id(
    call: ast.Call,
    caller: ParsedFunctionUnit,
    by_qual: dict[str, ParsedFunctionUnit],
    by_unique_tail: dict[str, str | None],
) -> str | None:
    recv, tail = _call_name_parts(call)
    if not tail:
        return None
    if recv is None:
        imp_target = caller.imports_map.get(tail)
        if imp_target and imp_target in by_qual:
            return imp_target
        same_mod = f"{caller.module_key}:{tail}"
        if same_mod in by_qual:
            return same_mod
    elif recv in {"self", "cls"}:
        prefix = caller.qual_id.rsplit(".", 1)[0]
        cand = f"{prefix}.{tail}"
        if cand in by_qual:
            return cand
    elif recv in caller.imports_map:
        mod_prefix = caller.imports_map[recv]
        cand = f"{mod_prefix}:{tail}"
        if cand in by_qual:
            return cand

    uniq = by_unique_tail.get(tail)
    if uniq is not None and uniq != caller.qual_id:
        return uniq
    return None


def tarjan_scc(nodes: Iterable[str], adj: dict[str, set[str]]) -> list[list[str]]:
    """Iterative Tarjan strongly connected components in reverse topological order."""
    index_counter = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []

    for start in sorted(nodes):
        if start in indices:
            continue
        work: list[tuple[str, list[str], int]] = [
            (start, sorted(adj.get(start, ())), 0)
        ]
        indices[start] = lowlink[start] = index_counter
        index_counter += 1
        stack.append(start)
        on_stack.add(start)

        while work:
            v, neighs, idx = work[-1]
            if idx < len(neighs):
                work[-1] = (v, neighs, idx + 1)
                w = neighs[idx]
                if w not in indices:
                    indices[w] = lowlink[w] = index_counter
                    index_counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, sorted(adj.get(w, ())), 0))
                elif w in on_stack:
                    if indices[w] < lowlink[v]:
                        lowlink[v] = indices[w]
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    if lowlink[v] < lowlink[parent]:
                        lowlink[parent] = lowlink[v]
                if lowlink[v] == indices[v]:
                    comp: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.remove(w)
                        comp.append(w)
                        if w == v:
                            break
                    sccs.append(comp)
    return sccs


def _reachable(start: int, target: int, adj: dict[int, list[int]]) -> bool:
    q: deque[int] = deque([start])
    seen: set[int] = {start}
    while q:
        u = q.popleft()
        if u == target:
            return True
        for nxt in adj.get(u, ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False


def _is_sanitizer_call(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Call):
        _, tail = _call_name_parts(expr)
        if tail in SANITIZER_CALLS:
            return True
    return False


def _expr_reads_request_source(expr: ast.expr, request_names: set[str]) -> bool:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Attribute) and sub.attr in UNTRUSTED_REQUEST_ATTRS:
            if isinstance(sub.value, ast.Name) and sub.value.id in request_names:
                return True
            if sub.attr in {"query_params", "cookies", "headers", "form"}:
                return True
        if isinstance(sub, ast.Call):
            recv, tail = _call_name_parts(sub)
            if recv in request_names and tail in {"json", "body", "form"}:
                return True
    return False


def _is_string_built_sql_expr(expr: ast.expr) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in expr.values)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr in {"format", "join"}:
            return True
    return False


def is_route_entrypoint(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr.lower() in ROUTE_DECORATOR_METHODS:
            return True
        if isinstance(target, ast.Name) and target.id.lower() in {"route", "login_required"}:
            return True
    return False


def _direct_sink_on_tainted_expr(
    call: ast.Call,
    expr_taint_fn,
) -> tuple[set[str], str, str] | None:
    recv, tail = _call_name_parts(call)
    if not tail:
        return None

    if tail in SQL_RUNNER_METHODS and call.args:
        q_arg = call.args[0]
        origins, built = expr_taint_fn(q_arg)
        if origins and (built or _is_string_built_sql_expr(q_arg)):
            return (origins, "sql_exec", f"{tail}(dynamic SQL)")

    if (recv == "os" and tail in SHELL_SINK_CALLS and call.args) or (
        recv == "subprocess"
        and tail in SUBPROCESS_CALLS
        and call.args
        and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call.keywords
        )
    ):
        origins, _ = expr_taint_fn(call.args[0])
        if origins:
            return (origins, "shell_exec", f"{recv}.{tail}")

    if (recv in {"pickle", "cPickle", "dill", "marshal"} and tail in DESER_MODULES_AND_CALLS and call.args) or (
        recv == "yaml" and tail == "unsafe_load" and call.args
    ):
        origins, _ = expr_taint_fn(call.args[0])
        if origins:
            return (origins, "unsafe_deser", f"{recv}.{tail}")

    return None


def _compute_single_summary(
    unit: ParsedFunctionUnit,
    summaries: dict[str, FunctionSummary],
    by_qual: dict[str, ParsedFunctionUnit],
    by_unique_tail: dict[str, str | None],
) -> FunctionSummary:
    must_guards: set[str] = set()
    unguarded_sinks: list[DelegatedSink] = []

    try:
        cfg = build_function_cfg(unit.node)
    except CFGBuildLimitError:
        cfg = None

    if cfg is not None:
        standalone_guards: dict[str, set[tuple[int, int]]] = {"authz": set(), "signature": set()}
        branch_guards: dict[str, set[tuple[int, int, str]]] = {"authz": set(), "signature": set()}
        block_sinks: dict[int, DelegatedSink] = {}

        for bid, block in cfg.blocks.items():
            if block.is_synthetic:
                continue
            active_guard: str | None = None
            for stmt in block.statements:
                s_cls = classify_standalone_guard_call(stmt)
                if s_cls is None and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    cid = resolve_callee_id(stmt.value, unit, by_qual, by_unique_tail)
                    if cid and cid in summaries:
                        for g_c in ("signature", "authz"):
                            if g_c in summaries[cid].must_guards:
                                s_cls = g_c
                                break
                if s_cls is not None:
                    active_guard = s_cls

                if bid not in block_sinks and active_guard is None:
                    direct_priv = find_privileged_sink(stmt)
                    if direct_priv is not None:
                        lbl, ln = direct_priv
                        block_sinks[bid] = DelegatedSink(
                            sink_label=lbl,
                            origin_file=unit.rel_file,
                            origin_line=ln,
                            callee_chain=(unit.func_name,),
                        )
                    else:
                        for sub in ast.walk(stmt):
                            if isinstance(sub, ast.Call):
                                cid = resolve_callee_id(sub, unit, by_qual, by_unique_tail)
                                if cid and cid in summaries and summaries[cid].unguarded_sinks:
                                    first_del = summaries[cid].unguarded_sinks[0]
                                    if (
                                        len(first_del.callee_chain) < MAX_CALLEE_CHAIN
                                        and unit.func_name not in first_del.callee_chain
                                    ):
                                        block_sinks[bid] = DelegatedSink(
                                            sink_label=first_del.sink_label,
                                            origin_file=first_del.origin_file,
                                            origin_line=first_del.origin_line,
                                            callee_chain=(unit.func_name, *first_del.callee_chain),
                                        )
                                        break

            if active_guard is not None:
                for edge in cfg.succ.get(bid, ()):
                    if edge.kind != "exception":
                        standalone_guards[active_guard].add((edge.src, edge.dst))

            b_guard = classify_branch_guard(block.condition)
            if b_guard is not None:
                g_cls, protected_kind = b_guard
                for edge in cfg.succ.get(bid, ()):
                    if edge.kind == protected_kind:
                        branch_guards[g_cls].add((edge.src, edge.dst, edge.kind))

        full_adj: dict[int, list[int]] = {
            bid: [e.dst for e in edges if e.dst != cfg.abort_exit_id]
            for bid, edges in cfg.succ.items()
        }
        normal_reachable_in_full = _reachable(cfg.entry_id, cfg.normal_exit_id, full_adj)
        abort_has_preds = bool(cfg.pred.get(cfg.abort_exit_id))

        for g_cls in ("signature", "authz"):
            pos_b = branch_guards[g_cls]
            pos_s = standalone_guards[g_cls]
            if not pos_b and not pos_s:
                continue
            unguarded_adj: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
            for edge in cfg.edges:
                if edge.dst == cfg.abort_exit_id:
                    continue
                if (edge.src, edge.dst, edge.kind) in pos_b:
                    continue
                if (edge.src, edge.dst) in pos_s and edge.kind != "exception":
                    continue
                unguarded_adj[edge.src].append(edge.dst)

            if (
                normal_reachable_in_full
                and abort_has_preds
                and not _reachable(cfg.entry_id, cfg.normal_exit_id, unguarded_adj)
            ):
                must_guards.add(g_cls)

        all_pos_b = branch_guards["signature"] | branch_guards["authz"]
        all_pos_s = standalone_guards["signature"] | standalone_guards["authz"]
        unguarded_any: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
        for edge in cfg.edges:
            if edge.dst == cfg.abort_exit_id:
                continue
            if (edge.src, edge.dst, edge.kind) in all_pos_b:
                continue
            if (edge.src, edge.dst) in all_pos_s and edge.kind != "exception":
                continue
            unguarded_any[edge.src].append(edge.dst)

        for s_bid, d_sink in sorted(block_sinks.items()):
            if _reachable(cfg.entry_id, s_bid, unguarded_any):
                unguarded_sinks.append(d_sink)

    param_offset = 1 if (unit.is_method and unit.param_names and unit.param_names[0] in {"self", "cls"}) else 0
    env_taint: dict[str, set[str]] = {}
    env_built_sql: dict[str, bool] = {}
    request_names = {"request", "req"}
    for idx, pname in enumerate(unit.param_names):
        if pname in {"request", "req"}:
            request_names.add(pname)
        if idx >= param_offset:
            env_taint[pname] = {f"p:{idx}"}

    returns_to_param: set[int] = set()
    returns_untrusted = False
    param_sinks: dict[tuple[int, str], ParamSinkFlow] = {}

    def eval_expr(expr: ast.expr | None) -> tuple[set[str], bool]:
        if expr is None or _is_sanitizer_call(expr):
            return (set(), False)
        if isinstance(expr, ast.Name):
            return (set(env_taint.get(expr.id, ())), env_built_sql.get(expr.id, False))
        if _expr_reads_request_source(expr, request_names):
            return ({"SRC"}, False)
        if isinstance(expr, ast.JoinedStr):
            acc: set[str] = set()
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    sub_o, _ = eval_expr(val.value)
                    acc |= sub_o
            return (acc, bool(acc))
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            lo, _ = eval_expr(expr.left)
            ro, _ = eval_expr(expr.right)
            comb = lo | ro
            return (comb, bool(comb))
        if isinstance(expr, ast.Call):
            if _is_sanitizer_call(expr):
                return (set(), False)
            if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"format", "join"}:
                base_o, _ = eval_expr(expr.func.value)
                for a in expr.args:
                    ao, _ = eval_expr(a)
                    base_o |= ao
                for kw in expr.keywords:
                    ko, _ = eval_expr(kw.value)
                    base_o |= ko
                return (base_o, bool(base_o))

            cid = resolve_callee_id(expr, unit, by_qual, by_unique_tail)
            if cid and cid in summaries:
                cal = summaries[cid]
                out_o: set[str] = set()
                if cal.returns_untrusted_source:
                    out_o.add("SRC")
                callee_unit = by_qual.get(cid)
                c_offset = (
                    1
                    if (
                        callee_unit
                        and callee_unit.is_method
                        and callee_unit.param_names
                        and callee_unit.param_names[0] in {"self", "cls"}
                    )
                    else 0
                )
                arg_map: dict[int, tuple[set[str], bool]] = {}
                for pos_i, arg_node in enumerate(expr.args):
                    arg_map[pos_i + c_offset] = eval_expr(arg_node)
                if callee_unit:
                    name_to_idx = {n: i for i, n in enumerate(callee_unit.param_names)}
                    for kw in expr.keywords:
                        if kw.arg and kw.arg in name_to_idx:
                            arg_map[name_to_idx[kw.arg]] = eval_expr(kw.value)

                for p_idx in cal.param_to_return:
                    if p_idx in arg_map:
                        out_o |= arg_map[p_idx][0]
                return (out_o, False)

            acc_call: set[str] = set()
            if isinstance(expr.func, ast.Attribute):
                ro, rb = eval_expr(expr.func.value)
                if expr.func.attr in {"strip", "lstrip", "rstrip", "lower", "upper", "replace", "get", "pop"}:
                    acc_call |= ro
                    if rb:
                        return (acc_call, True)
            for a in expr.args:
                ao, _ = eval_expr(a)
                acc_call |= ao
            return (acc_call, False)

        if isinstance(expr, ast.Await):
            return eval_expr(expr.value)
        if isinstance(expr, ast.Subscript):
            return eval_expr(expr.value)
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            acc_seq: set[str] = set()
            built_seq = False
            for elt in expr.elts:
                eo, eb = eval_expr(elt)
                acc_seq |= eo
                built_seq = built_seq or eb
            return (acc_seq, built_seq)
        if isinstance(expr, ast.IfExp):
            bo, bb = eval_expr(expr.body)
            oo, ob = eval_expr(expr.orelse)
            return (bo | oo, bb or ob)
        return (set(), False)

    def walk_stmts(stmts: list[ast.stmt], allowlist_guarded: set[str]) -> None:
        nonlocal returns_untrusted
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.If):
                guarded_here = set(allowlist_guarded)
                cond = stmt.test
                if isinstance(cond, ast.Compare) and len(cond.ops) == 1:
                    if isinstance(cond.ops[0], ast.In) and isinstance(cond.left, ast.Name):
                        guarded_here.add(cond.left.id)
                    elif isinstance(cond.ops[0], ast.NotIn) and isinstance(cond.left, ast.Name):
                        if stmt.body and isinstance(stmt.body[-1], (ast.Raise, ast.Return)):
                            walk_stmts(stmt.body, allowlist_guarded)
                            allowlist_guarded = set(allowlist_guarded) | {cond.left.id}
                            continue
                walk_stmts(stmt.body, guarded_here)
                walk_stmts(stmt.orelse, allowlist_guarded)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                walk_stmts(stmt.body, allowlist_guarded)
                continue
            if isinstance(stmt, ast.Try):
                walk_stmts(stmt.body, allowlist_guarded)
                for h in stmt.handlers:
                    walk_stmts(h.body, allowlist_guarded)
                walk_stmts(stmt.orelse, allowlist_guarded)
                walk_stmts(stmt.finalbody, allowlist_guarded)
                continue

            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                tgt = stmt.targets[0].id
                orig, built = eval_expr(stmt.value)
                orig = {o for o in orig if tgt not in allowlist_guarded}
                if orig:
                    env_taint[tgt] = orig
                    env_built_sql[tgt] = built
                else:
                    env_taint.pop(tgt, None)
                    env_built_sql.pop(tgt, None)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                tgt = stmt.target.id
                orig, built = eval_expr(stmt.value)
                if orig and tgt not in allowlist_guarded:
                    env_taint[tgt] = orig
                    env_built_sql[tgt] = built

            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                direct = _direct_sink_on_tainted_expr(sub, eval_expr)
                if direct is not None:
                    origins, s_kind, s_label = direct
                    for tag in origins:
                        if tag.startswith("p:"):
                            p_idx = int(tag.split(":", 1)[1])
                            p_name = unit.param_names[p_idx]
                            if p_name not in allowlist_guarded:
                                param_sinks.setdefault(
                                    (p_idx, s_kind),
                                    ParamSinkFlow(
                                        param_index=p_idx,
                                        param_name=p_name,
                                        sink_kind=s_kind,
                                        sink_label=s_label,
                                        origin_file=unit.rel_file,
                                        origin_line=getattr(sub, "lineno", unit.node.lineno),
                                        callee_chain=(unit.func_name,),
                                    ),
                                )
                else:
                    cid = resolve_callee_id(sub, unit, by_qual, by_unique_tail)
                    if cid and cid in summaries and summaries[cid].param_to_sinks:
                        cal_s = summaries[cid]
                        callee_unit = by_qual.get(cid)
                        c_offset = (
                            1
                            if (
                                callee_unit
                                and callee_unit.is_method
                                and callee_unit.param_names
                                and callee_unit.param_names[0] in {"self", "cls"}
                            )
                            else 0
                        )
                        arg_map: dict[int, tuple[set[str], bool]] = {}
                        for pos_i, arg_node in enumerate(sub.args):
                            arg_map[pos_i + c_offset] = eval_expr(arg_node)
                        if callee_unit:
                            name_to_idx = {n: i for i, n in enumerate(callee_unit.param_names)}
                            for kw in sub.keywords:
                                if kw.arg and kw.arg in name_to_idx:
                                    arg_map[name_to_idx[kw.arg]] = eval_expr(kw.value)

                        for p_flow in cal_s.param_to_sinks:
                            if (
                                p_flow.param_index in arg_map
                                and len(p_flow.callee_chain) < MAX_CALLEE_CHAIN
                                and unit.func_name not in p_flow.callee_chain
                            ):
                                passed_origins, _ = arg_map[p_flow.param_index]
                                for tag in passed_origins:
                                    if tag.startswith("p:"):
                                        caller_p_idx = int(tag.split(":", 1)[1])
                                        caller_p_name = unit.param_names[caller_p_idx]
                                        if caller_p_name not in allowlist_guarded:
                                            param_sinks.setdefault(
                                                (caller_p_idx, p_flow.sink_kind),
                                                ParamSinkFlow(
                                                    param_index=caller_p_idx,
                                                    param_name=caller_p_name,
                                                    sink_kind=p_flow.sink_kind,
                                                    sink_label=p_flow.sink_label,
                                                    origin_file=p_flow.origin_file,
                                                    origin_line=p_flow.origin_line,
                                                    callee_chain=(unit.func_name, *p_flow.callee_chain),
                                                ),
                                            )

            if isinstance(stmt, ast.Return) and stmt.value is not None:
                ret_o, _ = eval_expr(stmt.value)
                for tag in ret_o:
                    if tag == "SRC":
                        returns_untrusted = True
                    elif tag.startswith("p:"):
                        p_idx = int(tag.split(":", 1)[1])
                        if unit.param_names[p_idx] not in allowlist_guarded:
                            returns_to_param.add(p_idx)

    walk_stmts(unit.node.body, set())

    return FunctionSummary(
        qual_id=unit.qual_id,
        rel_file=unit.rel_file,
        func_name=unit.func_name,
        lineno=unit.node.lineno,
        param_names=unit.param_names,
        must_guards=frozenset(must_guards),
        unguarded_sinks=tuple(unguarded_sinks),
        param_to_return=frozenset(returns_to_param),
        returns_untrusted_source=returns_untrusted,
        param_to_sinks=tuple(param_sinks.values()),
    )


@dataclass
class RepositoryCallIndex:
    units: dict[str, ParsedFunctionUnit]
    by_unique_tail: dict[str, str | None]
    summaries: dict[str, FunctionSummary]


def build_repository_summaries(parsed_files: list[tuple[str, ast.Module]]) -> RepositoryCallIndex:
    """Parse module imports/functions, run Tarjan SCC, and compute fixpoint summaries."""
    units: dict[str, ParsedFunctionUnit] = {}
    tail_counts: dict[str, list[str]] = {}

    module_exports: dict[str, set[str]] = {}
    raw_modules: list[tuple[str, str, ast.Module]] = []
    for rel_file, tree in parsed_files:
        mod_key = module_key_from_path(rel_file)
        raw_modules.append((rel_file, mod_key, tree))
        exported: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                exported.add(node.name)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        exported.add(f"{node.name}.{item.name}")
        module_exports[mod_key] = exported

    for rel_file, mod_key, tree in raw_modules:
        if len(units) >= MAX_SUMMARY_FUNCTIONS:
            break
        imports_map: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                target_mod = node.module
                if node.level > 0:
                    base_parts = mod_key.split(".")[:-node.level]
                    target_mod = ".".join([*base_parts, node.module]).strip(".")
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    cand_fn = f"{target_mod}:{alias.name}"
                    if alias.name in module_exports.get(target_mod, ()):
                        imports_map[local_name] = cand_fn
                    else:
                        imports_map[local_name] = f"{target_mod}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    imports_map[local_name] = alias.name

        for node in tree.body:
            if len(units) >= MAX_SUMMARY_FUNCTIONS:
                break
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qid = f"{mod_key}:{node.name}"
                pnames = tuple(a.arg for a in node.args.args)
                units[qid] = ParsedFunctionUnit(
                    qual_id=qid,
                    module_key=mod_key,
                    rel_file=rel_file,
                    func_name=node.name,
                    node=node,
                    param_names=pnames,
                    is_method=False,
                    imports_map=imports_map,
                )
                tail_counts.setdefault(node.name, []).append(qid)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if len(units) >= MAX_SUMMARY_FUNCTIONS:
                        break
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qid = f"{mod_key}:{node.name}.{item.name}"
                        pnames = tuple(a.arg for a in item.args.args)
                        units[qid] = ParsedFunctionUnit(
                            qual_id=qid,
                            module_key=mod_key,
                            rel_file=rel_file,
                            func_name=f"{node.name}.{item.name}",
                            node=item,
                            param_names=pnames,
                            is_method=True,
                            imports_map=imports_map,
                        )
                        tail_counts.setdefault(item.name, []).append(qid)

    by_unique_tail: dict[str, str | None] = {
        t: qids[0] if len(qids) == 1 else None for t, qids in tail_counts.items()
    }

    call_adj: dict[str, set[str]] = {qid: set() for qid in units}
    for qid, unit in units.items():
        for sub in ast.walk(unit.node):
            if isinstance(sub, ast.Call):
                cid = resolve_callee_id(sub, unit, units, by_unique_tail)
                if cid is not None and cid in units:
                    call_adj[qid].add(cid)

    sccs = tarjan_scc(units.keys(), call_adj)
    summaries: dict[str, FunctionSummary] = {}

    for comp in sccs:
        max_iters = 1 if len(comp) == 1 and comp[0] not in call_adj.get(comp[0], ()) else min(6, len(comp) + 2)
        for _ in range(max_iters):
            changed = False
            for qid in comp:
                new_sum = _compute_single_summary(units[qid], summaries, units, by_unique_tail)
                if summaries.get(qid) != new_sum:
                    summaries[qid] = new_sum
                    changed = True
            if not changed:
                break

    return RepositoryCallIndex(
        units=units,
        by_unique_tail=by_unique_tail,
        summaries=summaries,
    )
