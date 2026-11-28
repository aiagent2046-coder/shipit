"""Inter-procedural summary-based taint flow detector for Python repositories."""

from __future__ import annotations

import ast
from typing import BinaryIO

from app.scan.core.checks import CheckFinding
from app.scan.detectors_app.graph_guards.bypass_detector import _collect_parsed_python_files
from app.scan.detectors_app.graph_guards.call_summaries import (
    SAFE_FRAMEWORK_PARAMS,
    ParsedFunctionUnit,
    RepositoryCallIndex,
    _direct_sink_on_tainted_expr,
    _expr_reads_request_source,
    _is_sanitizer_call,
    build_repository_summaries,
    is_route_entrypoint,
    resolve_callee_id,
)

RULE_ID = "python-interprocedural-taint-flow"
MAX_FINDINGS = 50

_SINK_HUMAN_NOUN = {
    "sql_exec": "string-built SQL execution",
    "shell_exec": "shell command execution",
    "unsafe_deser": "unsafe byte deserialization",
}

_SINK_FIX_ADVICE = {
    "sql_exec": (
        "Pass values as driver parameters (`cur.execute(\"SELECT ... WHERE id = %s\", (val,))`) "
        "and validate dynamic SQL identifiers (such as `ORDER BY` columns) against a strict allowlist."
    ),
    "shell_exec": (
        "Pass an argument list to `subprocess.run([...], shell=False)` instead of invoking a shell, "
        "or validate inputs against a strict allowlist."
    ),
    "unsafe_deser": (
        "Replace `pickle.loads` / `yaml.unsafe_load` on request-derived data with `json.loads` "
        "or `yaml.safe_load`."
    ),
}


def _analyze_entrypoint_taint(
    unit: ParsedFunctionUnit,
    call_index: RepositoryCallIndex,
) -> list[CheckFinding]:
    is_route = is_route_entrypoint(unit.node)
    request_names = {"request", "req"}
    taint_env: dict[str, tuple[str, tuple[str, ...], bool]] = {}

    param_offset = (
        1
        if (unit.is_method and unit.param_names and unit.param_names[0] in {"self", "cls"})
        else 0
    )
    for idx, pname in enumerate(unit.param_names):
        if pname in {"request", "req"}:
            request_names.add(pname)
        elif is_route and idx >= param_offset and pname not in SAFE_FRAMEWORK_PARAMS:
            arg_node = unit.node.args.args[idx]
            ann = arg_node.annotation
            if isinstance(ann, ast.Name) and ann.id in {"int", "float", "bool", "UUID"}:
                continue
            taint_env[pname] = (f"route parameter `{pname}`", (), False)

    findings: list[CheckFinding] = []
    seen_sites: set[tuple[str, int, str]] = set()

    def eval_taint(expr: ast.expr | None) -> tuple[str, tuple[str, ...], bool] | None:
        if expr is None or _is_sanitizer_call(expr):
            return None
        if isinstance(expr, ast.Name):
            return taint_env.get(expr.id)
        if _expr_reads_request_source(expr, request_names):
            return ("HTTP request input", (), False)
        if isinstance(expr, ast.Await):
            return eval_taint(expr.value)
        if isinstance(expr, ast.Subscript):
            return eval_taint(expr.value)
        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    sub = eval_taint(v.value)
                    if sub is not None:
                        return (sub[0], sub[1], True)
            return None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            left = eval_taint(expr.left)
            if left is not None:
                return (left[0], left[1], True)
            right = eval_taint(expr.right)
            if right is not None:
                return (right[0], right[1], True)
            return None
        if isinstance(expr, ast.Call):
            if _is_sanitizer_call(expr):
                return None
            if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"format", "join"}:
                base = eval_taint(expr.func.value)
                if base is not None:
                    return (base[0], base[1], True)
                for a in expr.args:
                    at = eval_taint(a)
                    if at is not None:
                        return (at[0], at[1], True)
                for kw in expr.keywords:
                    kt = eval_taint(kw.value)
                    if kt is not None:
                        return (kt[0], kt[1], True)
                return None

            cid = resolve_callee_id(expr, unit, call_index.units, call_index.by_unique_tail)
            if cid and cid in call_index.summaries:
                cal = call_index.summaries[cid]
                if cal.returns_untrusted_source:
                    return ("HTTP request input", (cal.func_name,), False)
                callee_unit = call_index.units.get(cid)
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
                arg_map: dict[int, tuple[str, tuple[str, ...], bool]] = {}
                for pos_i, arg_node in enumerate(expr.args):
                    ev = eval_taint(arg_node)
                    if ev is not None:
                        arg_map[pos_i + c_offset] = ev
                if callee_unit:
                    name_to_idx = {n: i for i, n in enumerate(callee_unit.param_names)}
                    for kw in expr.keywords:
                        if kw.arg and kw.arg in name_to_idx:
                            ev = eval_taint(kw.value)
                            if ev is not None:
                                arg_map[name_to_idx[kw.arg]] = ev
                for p_idx in cal.param_to_return:
                    if p_idx in arg_map:
                        src_lbl, chain, _ = arg_map[p_idx]
                        next_chain = (*chain, cal.func_name) if cal.func_name not in chain else chain
                        return (src_lbl, next_chain, False)
                return None

            if isinstance(expr.func, ast.Attribute) and expr.func.attr in {
                "strip", "lstrip", "rstrip", "lower", "upper", "replace", "get", "pop"
            }:
                recv_t = eval_taint(expr.func.value)
                if recv_t is not None:
                    return recv_t
        return None

    def walk_body(stmts: list[ast.stmt], allowlisted: set[str]) -> None:
        for stmt in stmts:
            if len(findings) >= MAX_FINDINGS:
                return
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.If):
                guarded_branch = set(allowlisted)
                cond = stmt.test
                if isinstance(cond, ast.Compare) and len(cond.ops) == 1:
                    if isinstance(cond.ops[0], ast.In) and isinstance(cond.left, ast.Name):
                        guarded_branch.add(cond.left.id)
                    elif isinstance(cond.ops[0], ast.NotIn) and isinstance(cond.left, ast.Name):
                        if stmt.body and isinstance(stmt.body[-1], (ast.Raise, ast.Return)):
                            walk_body(stmt.body, allowlisted)
                            allowlisted = set(allowlisted) | {cond.left.id}
                            continue
                walk_body(stmt.body, guarded_branch)
                walk_body(stmt.orelse, allowlisted)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                walk_body(stmt.body, allowlisted)
                continue
            if isinstance(stmt, ast.Try):
                walk_body(stmt.body, allowlisted)
                for h in stmt.handlers:
                    walk_body(h.body, allowlisted)
                walk_body(stmt.orelse, allowlisted)
                walk_body(stmt.finalbody, allowlisted)
                continue

            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                tgt = stmt.targets[0].id
                ev = eval_taint(stmt.value)
                if ev is not None and tgt not in allowlisted:
                    taint_env[tgt] = ev
                else:
                    taint_env.pop(tgt, None)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                tgt = stmt.target.id
                ev = eval_taint(stmt.value)
                if ev is not None and tgt not in allowlisted:
                    taint_env[tgt] = ev

            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue

                def _adapter(e: ast.expr) -> tuple[set[str], bool]:
                    res = eval_taint(e)
                    if res is None:
                        return (set(), False)
                    if isinstance(e, ast.Name) and e.id in allowlisted:
                        return (set(), False)
                    return ({"HIT"}, res[2])

                direct = _direct_sink_on_tainted_expr(sub, _adapter)
                if direct is not None and sub.args:
                    _, s_kind, s_label = direct
                    ev0 = eval_taint(sub.args[0])
                    if ev0 is not None and len(ev0[1]) >= 1:
                        src_lbl, helper_chain, _ = ev0
                        ln = getattr(sub, "lineno", unit.node.lineno)
                        site_key = (unit.rel_file, ln, s_kind)
                        if site_key not in seen_sites:
                            seen_sites.add(site_key)
                            full_chain = [unit.func_name, *helper_chain]
                            findings.append(
                                _build_finding(
                                    rel_file=unit.rel_file,
                                    line=ln,
                                    entry_func=unit.func_name,
                                    source_label=src_lbl,
                                    sink_kind=s_kind,
                                    sink_label=s_label,
                                    sink_file=unit.rel_file,
                                    sink_line=ln,
                                    call_chain=full_chain,
                                )
                            )
                    continue

                cid = resolve_callee_id(sub, unit, call_index.units, call_index.by_unique_tail)
                if cid and cid in call_index.summaries and call_index.summaries[cid].param_to_sinks:
                    cal = call_index.summaries[cid]
                    callee_unit = call_index.units.get(cid)
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
                    arg_taint: dict[int, tuple[str, tuple[str, ...], bool]] = {}
                    for pos_i, arg_node in enumerate(sub.args):
                        if isinstance(arg_node, ast.Name) and arg_node.id in allowlisted:
                            continue
                        ev = eval_taint(arg_node)
                        if ev is not None:
                            arg_taint[pos_i + c_offset] = ev
                    if callee_unit:
                        name_to_idx = {n: i for i, n in enumerate(callee_unit.param_names)}
                        for kw in sub.keywords:
                            if kw.arg and kw.arg in name_to_idx:
                                if isinstance(kw.value, ast.Name) and kw.value.id in allowlisted:
                                    continue
                                ev = eval_taint(kw.value)
                                if ev is not None:
                                    arg_taint[name_to_idx[kw.arg]] = ev

                    for p_flow in cal.param_to_sinks:
                        if p_flow.param_index in arg_taint:
                            src_lbl, pre_chain, _ = arg_taint[p_flow.param_index]
                            call_ln = getattr(sub, "lineno", unit.node.lineno)
                            site_key = (p_flow.origin_file, p_flow.origin_line, p_flow.sink_kind)
                            if site_key not in seen_sites:
                                seen_sites.add(site_key)
                                full_chain = [unit.func_name, *pre_chain, *p_flow.callee_chain]
                                dedup_chain: list[str] = []
                                for fn_name in full_chain:
                                    if not dedup_chain or dedup_chain[-1] != fn_name:
                                        dedup_chain.append(fn_name)
                                findings.append(
                                    _build_finding(
                                        rel_file=p_flow.origin_file,
                                        line=p_flow.origin_line,
                                        entry_func=unit.func_name,
                                        source_label=src_lbl,
                                        sink_kind=p_flow.sink_kind,
                                        sink_label=p_flow.sink_label,
                                        sink_file=p_flow.origin_file,
                                        sink_line=p_flow.origin_line,
                                        call_chain=dedup_chain,
                                        entry_file=unit.rel_file,
                                        entry_line=call_ln,
                                    )
                                )

    walk_body(unit.node.body, set())
    return findings


def _build_finding(
    *,
    rel_file: str,
    line: int,
    entry_func: str,
    source_label: str,
    sink_kind: str,
    sink_label: str,
    sink_file: str,
    sink_line: int,
    call_chain: list[str],
    entry_file: str | None = None,
    entry_line: int | None = None,
) -> CheckFinding:
    sink_noun = _SINK_HUMAN_NOUN[sink_kind]
    chain_str = " -> ".join(call_chain)
    cross_note = (
        f" initiated at `{entry_file}:{entry_line}`"
        if entry_file and entry_file != sink_file and entry_line
        else ""
    )
    explanation = (
        f"Untrusted {source_label} enters `{entry_func}`{cross_note} and flows unvalidated "
        f"across call chain `{chain_str}` into {sink_noun} (`{sink_label}`) at `{sink_file}:{sink_line}`. "
        f"External middleware validation and runtime reachability outside the analyzed modules were not verified."
    )
    return CheckFinding(
        rule_id=RULE_ID,
        title=f"Inter-procedural untrusted input reaches {sink_noun} via `{chain_str}`",
        severity="high",
        confidence=0.86,
        category="Security",
        file=rel_file,
        line=line,
        explanation=explanation,
        fix_hint=_SINK_FIX_ADVICE[sink_kind],
        claim_evidence={
            "source_type": "static_interproc_taint_summary",
            "sink_kind": sink_kind,
            "sink_label": sink_label,
            "entry_function": entry_func,
            "call_chain": call_chain,
            "hop_count": max(1, len(call_chain) - 1),
        },
    )


def scan_interproc_taint(fileobj: BinaryIO) -> list[CheckFinding]:
    """Scan a Python archive for inter-procedural taint flows from request inputs to sinks."""
    parsed = _collect_parsed_python_files(fileobj)
    if not parsed:
        return []
    call_index = build_repository_summaries(parsed)

    findings: list[CheckFinding] = []
    seen_keys: set[tuple[str, int, str]] = set()
    for qid in sorted(call_index.units):
        unit = call_index.units[qid]
        for hit in _analyze_entrypoint_taint(unit, call_index):
            dedup_k = (hit.file, hit.line, hit.title)
            if dedup_k in seen_keys:
                continue
            seen_keys.add(dedup_k)
            findings.append(hit)
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings
