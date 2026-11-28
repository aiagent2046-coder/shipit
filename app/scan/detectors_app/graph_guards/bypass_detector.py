"""Partial Guard Bypass detector using CFG reachability, Lengauer-Tarjan, Min-Cut,
and inter-procedural Tarjan SCC guard/sink summaries.
"""

from __future__ import annotations

import ast
from collections import deque
import stat
from typing import BinaryIO
import zipfile

from app.scan.core.checks import CheckFinding
from app.scan.core.file_scope import is_dependency_path, is_generated_path
from app.scan.core.secrets import is_non_production_path
from app.scan.detectors_app.graph_guards.call_summaries import (
    ParsedFunctionUnit,
    RepositoryCallIndex,
    build_repository_summaries,
    resolve_callee_id,
)
from app.scan.detectors_app.graph_guards.cfg_builder import (
    CFGBuildLimitError,
    ControlFlowGraph,
    build_function_cfg,
)
from app.scan.detectors_app.graph_guards.dominators import compute_dominator_tree
from app.scan.detectors_app.graph_guards.guard_specs import (
    classify_branch_guard,
    classify_standalone_guard_call,
    find_privileged_sink,
)
from app.scan.detectors_app.graph_guards.min_cut import compute_optimal_fix_cut

RULE_ID = "python-cfg-partial-guard-bypass"
MAX_FILE_BYTES = 512 * 1024
MAX_FILES_SCANNED = 600
MAX_FINDINGS = 50


def _shortest_path(
    entry: int,
    targets: set[int],
    adj: dict[int, list[int]],
) -> tuple[int, ...] | None:
    queue: deque[int] = deque([entry])
    parent: dict[int, int | None] = {entry: None}
    while queue:
        u = queue.popleft()
        if u in targets:
            path: list[int] = []
            cur: int | None = u
            while cur is not None:
                path.append(cur)
                cur = parent[cur]
            path.reverse()
            return tuple(path)
        for nxt in adj.get(u, ()):
            if nxt not in parent:
                parent[nxt] = u
                queue.append(nxt)
    return None


def _can_reach_clean_exit(
    cfg: ControlFlowGraph,
    sink_blocks: set[int],
) -> set[int]:
    rev: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
    for edge in cfg.edges:
        if edge.src not in sink_blocks:
            rev[edge.dst].append(edge.src)
    clean_reaching: set[int] = set()
    q: deque[int] = deque([cfg.normal_exit_id])
    while q:
        u = q.popleft()
        if u in clean_reaching:
            continue
        clean_reaching.add(u)
        for p in rev.get(u, ()):
            if p not in clean_reaching and p not in sink_blocks:
                q.append(p)
    return clean_reaching


def analyze_function_bypass(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_file: str,
    *,
    unit: ParsedFunctionUnit | None = None,
    call_index: RepositoryCallIndex | None = None,
) -> list[CheckFinding]:
    try:
        cfg = build_function_cfg(func)
    except CFGBuildLimitError:
        return []

    sink_info: dict[int, tuple[str, int, tuple[str, ...]]] = {}
    standalone_guards: dict[str, set[tuple[int, int]]] = {"authz": set(), "signature": set()}
    branch_guards: dict[str, set[tuple[int, int, str]]] = {"authz": set(), "signature": set()}

    for bid, block in cfg.blocks.items():
        if block.is_synthetic:
            continue
        guard_cls_in_block: str | None = None
        for stmt in block.statements:
            s_cls = classify_standalone_guard_call(stmt)
            if (
                s_cls is None
                and unit is not None
                and call_index is not None
                and isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
            ):
                cid = resolve_callee_id(
                    stmt.value, unit, call_index.units, call_index.by_unique_tail
                )
                if cid and cid in call_index.summaries:
                    for g_c in ("signature", "authz"):
                        if g_c in call_index.summaries[cid].must_guards:
                            s_cls = g_c
                            break
            if s_cls is not None:
                guard_cls_in_block = s_cls

            if bid not in sink_info and guard_cls_in_block is None:
                sink = find_privileged_sink(stmt)
                if sink is not None:
                    sink_info[bid] = (sink[0], sink[1], ())
                elif unit is not None and call_index is not None:
                    for sub in ast.walk(stmt):
                        if isinstance(sub, ast.Call):
                            cid = resolve_callee_id(
                                sub, unit, call_index.units, call_index.by_unique_tail
                            )
                            if (
                                cid
                                and cid in call_index.summaries
                                and call_index.summaries[cid].unguarded_sinks
                            ):
                                d_sink = call_index.summaries[cid].unguarded_sinks[0]
                                call_ln = getattr(sub, "lineno", getattr(stmt, "lineno", 1))
                                sink_info[bid] = (
                                    d_sink.sink_label,
                                    call_ln,
                                    d_sink.callee_chain,
                                )
                                break

        if guard_cls_in_block is not None:
            for edge in cfg.succ.get(bid, ()):
                if edge.kind != "exception":
                    standalone_guards[guard_cls_in_block].add((edge.src, edge.dst))

        b_guard = classify_branch_guard(block.condition)
        if b_guard is not None:
            g_cls, protected_kind = b_guard
            for edge in cfg.succ.get(bid, ()):
                if edge.kind == protected_kind:
                    branch_guards[g_cls].add((edge.src, edge.dst, edge.kind))

    if not sink_info:
        return []

    full_adj: dict[int, list[int]] = {
        bid: [e.dst for e in edges if e.dst != cfg.abort_exit_id]
        for bid, edges in cfg.succ.items()
    }
    dom_tree = compute_dominator_tree(cfg.entry_id, full_adj)
    reachable_sinks = {bid for bid in sink_info if bid in dom_tree.reachable}
    if not reachable_sinks:
        return []

    clean_exit_blocks = _can_reach_clean_exit(cfg, reachable_sinks)
    results: list[CheckFinding] = []

    for g_cls in ("signature", "authz"):
        pos_branch = branch_guards[g_cls]
        pos_standalone = standalone_guards[g_cls]
        if not pos_branch and not pos_standalone:
            continue

        guarded_targets_exist = False
        for _, dst, _ in pos_branch:
            if _shortest_path(dst, reachable_sinks, full_adj) is not None:
                guarded_targets_exist = True
                break
        if not guarded_targets_exist:
            for _, dst in pos_standalone:
                if _shortest_path(dst, reachable_sinks, full_adj) is not None:
                    guarded_targets_exist = True
                    break
        if not guarded_targets_exist:
            continue

        unguarded_adj: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
        for edge in cfg.edges:
            if edge.dst == cfg.abort_exit_id:
                continue
            if (edge.src, edge.dst, edge.kind) in pos_branch:
                continue
            if (edge.src, edge.dst) in pos_standalone and edge.kind != "exception":
                continue
            unguarded_adj[edge.src].append(edge.dst)

        witness = _shortest_path(cfg.entry_id, reachable_sinks, unguarded_adj)
        if witness is None:
            continue

        vuln_sinks = {
            s_bid for s_bid in reachable_sinks
            if _shortest_path(cfg.entry_id, {s_bid}, unguarded_adj) is not None
        }

        weights: dict[int, int] = {}
        for bid, blk in cfg.blocks.items():
            if blk.is_synthetic or blk.start_line is None:
                weights[bid] = 10**6
                continue
            cost = 10
            if blk.in_loop:
                cost += 15
            if blk.in_except:
                cost += 20
            if bid in clean_exit_blocks:
                cost += 15
            weights[bid] = cost

        cut = compute_optimal_fix_cut(cfg.entry_id, vuln_sinks, unguarded_adj, weights)
        nca_block = dom_tree.nearest_common_dominator(vuln_sinks)

        sink_bid = witness[-1]
        sink_label, sink_line, delegated_chain = sink_info[sink_bid]
        witness_lines = [
            cfg.blocks[b].start_line
            for b in witness
            if cfg.blocks[b].start_line is not None
        ]
        dedup_lines: list[int] = []
        for ln in witness_lines:
            if not dedup_lines or dedup_lines[-1] != ln:
                dedup_lines.append(ln)

        cut_lines = sorted({
            cfg.blocks[b].start_line
            for b in cut.block_ids
            if cfg.blocks[b].start_line is not None
        })
        nca_line = cfg.blocks[nca_block].start_line if nca_block is not None else None
        guard_noun = "signature verification" if g_cls == "signature" else "authorization check"

        via_note = (
            f" (delegated via `{' -> '.join(delegated_chain)}`)"
            if delegated_chain
            else ""
        )
        explanation = (
            f"In `{func.name}`, at least one execution path enforces a {guard_noun}, "
            f"but control-flow path lines {dedup_lines} reaches `{sink_label}`{via_note} at line "
            f"{sink_line} without traversing that guard. External middleware, framework "
            f"dependencies and runtime reachability outside `{func.name}` were not verified."
        )
        cut_hint = f"line(s) {cut_lines}" if cut_lines else f"line {sink_line}"
        fix_hint = (
            f"Enforce the {guard_noun} on every path before `{sink_label}` (for example at "
            f"minimum-cut {cut_hint}) or abort execution when the check fails."
        )

        evidence_payload: dict[str, object] = {
            "source_type": "static_cfg_dominator",
            "guard_class": g_cls,
            "function": func.name,
            "sink": sink_label,
            "witness_lines": dedup_lines,
            "optimal_cut_lines": cut_lines,
            "dominator_nca_line": nca_line,
        }
        if delegated_chain:
            evidence_payload["delegated_callee_chain"] = list(delegated_chain)

        finding = CheckFinding(
            rule_id=RULE_ID,
            title=f"Privileged call in `{func.name}` reachable via unguarded control-flow branch",
            severity="high",
            confidence=0.85,
            category="Auth",
            file=rel_file,
            line=sink_line,
            explanation=explanation,
            fix_hint=fix_hint,
            claim_evidence=evidence_payload,
        )
        results.append(finding)
        break

    return results


def _collect_parsed_python_files(fileobj: BinaryIO) -> list[tuple[str, ast.Module]]:
    parsed: list[tuple[str, ast.Module]] = []
    files_scanned = 0
    with zipfile.ZipFile(fileobj) as archive:
        for info in archive.infolist():
            if info.is_dir() or files_scanned >= MAX_FILES_SCANNED:
                continue
            path = info.filename
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            if ".git" in path.replace("\\", "/").split("/")[:-1]:
                continue
            if not path.endswith(".py") or info.file_size > MAX_FILE_BYTES:
                continue
            if is_dependency_path(path) or is_generated_path(path) or is_non_production_path(path):
                continue
            files_scanned += 1
            try:
                raw = archive.read(info)
                source = raw.decode("utf-8")
                tree = ast.parse(source, filename=path)
            except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
                continue
            parsed.append((path, tree))
    return parsed


def scan_guard_bypass(fileobj: BinaryIO) -> list[CheckFinding]:
    """Scan Python files in an archive for intra- and inter-procedural guard bypasses."""
    parsed = _collect_parsed_python_files(fileobj)
    if not parsed:
        return []
    call_index = build_repository_summaries(parsed)

    findings: list[CheckFinding] = []
    unit_by_node_id = {id(u.node): u for u in call_index.units.values()}

    for path, tree in parsed:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                unit = unit_by_node_id.get(id(node))
                for hit in analyze_function_bypass(
                    node, path, unit=unit, call_index=call_index
                ):
                    findings.append(hit)
                    if len(findings) >= MAX_FINDINGS:
                        return findings
    return findings
