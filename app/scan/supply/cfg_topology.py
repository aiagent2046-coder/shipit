"""Reference Directed 1-Weisfeiler-Lehman & Tarjan SCC topology engine.

Bit-identical to ExportDrydockFacts.java: computes address- and symbol-invariant
topological fingerprints over basic-block control-flow graphs, plus structural
anomaly detectors (loop+indirect-call unpacker stubs, Tarjan-SCC control-flow
flattening dispatchers, and stripped function signature matching).
"""
from __future__ import annotations

import hashlib

WL_ROUNDS = 3


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_back_edges_dfs(node_count: int, succs: list[list[int]]) -> int:
    if node_count == 0:
        return 0
    state = [0] * node_count
    back_edges = 0
    for root in range(node_count):
        if state[root] != 0:
            continue
        state[root] = 1
        stack = [[root, 0]]
        while stack:
            u, child_idx = stack[-1]
            children = succs[u]
            if child_idx < len(children):
                stack[-1][1] += 1
                v = children[child_idx]
                if state[v] == 1:
                    back_edges += 1
                elif state[v] == 0:
                    state[v] = 1
                    stack.append([v, 0])
            else:
                state[u] = 2
                stack.pop()
    return back_edges


def compute_cyclic_scc_metrics(node_count: int, succs: list[list[int]]) -> tuple[int, int]:
    """Iterative Tarjan SCC: returns (max_scc_blocks, max_scc_hub_in) over cyclic SCCs."""
    if node_count == 0:
        return 0, 0
    indices = [-1] * node_count
    lowlink = [0] * node_count
    on_stack = [False] * node_count
    tarjan_stack: list[int] = []
    current_index = 0
    max_scc_blocks = 0
    max_scc_hub_in = 0

    for start in range(node_count):
        if indices[start] != -1:
            continue
        indices[start] = current_index
        lowlink[start] = current_index
        current_index += 1
        tarjan_stack.append(start)
        on_stack[start] = True
        call_stack = [[start, 0]]

        while call_stack:
            v, ci = call_stack[-1]
            children = succs[v]
            if ci < len(children):
                call_stack[-1][1] = ci + 1
                w = children[ci]
                if indices[w] == -1:
                    indices[w] = current_index
                    lowlink[w] = current_index
                    current_index += 1
                    tarjan_stack.append(w)
                    on_stack[w] = True
                    call_stack.append([w, 0])
                elif on_stack[w]:
                    lowlink[v] = min(lowlink[v], indices[w])
            else:
                call_stack.pop()
                if call_stack:
                    parent = call_stack[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[v])
                if lowlink[v] == indices[v]:
                    comp: list[int] = []
                    while True:
                        w = tarjan_stack.pop()
                        on_stack[w] = False
                        comp.append(w)
                        if w == v:
                            break
                    cyclic = len(comp) > 1 or (len(comp) == 1 and comp[0] in succs[comp[0]])
                    if cyclic:
                        comp_set = set(comp)
                        in_deg: dict[int, int] = {}
                        hub_in = 0
                        for u in comp:
                            for dst in succs[u]:
                                if dst in comp_set:
                                    nxt = in_deg.get(dst, 0) + 1
                                    in_deg[dst] = nxt
                                    if nxt > hub_in:
                                        hub_in = nxt
                        if (len(comp), hub_in) > (max_scc_blocks, max_scc_hub_in):
                            max_scc_blocks = len(comp)
                            max_scc_hub_in = hub_in
    return max_scc_blocks, max_scc_hub_in


def compute_cfg_dna(
    blocks: list[dict],
    edges: list[tuple[int, int]],
    *,
    entry_index: int = 0,
) -> dict:
    """Compute canonical WL hash and Loop/SCC DNA for a basic-block graph."""
    n = len(blocks)
    if n == 0:
        return {
            "basic_blocks": 0,
            "cfg_edges": 0,
            "back_edges": 0,
            "branch_blocks": 0,
            "cyclomatic": 1,
            "indirect_calls": 0,
            "max_scc_blocks": 0,
            "max_scc_hub_in": 0,
            "wl_hash": _sha256_hex("wl1|n=0|"),
        }

    order = [entry_index, *(i for i in range(n) if i != entry_index)]
    old_to_new = {old: new for new, old in enumerate(order)}

    succs: list[list[int]] = [[] for _ in range(n)]
    preds: list[list[int]] = [[] for _ in range(n)]
    seen_edges: set[tuple[int, int]] = set()
    for src, dst in edges:
        if 0 <= src < n and 0 <= dst < n:
            u, v = old_to_new[src], old_to_new[dst]
            if (u, v) not in seen_edges:
                seen_edges.add((u, v))
                succs[u].append(v)
                preds[v].append(u)
    for idx in range(n):
        succs[idx].sort()
        preds[idx].sort()

    cfg_edges = len(seen_edges)
    branch_blocks = 0
    total_indirect = 0
    colors: list[str] = []

    for idx in range(n):
        blk = blocks[order[idx]]
        in_deg = len(preds[idx])
        out_deg = len(succs[idx])
        if out_deg >= 2:
            branch_blocks += 1
        is_entry = 1 if idx == 0 else 0
        is_ret = 1 if blk.get("is_return", False) else 0
        d_calls = int(blk.get("direct_calls", 0))
        i_calls = int(blk.get("indirect_calls", 0))
        total_indirect += i_calls
        role = f"{in_deg}:{out_deg}:{is_entry}:{is_ret}:{d_calls}:{i_calls}"
        colors.append(_sha256_hex(f"v0|{role}"))

    for r in range(1, WL_ROUNDS + 1):
        next_colors: list[str] = []
        for idx in range(n):
            in_labels = ",".join(sorted(colors[p] for p in preds[idx]))
            out_labels = ",".join(sorted(colors[s] for s in succs[idx]))
            payload = f"r{r}|{colors[idx]}|in:{in_labels}|out:{out_labels}"
            next_colors.append(_sha256_hex(payload))
        colors = next_colors

    multiset = ",".join(sorted(colors))
    wl_hash = _sha256_hex(f"wl1|n={n}|{multiset}")
    back_edges = count_back_edges_dfs(n, succs)
    max_scc_blocks, max_scc_hub_in = compute_cyclic_scc_metrics(n, succs)
    cyclomatic = max(1, cfg_edges - n + 2)
    return {
        "basic_blocks": n,
        "cfg_edges": cfg_edges,
        "back_edges": back_edges,
        "branch_blocks": branch_blocks,
        "cyclomatic": cyclomatic,
        "indirect_calls": total_indirect,
        "max_scc_blocks": max_scc_blocks,
        "max_scc_hub_in": max_scc_hub_in,
        "wl_hash": wl_hash,
    }


_DECODER_STUB_DNA = compute_cfg_dna(
    blocks=[
        {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
        {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
        {"is_return": True, "direct_calls": 0, "indirect_calls": 1},
    ],
    edges=[(0, 1), (1, 1), (1, 2)],
    entry_index=0,
)

KNOWN_TOPOLOGY_SIGNATURES: dict[str, dict[str, str]] = {
    _DECODER_STUB_DNA["wl_hash"]: {
        "signature_id": "cfg-loop-indirect-stager-v1",
        "description": "Tight self-loop feeding an indirect call tail (typical decode-and-dispatch stub)",
    },
}


def analyze_function_topologies(functions: list[dict]) -> dict:
    """Detect structural anomalies and match stripped functions against WL signatures."""
    signature_matches = []
    loop_indirect_anomalies = []
    flattened_dispatchers = []

    for fn in functions:
        if fn.get("is_thunk"):
            continue
        wl = fn.get("wl_hash")
        entry = fn.get("entry")
        name = fn.get("name", "")
        b_blocks = fn.get("basic_blocks", 0)
        back_edges = fn.get("back_edges", 0)
        cyclomatic = fn.get("cyclomatic", 1)
        indirect = fn.get("indirect_calls", 0)
        scc_blocks = fn.get("max_scc_blocks", 0)
        scc_hub_in = fn.get("max_scc_hub_in", 0)

        if isinstance(wl, str) and wl in KNOWN_TOPOLOGY_SIGNATURES:
            sig = KNOWN_TOPOLOGY_SIGNATURES[wl]
            signature_matches.append({
                "entry": entry,
                "name": name,
                "wl_hash": wl,
                "signature_id": sig["signature_id"],
            })

        if back_edges >= 1 and indirect >= 1 and b_blocks <= 12:
            loop_indirect_anomalies.append({
                "entry": entry,
                "name": name,
                "basic_blocks": b_blocks,
                "back_edges": back_edges,
                "indirect_calls": indirect,
                "wl_hash": wl,
            })

        # Tarjan-SCC Control-Flow Flattening invariant:
        # >=14 blocks locked inside a single cyclic SCC (>=70% of function) with central latch/header fan-in >=8.
        if scc_blocks >= 14 and scc_hub_in >= 8 and scc_blocks * 10 >= b_blocks * 7:
            flattened_dispatchers.append({
                "entry": entry,
                "name": name,
                "basic_blocks": b_blocks,
                "max_scc_blocks": scc_blocks,
                "max_scc_hub_in": scc_hub_in,
                "cyclomatic": cyclomatic,
                "wl_hash": wl,
            })

    return {
        "signature_matches": signature_matches,
        "loop_indirect_anomalies": loop_indirect_anomalies,
        "flattened_dispatchers": flattened_dispatchers,
    }
