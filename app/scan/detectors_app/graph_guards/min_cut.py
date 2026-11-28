"""Minimum weighted vertex cut for Optimal Fix Cut localization on CFGs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

INF_COST = 10**9


@dataclass(frozen=True)
class OptimalFixCut:
    block_ids: tuple[int, ...]
    total_cost: int


def compute_optimal_fix_cut(
    entry: int,
    targets: set[int] | frozenset[int],
    adjacency: dict[int, tuple[int, ...] | list[int]],
    weights: dict[int, int],
) -> OptimalFixCut:
    """Compute a minimum-weight vertex cut disconnecting entry from all targets.

    Uses standard vertex splitting (v_in -> v_out with capacity weights[v]) and
    Edmonds-Karp shortest augmenting paths, returning a deterministic canonical
    source-side minimum vertex cut.
    """
    if not targets:
        return OptimalFixCut(block_ids=(), total_cost=0)

    # Restrict to nodes forward-reachable from entry and backward-reaching targets.
    fwd: set[int] = set()
    q: deque[int] = deque([entry])
    while q:
        u = q.popleft()
        if u in fwd:
            continue
        fwd.add(u)
        if u in targets:
            # A guard placed on or before u already intercepts u; no need to traverse past a sink
            # unless u can reach another sink, so keep traversing normally.
            pass
        for v in adjacency.get(u, ()):
            if v not in fwd:
                q.append(v)

    active_targets = fwd & set(targets)
    if not active_targets:
        return OptimalFixCut(block_ids=(), total_cost=0)

    rev_adj: dict[int, list[int]] = {u: [] for u in fwd}
    for u in fwd:
        for v in adjacency.get(u, ()):
            if v in fwd:
                rev_adj[v].append(u)

    bwd: set[int] = set()
    rq: deque[int] = deque(sorted(active_targets))
    while rq:
        u = rq.popleft()
        if u in bwd:
            continue
        bwd.add(u)
        for p in rev_adj.get(u, ()):
            if p not in bwd:
                rq.append(p)

    relevant = sorted(fwd & bwd)
    if not relevant:
        return OptimalFixCut(block_ids=(), total_cost=0)

    # Node indexing in flow network:
    # 0 = super_source, 1 = super_sink
    # For each idx, v in enumerate(relevant): v_in = 2 + 2*idx, v_out = 3 + 2*idx
    src_net = 0
    sink_net = 1
    total_nodes = 2 + 2 * len(relevant)
    cap: dict[int, dict[int, int]] = {i: {} for i in range(total_nodes)}

    def _add_directed(u: int, v: int, c: int) -> None:
        cap[u][v] = cap[u].get(v, 0) + c
        cap[v].setdefault(u, 0)

    node_Index = {v: idx for idx, v in enumerate(relevant)}
    _add_directed(src_net, 2 + 2 * node_Index[entry], INF_COST)

    for v in relevant:
        idx = node_Index[v]
        v_in = 2 + 2 * idx
        v_out = 3 + 2 * idx
        cost = weights.get(v, 10)
        _add_directed(v_in, v_out, max(1, cost))
        if v in active_targets:
            _add_directed(v_out, sink_net, INF_COST)
        for nxt in adjacency.get(v, ()):
            if nxt in node_Index:
                _add_directed(v_out, 2 + 2 * node_Index[nxt], INF_COST)

    # Edmonds-Karp max-flow
    flow = 0
    while True:
        parent = [-1] * total_nodes
        parent[src_net] = src_net
        bfs: deque[int] = deque([src_net])
        while bfs and parent[sink_net] == -1:
            u = bfs.popleft()
            for v, rem in cap[u].items():
                if rem > 0 and parent[v] == -1:
                    parent[v] = u
                    bfs.append(v)
        if parent[sink_net] == -1:
            break
        bottleneck = INF_COST
        cur = sink_net
        while cur != src_net:
            p = parent[cur]
            bottleneck = min(bottleneck, cap[p][cur])
            cur = p
        cur = sink_net
        while cur != src_net:
            p = parent[cur]
            cap[p][cur] -= bottleneck
            cap[cur][p] += bottleneck
            cur = p
        flow += bottleneck

    # Residual reachability from src_net yields the canonical minimum cut
    visited = [False] * total_nodes
    rq2: deque[int] = deque([src_net])
    visited[src_net] = True
    while rq2:
        u = rq2.popleft()
        for v, rem in cap[u].items():
            if rem > 0 and not visited[v]:
                visited[v] = True
                rq2.append(v)

    cut_blocks: list[int] = []
    for v in relevant:
        idx = node_Index[v]
        v_in = 2 + 2 * idx
        v_out = 3 + 2 * idx
        if visited[v_in] and not visited[v_out]:
            cut_blocks.append(v)

    return OptimalFixCut(block_ids=tuple(cut_blocks), total_cost=flow)
