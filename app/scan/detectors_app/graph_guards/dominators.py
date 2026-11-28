"""Lengauer-Tarjan dominator tree (O(E * alpha(E, V))) and NCA queries."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DominatorTree:
    entry: int
    reachable: frozenset[int]
    idom: dict[int, int | None]
    depth: dict[int, int]

    def dominates(self, u: int, v: int) -> bool:
        """Return True iff u dominates v (every entry -> v path contains u)."""
        if u not in self.reachable or v not in self.reachable:
            return False
        cur: int | None = v
        while cur is not None:
            if cur == u:
                return True
            cur = self.idom[cur]
        return False

    def dominator_chain(self, v: int) -> tuple[int, ...]:
        """Return (v, idom[v], ..., entry) for reachable v, else ()."""
        if v not in self.reachable:
            return ()
        chain: list[int] = []
        cur: int | None = v
        while cur is not None:
            chain.append(cur)
            cur = self.idom[cur]
        return tuple(chain)

    def nearest_common_dominator(self, targets: set[int] | frozenset[int]) -> int | None:
        """Return the deepest node in the dominator tree that dominates all targets."""
        valid = [t for t in targets if t in self.reachable]
        if not valid:
            return None
        nca = valid[0]
        for node in valid[1:]:
            a, b = nca, node
            while a != b:
                if self.depth[a] > self.depth[b]:
                    parent_a = self.idom[a]
                    if parent_a is None:
                        return None
                    a = parent_a
                else:
                    parent_b = self.idom[b]
                    if parent_b is None:
                        return None
                    b = parent_b
            nca = a
        return nca


def compute_dominator_tree(entry: int, adjacency: dict[int, tuple[int, ...] | list[int]]) -> DominatorTree:
    """Compute immediate dominators using iterative Lengauer-Tarjan in 1..N DFS space."""
    dfn: dict[int, int] = {}
    vertex: list[int] = [0]  # 1-indexed: vertex[i] = original node id
    parent: list[int] = [0]

    # Iterative pre-order DFS from entry
    stack: list[tuple[int, int]] = [(entry, 0)]
    while stack:
        node, par_idx = stack.pop()
        if node in dfn:
            continue
        idx = len(vertex)
        dfn[node] = idx
        vertex.append(node)
        parent.append(par_idx)
        succs = adjacency.get(node, ())
        for nxt in reversed(succs):
            if nxt not in dfn:
                stack.append((nxt, idx))

    n = len(vertex) - 1
    if n == 0:
        return DominatorTree(entry=entry, reachable=frozenset(), idom={}, depth={})

    pred: list[list[int]] = [[] for _ in range(n + 1)]
    for u_orig, u_idx in dfn.items():
        for v_orig in adjacency.get(u_orig, ()):
            v_idx = dfn.get(v_orig)
            if v_idx is not None:
                pred[v_idx].append(u_idx)

    semi = list(range(n + 1))
    ancestor = [0] * (n + 1)
    label = list(range(n + 1))
    bucket: list[list[int]] = [[] for _ in range(n + 1)]
    idom_idx = [0] * (n + 1)

    def _compress(v: int) -> None:
        trail: list[int] = []
        cur = v
        while ancestor[ancestor[cur]] != 0:
            trail.append(cur)
            cur = ancestor[cur]
        for node_idx in reversed(trail):
            anc = ancestor[node_idx]
            if semi[label[anc]] < semi[label[node_idx]]:
                label[node_idx] = label[anc]
            ancestor[node_idx] = ancestor[anc]

    def _eval(v: int) -> int:
        if ancestor[v] == 0:
            return v
        _compress(v)
        return label[v]

    for w in range(n, 1, -1):
        for v in pred[w]:
            u = _eval(v)
            if semi[u] < semi[w]:
                semi[w] = semi[u]
        bucket[semi[w]].append(w)
        p = parent[w]
        ancestor[w] = p
        for v in bucket[p]:
            u = _eval(v)
            idom_idx[v] = p if semi[u] == semi[v] else u
        bucket[p].clear()

    for w in range(2, n + 1):
        if idom_idx[w] != semi[w]:
            idom_idx[w] = idom_idx[idom_idx[w]]

    idom: dict[int, int | None] = {vertex[1]: None}
    depth: dict[int, int] = {vertex[1]: 0}
    for i in range(2, n + 1):
        orig = vertex[i]
        dom_orig = vertex[idom_idx[i]]
        idom[orig] = dom_orig
        depth[orig] = depth[dom_orig] + 1

    return DominatorTree(
        entry=entry,
        reachable=frozenset(dfn),
        idom=idom,
        depth=depth,
    )
