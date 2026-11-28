"""Algebraic and property tests for Lengauer-Tarjan dominators and Optimal Fix Cut."""

from __future__ import annotations

from collections import deque
import random

from app.scan.detectors_app.graph_guards.dominators import compute_dominator_tree
from app.scan.detectors_app.graph_guards.min_cut import compute_optimal_fix_cut


def _naive_dominators(entry: int, adj: dict[int, list[int]]) -> dict[int, set[int]]:
    """Ground-truth dataflow fixed-point: D(v) = {v} U intersect_{p in pred(v)} D(p)."""
    reachable: set[int] = set()
    q: deque[int] = deque([entry])
    while q:
        u = q.popleft()
        if u in reachable:
            continue
        reachable.add(u)
        for v in adj.get(u, ()):
            if v not in reachable:
                q.append(v)

    preds: dict[int, list[int]] = {v: [] for v in reachable}
    for u in reachable:
        for v in adj.get(u, ()):
            if v in reachable:
                preds[v].append(u)

    dom: dict[int, set[int]] = {v: set(reachable) for v in reachable}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for v in sorted(reachable):
            if v == entry:
                continue
            if not preds[v]:
                continue
            intersected = set.intersection(*(dom[p] for p in preds[v]))
            new_dom = {v} | intersected
            if new_dom != dom[v]:
                dom[v] = new_dom
                changed = True
    return dom


def test_lengauer_tarjan_matches_dataflow_fixed_point_across_random_cyclic_cfgs() -> None:
    """Verify exact equivalence across 150 random directed graphs including irreducible loops."""
    rng = random.Random(20261127)
    for trial in range(150):
        n = rng.randint(2, 35)
        adj: dict[int, list[int]] = {i: [] for i in range(n)}
        for u in range(n):
            k = rng.randint(0, min(5, n))
            adj[u] = sorted(rng.sample(range(n), k))
        # Also include dead unreachable nodes intentionally
        adj[n + 10] = [n + 11]
        adj[n + 11] = [0]

        lt = compute_dominator_tree(0, adj)
        expected = _naive_dominators(0, adj)

        assert lt.reachable == frozenset(expected), f"trial {trial}: reachable mismatch"
        for node, exp_doms in expected.items():
            lt_doms = set(lt.dominator_chain(node))
            assert lt_doms == exp_doms, f"trial {trial}, node {node}: {lt_doms} != {exp_doms}"


def test_nearest_common_dominator_on_irreducible_two_header_loop() -> None:
    # Classic irreducible flowgraph: 0 -> 1, 0 -> 2, 1 <-> 2, 1 -> 3, 2 -> 4
    adj = {
        0: [1, 2],
        1: [2, 3],
        2: [1, 4],
        3: [],
        4: [],
    }
    tree = compute_dominator_tree(0, adj)
    assert tree.idom[1] == 0
    assert tree.idom[2] == 0
    assert tree.idom[3] == 1
    assert tree.idom[4] == 2
    assert tree.nearest_common_dominator({3, 4}) == 0
    assert tree.nearest_common_dominator({1, 3}) == 1


def test_optimal_fix_cut_disconnects_all_targets_with_minimum_weight() -> None:
    rng = random.Random(424242)
    for _ in range(80):
        n = rng.randint(4, 18)
        adj: dict[int, list[int]] = {i: [] for i in range(n)}
        for u in range(n - 1):
            adj[u] = sorted(rng.sample(range(n), rng.randint(1, min(4, n))))
        weights = {i: rng.randint(5, 40) for i in range(n)}
        targets = set(rng.sample(range(1, n), rng.randint(1, min(3, n - 1))))

        cut = compute_optimal_fix_cut(0, targets, adj, weights)
        blocked = set(cut.block_ids)

        # Verify zero paths remain from 0 to any reachable target when blocked nodes are removed
        q: deque[int] = deque([] if 0 in blocked else [0])
        seen: set[int] = set(q)
        while q:
            u = q.popleft()
            assert u not in targets, "target remained reachable after removing optimal_cut"
            for v in adj.get(u, ()):
                if v not in blocked and v not in seen:
                    seen.add(v)
                    q.append(v)

        assert cut.total_cost == sum(weights[b] for b in cut.block_ids)


def test_clean_exit_penalty_steers_cut_away_from_public_early_return() -> None:
    # Entry 0 branches to 1 (public health check -> exit) and 2 (unprotected sink)
    adj = {0: [1, 2], 1: [], 2: [3], 3: []}
    # Block 0 has clean-exit penalty (25), while block 2 only leads to sink (10)
    weights = {0: 25, 1: 10, 2: 10, 3: 10}
    cut = compute_optimal_fix_cut(0, {3}, adj, weights)
    assert cut.block_ids == (2,)
    assert cut.total_cost == 10
