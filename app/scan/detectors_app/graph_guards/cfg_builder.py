"""Bounded intra-procedural Control Flow Graph (CFG) builder for Python ASTs."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

MAX_AST_NODES = 4_000
MAX_CFG_BLOCKS = 512


@dataclass(frozen=True)
class CFGEdge:
    src: int
    dst: int
    kind: str  # "fallthrough" | "branch_true" | "branch_false" | "loop_back" | "exception"


@dataclass
class BasicBlock:
    block_id: int
    statements: list[ast.stmt] = field(default_factory=list)
    condition: ast.expr | None = None
    start_line: int | None = None
    end_line: int | None = None
    in_loop: bool = False
    in_except: bool = False
    is_synthetic: bool = False

    def record_stmt(self, stmt: ast.stmt) -> None:
        self.statements.append(stmt)
        line = getattr(stmt, "lineno", None)
        end = getattr(stmt, "end_lineno", line)
        if line is not None:
            self.start_line = line if self.start_line is None else min(self.start_line, line)
        if end is not None:
            self.end_line = end if self.end_line is None else max(self.end_line, end)


@dataclass
class ControlFlowGraph:
    func_name: str
    entry_id: int
    normal_exit_id: int
    abort_exit_id: int
    blocks: dict[int, BasicBlock]
    edges: tuple[CFGEdge, ...]
    succ: dict[int, tuple[CFGEdge, ...]]
    pred: dict[int, tuple[CFGEdge, ...]]


class CFGBuildLimitError(ValueError):
    """Raised when a function exceeds bounded CFG construction limits."""


class _Builder:
    def __init__(self, func_name: str, func_lineno: int) -> None:
        self.func_name = func_name
        self.blocks: dict[int, BasicBlock] = {}
        self.edges: list[CFGEdge] = []
        self._seen_edges: set[tuple[int, int, str]] = set()
        self._loop_stack: list[tuple[int, int]] = []  # (continue_target, break_target)
        self._except_stack: list[int] = []
        self.entry_id = self._new_block(start_line=func_lineno)
        self.normal_exit_id = self._new_block(synthetic=True)
        self.abort_exit_id = self._new_block(synthetic=True)

    def _new_block(
        self,
        *,
        start_line: int | None = None,
        in_loop: bool = False,
        in_except: bool = False,
        synthetic: bool = False,
    ) -> int:
        if len(self.blocks) >= MAX_CFG_BLOCKS:
            raise CFGBuildLimitError("cfg_block_limit")
        bid = len(self.blocks)
        block = BasicBlock(
            block_id=bid,
            start_line=start_line,
            end_line=start_line,
            in_loop=in_loop or bool(self._loop_stack),
            in_except=in_except or bool(self._except_stack),
            is_synthetic=synthetic,
        )
        self.blocks[bid] = block
        return bid

    def _add_edge(self, src: int, dst: int, kind: str = "fallthrough") -> None:
        key = (src, dst, kind)
        if key not in self._seen_edges:
            self._seen_edges.add(key)
            self.edges.append(CFGEdge(src=src, dst=dst, kind=kind))

    def build_suite(self, stmts: list[ast.stmt], current: int) -> list[int]:
        open_heads = [current]
        for stmt in stmts:
            if not open_heads:
                break
            if len(open_heads) == 1:
                head = open_heads[0]
            else:
                join = self._new_block(start_line=getattr(stmt, "lineno", None))
                for h in open_heads:
                    self._add_edge(h, join, "fallthrough")
                head = join
            open_heads = self._visit_stmt(stmt, head)
        return open_heads

    def _visit_stmt(self, stmt: ast.stmt, current: int) -> list[int]:
        block = self.blocks[current]
        if self._except_stack and not isinstance(stmt, (ast.If, ast.Try, ast.For, ast.AsyncFor, ast.While, ast.Match)):
            self._add_edge(current, self._except_stack[-1], "exception")

        if isinstance(stmt, ast.Return):
            block.record_stmt(stmt)
            self._add_edge(current, self.normal_exit_id, "fallthrough")
            return []

        if isinstance(stmt, ast.Raise):
            block.record_stmt(stmt)
            target = self._except_stack[-1] if self._except_stack else self.abort_exit_id
            self._add_edge(current, target, "exception")
            return []

        if isinstance(stmt, ast.Break):
            block.record_stmt(stmt)
            if self._loop_stack:
                self._add_edge(current, self._loop_stack[-1][1], "fallthrough")
            return []

        if isinstance(stmt, ast.Continue):
            block.record_stmt(stmt)
            if self._loop_stack:
                self._add_edge(current, self._loop_stack[-1][0], "loop_back")
            return []

        if isinstance(stmt, ast.Assert):
            block.record_stmt(stmt)
            block.condition = stmt.test
            pass_block = self._new_block(start_line=stmt.lineno)
            fail_target = self._except_stack[-1] if self._except_stack else self.abort_exit_id
            self._add_edge(current, pass_block, "branch_true")
            self._add_edge(current, fail_target, "branch_false")
            return [pass_block]

        if isinstance(stmt, ast.If):
            block.record_stmt(stmt)
            block.condition = stmt.test
            true_entry = self._new_block(start_line=getattr(stmt.body[0], "lineno", stmt.lineno))
            self._add_edge(current, true_entry, "branch_true")
            true_tails = self.build_suite(stmt.body, true_entry)
            if stmt.orelse:
                false_entry = self._new_block(start_line=getattr(stmt.orelse[0], "lineno", stmt.lineno))
                self._add_edge(current, false_entry, "branch_false")
                false_tails = self.build_suite(stmt.orelse, false_entry)
            else:
                false_join = self._new_block(start_line=getattr(stmt, "end_lineno", stmt.lineno))
                self._add_edge(current, false_join, "branch_false")
                false_tails = [false_join]
            return true_tails + false_tails

        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            header = current if not block.statements and block.condition is None else self._new_block(
                start_line=stmt.lineno, in_loop=True
            )
            if header != current:
                self._add_edge(current, header, "fallthrough")
            self.blocks[header].record_stmt(stmt)
            if isinstance(stmt, ast.While):
                self.blocks[header].condition = stmt.test
            body_entry = self._new_block(start_line=getattr(stmt.body[0], "lineno", stmt.lineno), in_loop=True)
            after_loop = self._new_block(start_line=getattr(stmt, "end_lineno", stmt.lineno))
            self._add_edge(header, body_entry, "branch_true")
            self._add_edge(header, after_loop, "branch_false")
            self._loop_stack.append((header, after_loop))
            try:
                body_tails = self.build_suite(stmt.body, body_entry)
            finally:
                self._loop_stack.pop()
            for t in body_tails:
                self._add_edge(t, header, "loop_back")
            if stmt.orelse:
                else_tails = self.build_suite(stmt.orelse, after_loop)
                return else_tails
            return [after_loop]

        if isinstance(stmt, ast.Try):
            handler_dispatch = self._new_block(start_line=stmt.lineno, in_except=True) if stmt.handlers else None
            if handler_dispatch is not None:
                self._except_stack.append(handler_dispatch)
            try:
                try_tails = self.build_suite(stmt.body, current)
            finally:
                if handler_dispatch is not None:
                    self._except_stack.pop()

            exits: list[int] = []
            if stmt.orelse and try_tails:
                else_entry = self._new_block(start_line=getattr(stmt.orelse[0], "lineno", stmt.lineno))
                for t in try_tails:
                    self._add_edge(t, else_entry, "fallthrough")
                exits.extend(self.build_suite(stmt.orelse, else_entry))
            else:
                exits.extend(try_tails)

            if handler_dispatch is not None:
                for handler in stmt.handlers:
                    h_entry = self._new_block(start_line=handler.lineno, in_except=True)
                    self._add_edge(handler_dispatch, h_entry, "exception")
                    exits.extend(self.build_suite(handler.body, h_entry))

            if stmt.finalbody and exits:
                fin_entry = self._new_block(start_line=getattr(stmt.finalbody[0], "lineno", stmt.lineno))
                for e in exits:
                    self._add_edge(e, fin_entry, "fallthrough")
                return self.build_suite(stmt.finalbody, fin_entry)
            return exits

        if isinstance(stmt, ast.Match):
            block.record_stmt(stmt)
            exits = []
            has_wildcard = False
            for case in stmt.cases:
                if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                    has_wildcard = True
                c_entry = self._new_block(start_line=getattr(case.body[0], "lineno", stmt.lineno))
                self._add_edge(current, c_entry, "branch_true")
                exits.extend(self.build_suite(case.body, c_entry))
            if not has_wildcard:
                fall = self._new_block(start_line=getattr(stmt, "end_lineno", stmt.lineno))
                self._add_edge(current, fall, "branch_false")
                exits.append(fall)
            return exits

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            block.record_stmt(stmt)
            return self.build_suite(stmt.body, current)

        # Do not descend into nested FunctionDef / ClassDef bodies as inline flow.
        block.record_stmt(stmt)
        return [current]

    def finalize(self, open_tails: list[int]) -> ControlFlowGraph:
        for tail in open_tails:
            self._add_edge(tail, self.normal_exit_id, "fallthrough")
        succ: dict[int, list[CFGEdge]] = {bid: [] for bid in self.blocks}
        pred: dict[int, list[CFGEdge]] = {bid: [] for bid in self.blocks}
        for edge in self.edges:
            succ[edge.src].append(edge)
            pred[edge.dst].append(edge)
        return ControlFlowGraph(
            func_name=self.func_name,
            entry_id=self.entry_id,
            normal_exit_id=self.normal_exit_id,
            abort_exit_id=self.abort_exit_id,
            blocks=self.blocks,
            edges=tuple(self.edges),
            succ={k: tuple(v) for k, v in succ.items()},
            pred={k: tuple(v) for k, v in pred.items()},
        )


def build_function_cfg(func: ast.FunctionDef | ast.AsyncFunctionDef) -> ControlFlowGraph:
    """Build a bounded intra-procedural CFG for a Python function or route handler."""
    node_count = sum(1 for _ in ast.walk(func))
    if node_count > MAX_AST_NODES:
        raise CFGBuildLimitError("ast_node_limit")
    builder = _Builder(func.name, getattr(func, "lineno", 1))
    tails = builder.build_suite(func.body, builder.entry_id)
    return builder.finalize(tails)
