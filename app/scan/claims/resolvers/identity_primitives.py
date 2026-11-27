"""Bottom layer of issue-identity resolution: where a cited node lives.

The span/line/scope primitives and the shared check budget that both the
SourceIssueResolver in issue_identity and the identity handlers it
delegates to (projected_read_identity) build on. Moved verbatim during
the import-cycles fix phase (the resolver called the handlers while the
handlers reached back into the resolver's private helpers).
"""
from __future__ import annotations

from app.scan.context import guard_context as g

MAX_CHECKS = 256


def _span(node):
    return [node.start_byte, node.end_byte]


def _lines(node):
    return node.start_point[0] + 1, node.end_point[0] + 1


def _owning_scope(root, nodes, start):
    functions = [n for n in nodes if n.type in g._FUNCTIONS and _lines(n)[0] <= start <= _lines(n)[1]]
    return min(functions, key=lambda n: n.end_byte - n.start_byte) if functions else root
