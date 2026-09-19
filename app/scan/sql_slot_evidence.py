"""Establish narrowly supported SQL template roles without executing SQL.

Inputs are symbolic fragments: strings are fixed SQL and integers identify
dynamic slots. A role describes the original template, not the safety of any
input or the correctness of a prospective parameterization patch.
"""

from __future__ import annotations

from collections.abc import Callable

_MAX_BYTES = 16_384
_MAX_PARTS = 256
_MAX_SLOTS = 64
_MAX_AST_NODES = 2_048


def _result(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason, "facts": []}


def _template(parts: list[str | int], spend: Callable[[int], None]):
    """Replace slots with parameters, keeping original quote boundaries.

    Ordinary quoted literals containing slots become one synthetic parameter
    for the whole literal. Flattening fragments first is important: quote
    escapes and comment delimiters can straddle two fixed fragments.
    """
    if not isinstance(parts, list) or len(parts) > _MAX_PARTS:
        return None, "sql_input_limit"
    stream: list[str | int] = []
    byte_count = occurrences = 0
    indices: set[int] = set()
    for part in parts:
        spend(1)
        if type(part) is int:
            if not 0 <= part < _MAX_SLOTS:
                return None, "sql_parts_invalid"
            occurrences += 1
            if occurrences > _MAX_SLOTS:
                return None, "sql_input_limit"
            indices.add(part)
            stream.append(part)
            byte_count += 8  # Includes the synthetic parameter's length.
        elif isinstance(part, str):
            if len(part) > _MAX_BYTES:
                return None, "sql_input_limit"
            byte_count += len(part.encode("utf-8", errors="replace"))
            if byte_count > _MAX_BYTES:
                return None, "sql_input_limit"
            if "\x00" in part:
                return None, "sql_lexical_form_unsupported"
            stream.extend(part)
        else:
            return None, "sql_parts_invalid"
        if byte_count > _MAX_BYTES:
            return None, "sql_input_limit"
    if not indices:
        return None, "sql_slots_missing"
    if indices != set(range(max(indices) + 1)):
        return None, "sql_parts_invalid"

    output: list[str] = []
    bindings: dict[int, tuple[int, ...]] = {}

    def parameter(slots: list[int]) -> None:
        number = len(bindings) + 1
        bindings[number] = tuple(slots)
        output.append(f"${number}")

    index = 0
    while index < len(stream):
        spend(1)
        char = stream[index]
        if type(char) is int:
            parameter([char])
            index += 1
            continue
        following = stream[index + 1] if index + 1 < len(stream) else None
        if (char, following) in (("-", "-"), ("/", "*")) or char in ("$", "\\"):
            return None, "sql_lexical_form_unsupported"
        if char not in ("'", '"'):
            output.append(char)
            index += 1
            continue

        # E'', B'', X'', N'', U&'' and U&"" have different lexical rules.
        # Reject prefixes before interpreting either kind of quoted token.
        previous = stream[index - 1] if index else None
        if isinstance(previous, str) and (previous.isalnum() or previous in ("_", "&")):
            return None, "sql_lexical_form_unsupported"
        quote = char
        literal: list[str] = [quote]
        slots: list[int] = []
        index += 1
        closed = False
        while index < len(stream):
            spend(1)
            char = stream[index]
            if type(char) is int:
                if quote == '"':
                    return None, "sql_lexical_form_unsupported"
                slots.append(char)
                index += 1
                continue
            # Backslash interpretation depends on session settings for plain
            # string literals. Do not infer a role under an assumed setting.
            if char == "\\":
                return None, "sql_lexical_form_unsupported"
            literal.append(char)
            index += 1
            if char != quote:
                continue
            if index < len(stream) and stream[index] == quote:
                spend(1)
                literal.append(quote)
                index += 1
                continue
            closed = True
            break
        if not closed:
            return None, "sql_lexical_form_unsupported"
        if slots:
            parameter(slots)
        else:
            output.append("".join(literal))
    return ("".join(output), bindings, indices), None


def _column(node, ast, *, star: bool = False) -> bool:
    if not isinstance(node, ast.ColumnRef) or not node.fields or len(node.fields) > 3:
        return False
    return all(
        isinstance(field, ast.String)
        or (star and index == len(node.fields) - 1 and isinstance(field, ast.A_Star))
        for index, field in enumerate(node.fields)
    )


def classify_sql_slots(
    parts: list[str | int], *, spend: Callable[[int], None]
) -> dict:
    """Return a value-role fact only when every dynamic occurrence is proven.

    Supported grammar is a single SELECT from a fixed relation, with fixed
    projections and WHERE comparisons of fixed columns to values, optionally
    joined by AND/OR. Missing parser, unsupported syntax or ambiguous roles
    leave the predicate unestablished. Budget exceptions intentionally escape
    to the agent coordinator.
    """
    prepared, reason = _template(parts, spend)
    if reason:
        status = "unknown" if reason == "sql_slots_missing" else "unsupported"
        return _result(status, reason)
    query, bindings, indices = prepared
    try:
        from pglast import Error, ast, parse_sql
    except (ImportError, OSError):
        return _result("unsupported", "sql_parser_unavailable")
    # Charge the bounded parser input independently of the lexical scan.
    spend(len(query))
    try:
        statements = parse_sql(query)
    except (Error, ValueError, RecursionError):
        return _result("unsupported", "sql_parse_failed")
    if len(statements) != 1 or not isinstance(statements[0].stmt, ast.SelectStmt):
        return _result("unsupported", "sql_statement_unsupported")

    # Walk iteratively before checking grammar. This also detects parameters
    # outside WHERE and bounds every subsequent traversal of parsed nodes.
    stack = [statements[0]]
    parameters: list[int] = []
    node_count = 0
    while stack:
        node = stack.pop()
        spend(1)
        node_count += 1
        if node_count > _MAX_AST_NODES:
            return _result("unsupported", "sql_ast_limit")
        if isinstance(node, ast.ParamRef):
            parameters.append(node.number)
        for name in node:
            spend(1)
            child = getattr(node, name)
            if isinstance(child, ast.Node):
                stack.append(child)
            elif isinstance(child, tuple):
                stack.extend(item for item in child if isinstance(item, ast.Node))

    statement = statements[0].stmt
    unsupported_clauses = (
        "distinctClause", "intoClause", "groupClause", "havingClause", "windowClause",
        "valuesLists", "sortClause", "limitOffset", "limitCount", "lockingClause",
        "withClause", "larg", "rarg",
    )
    if any(getattr(statement, name) for name in unsupported_clauses) or statement.op != 0:
        return _result("unsupported", "sql_statement_unsupported")
    if (
        not statement.fromClause or len(statement.fromClause) != 1
        or not isinstance(statement.fromClause[0], ast.RangeVar)
        or not statement.targetList
        or not statement.whereClause
    ):
        return _result("unsupported", "sql_statement_unsupported")
    for target in statement.targetList:
        spend(1)
        if not isinstance(target, ast.ResTarget) or target.indirection or not (
            _column(target.val, ast, star=True) or isinstance(target.val, ast.A_Const)
        ):
            return _result("unknown", "sql_slot_context_unknown")

    proven: list[int] = []
    predicates = [statement.whereClause]
    while predicates:
        predicate = predicates.pop()
        spend(1)
        if isinstance(predicate, ast.BoolExpr) and predicate.boolop in (0, 1):
            predicates.extend(predicate.args or ())
            continue
        if not (
            isinstance(predicate, ast.A_Expr)
            and predicate.kind == 0
            and len(predicate.name or ()) == 1
            and isinstance(predicate.name[0], ast.String)
            and predicate.name[0].sval == "="
            and _column(predicate.lexpr, ast)
        ):
            return _result("unknown", "sql_slot_context_unknown")
        if isinstance(predicate.rexpr, ast.ParamRef):
            proven.append(predicate.rexpr.number)
        elif not isinstance(predicate.rexpr, ast.A_Const):
            return _result("unknown", "sql_slot_context_unknown")
    if sorted(proven) != sorted(bindings) or sorted(parameters) != sorted(bindings):
        return _result("unknown", "sql_slot_context_unknown")
    return {
        "status": "established",
        "reason": "sql_value_positions_established",
        "facts": [{
            "id": "sql_value_position",
            "method": "postgresql_ast_slot_context",
            "slots": [{"index": index, "role": "value"} for index in sorted(indices)],
        }],
    }
