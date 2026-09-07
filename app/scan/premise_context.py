"""Bounded source observations and public examples, never uploaded execution."""
import ast
from decimal import Decimal
import re

from pglast import ast as sql, parse_sql, scan
from pglast.parser import ParseError


def update_predicates(text):
    """Parse literal SQL; replace only lexer-recognized positional %s placeholders.

    Preserve AND/OR structure and a tiny public status vocabulary. All other
    values are redacted. This does not resolve Python parameter bindings.
    """
    try:
        tokens = scan(text)
        replacements = []
        for a, b in zip(tokens, tokens[1:]):
            if (text[a.end:a.end + 1] == '%' and a.name in {'Op', 'ASCII_37'}
                    and text[b.start:b.end + 1] == 's' and a.end + 1 == b.start):
                replacements.append((a.end, b.end + 1))
        for number, (start, end) in reversed(list(enumerate(replacements, 1))):
            text = text[:start] + f'${number}' + text[end:]
        statements = parse_sql(text)
    except (ParseError, ValueError, RecursionError):
        return []

    def expression(node, depth=0, status_value=False):
        if node is None:
            return {"absent": True}
        if depth > 6:
            return {"unsupported": "depth_limit"}
        if isinstance(node, sql.BoolExpr):
            return {"boolean": node.boolop.name, "args": [expression(n, depth + 1) for n in node.args[:8]],
                    "truncated": len(node.args) > 8}
        if isinstance(node, sql.ColumnRef):
            return {"column": [n.sval[:128] for n in node.fields if isinstance(n, sql.String)]}
        if isinstance(node, sql.ParamRef):
            return {"parameter": node.number}
        if isinstance(node, sql.A_Expr) and node.kind.name == 'AEXPR_OP':
            left = expression(node.lexpr, depth + 1)
            return {"operator": [n.sval[:8] for n in node.name], "left": left,
                    "right": expression(node.rexpr, depth + 1, left.get('column', [])[-1:] == ['status'])}
        if isinstance(node, sql.A_Const):
            value = node.val.sval if isinstance(node.val, sql.String) else None
            return ({"status_literal": value} if status_value and value in {'pending', 'completed'}
                    else {"literal": "redacted"})
        return {"unsupported": type(node).__name__}

    return [{"where": expression(stmt.stmt.whereClause)}
            for stmt in statements[:8] if isinstance(stmt.stmt, sql.UpdateStmt)]


def transaction_templates(fn):
    """Observe BEGIN/include/COMMIT in one template, not its execution."""
    records = []
    for node in fn.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.JoinedStr):
            continue
        parts = node.value.values
        for i, part in enumerate(parts[:-1]):
            if not (isinstance(part, ast.Constant) and isinstance(part.value, str)
                    and re.search(r'(?m)^[ \t]*\\i[ \t]*$', part.value)
                    and isinstance(parts[i + 1], ast.FormattedValue)):
                continue
            before = ''.join(p.value for p in parts[:i + 1] if isinstance(p, ast.Constant))
            after = ''.join(p.value for p in parts[i + 2:] if isinstance(p, ast.Constant))
            if re.search(r'(?m)^BEGIN;\s*$', before) and re.search(r'(?m)^COMMIT;\s*$', after):
                records.append({"kind": "transaction_template", "result": "observed", "line": node.lineno,
                                "detail": "One formatted template contains BEGIN, a psql include placeholder, "
                                "then COMMIT. "
                                "Template observation only: include target, interpolation, runner binding "
                                "and execution not verified."})
    return records[:4]


def finding_context(finding, source_facts):
    """Attach bounded counterexamples/context without dismissing a compound claim."""
    facts = source_facts or {}
    text = ' '.join(str(finding.get(k, '')) for k in ('title', 'explanation', 'observation'))[:16000]
    records = []
    if re.search(r'\bfloat\b', text, re.I):
        supported = any(r['file'] == finding.get('file') and r['kind'] == 'numeric_examples'
                        and int(finding['line_start']) <= r['line'] <= int(finding['line_end'])
                        for r in (facts.get('operations') or {}).get('records', []))
        if supported:
            cases = []
            for value in ('490.00', '990.00', '990.07', '333.33', '99.99'):
                if not re.search(r'(?<![\d.])' + re.escape(value) + r'(?![\d.])', text):
                    continue
                formatted = f'{float(value):.2f}'
                difference = Decimal(formatted) - Decimal(value)
                cases.append({"input": value, "formatted": formatted, "difference": str(difference),
                              "amount_changed": difference != 0})
            if cases:
                records.append({"kind": "numeric_examples", "cases": cases,
                                "detail": "Public examples mentioned in this claim. "
                                "Unchanged examples do not demonstrate lost cents. "
                                "Uploaded expression, bindings, production values and other inputs "
                                "were not executed or verified."})
    if re.search(r'\bmigration\b.*\btransaction\b', text, re.I):
        for record in (facts.get('functions') or {}).get('records', []):
            for check in record['checks']:
                if check['kind'] == 'transaction_template':
                    records.append({**check, "file": record['file'], "scope": record['scope']})
                    if len(records) >= 4:
                        return records
    return records
