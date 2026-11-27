"""Source roles and URI protocols, without executing code or retaining values."""
import ast
import re

MAX_PYTHON_BYTES = 256_000
MAX_TOTAL_PYTHON_BYTES = 2_000_000


def python_regions(text: str) -> list[tuple[int, int, int, int, str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    regions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                doc = node.body[0]
                regions.append((doc.lineno, doc.col_offset, doc.end_lineno, doc.end_col_offset, 'docstring'))
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and 'DATABASE_URL=' in node.value and 'POSTGRES_PASSWORD=change_me' in node.value):
            regions.append((node.lineno, node.col_offset, node.end_lineno, node.end_col_offset,
                            'configuration_template'))
        if isinstance(node, ast.FormattedValue):
            # Only the expression field is dynamic. Constant portions of the
            # same f-string may still contain genuine hardcoded credentials.
            # Older Python parsers can give this node the whole f-string's
            # span; never suppress a literal based on that imprecise range.
            segment = ast.get_source_segment(text, node)
            if segment and segment.startswith('{') and segment.endswith('}'):
                regions.append((node.lineno, node.col_offset, node.end_lineno, node.end_col_offset,
                                'formatted_value'))
    return regions


def uri_context(matched: str, role: str) -> dict:
    # Only the protocol is retained. Never persist hosts, usernames or passwords.
    scheme = re.match(r'([a-zA-Z][a-zA-Z0-9+.-]*)://', matched)
    protocol = scheme[1].lower() if scheme else 'not_recorded'
    base = protocol.split('+', 1)[0]
    kind = ('database' if base in {'postgres', 'postgresql', 'mysql', 'mariadb', 'mongodb', 'redis'}
            else 'web' if base in {'http', 'https'} else 'other_or_unknown')
    return {'kind': role, 'uri_scheme': protocol, 'uri_kind': kind}
