"""Small real-parser regressions shared verbatim by CPython and Pyodide.

Import this file (or execute its source) and call ``probe_parsers()``.  The
result contains only JSON values, no process state, addresses, or paths.
Assertions are intentional: two empty or failed parsers must not pass parity.
"""


PARSER_VERSIONS = {
    "tree-sitter": "0.26.0",
    "tree-sitter-typescript": "0.23.2",
    "tree-sitter-javascript": "0.25.0",
    "pglast": "8.4",
}

TREE_SOURCES = {
    "typescript": (
        '// café Ж 😀\nconst café: string = "Ж😀";\n'
        'client.query(`SELECT ${café} AS "Ж😀"`);\n'
    ),
    "tsx": (
        '// café Ж 😀\nconst café = "Ж😀";\n'
        'const view = <section title={café}>{format(`café Ж 😀 ${café}`)}</section>;\n'
    ),
    "javascript": (
        '// café Ж 😀\nconst café = "Ж😀";\n'
        'console.log(`café Ж 😀 ${café}`);\n'
    ),
}

SQL_SOURCE = (
    "-- café Ж 😀\nSELECT 'élan Ж 😀' AS label, 7 AS n;\n"
    "/* naïve Ж 😀 */ SELECT label FROM public.events WHERE id = 42;"
)


def _point(source, offset):
    """Tree-sitter points count UTF-8 bytes within a zero-based line."""
    prefix = source[:offset]
    return [prefix.count(b"\n"), len(prefix.rsplit(b"\n", 1)[-1])]


def _tree_probe(language_name, language):
    from tree_sitter import Parser

    source = TREE_SOURCES[language_name].encode("utf-8")
    root = Parser(language).parse(source).root_node
    assert root.type == "program" and not root.has_error
    assert root.start_byte == 0 and root.end_byte == len(source)
    nodes = []
    seen = set()
    pending = [root]
    while pending:
        node = pending.pop()
        assert node.text == source[node.start_byte:node.end_byte]
        assert list(node.start_point) == _point(source, node.start_byte)
        assert list(node.end_point) == _point(source, node.end_byte)
        assert not node.is_missing and not node.has_error
        fields = []
        for index, child in enumerate(node.children):
            field = node.field_name_for_child(index)
            if field is not None:
                # Exercise field lookup as well as positional child traversal.
                assert node.child_by_field_name(field) == child
                fields.append({
                    "field": field,
                    "type": child.type,
                    "span": [child.start_byte, child.end_byte],
                    "text_hex": child.text.hex(),
                })
        nodes.append({
            "type": node.type,
            "span": [node.start_byte, node.end_byte],
            "start_point": list(node.start_point),
            "end_point": list(node.end_point),
            "text_hex": node.text.hex(),
            "child_count": node.child_count,
            "named_child_count": node.named_child_count,
            "fields": fields,
        })
        seen.add(node.type)
        pending.extend(reversed(node.named_children))
    assert {"call_expression", "arguments", "template_substitution", "identifier"} <= seen
    assert any(node["type"] == "identifier" and node["text_hex"] == "café".encode().hex()
               for node in nodes)
    if language_name == "typescript":
        assert "type_annotation" in seen
    if language_name == "tsx":
        assert {"jsx_element", "jsx_expression"} <= seen
    assert 15 <= len(nodes) <= 80
    return {"source": source.decode("utf-8"), "byte_length": len(source), "nodes": nodes}


def _sql_probe():
    from pglast import ast, parse_sql
    from pglast.parser import ParseError, scan

    statements = parse_sql(SQL_SOURCE)
    assert len(statements) == 2
    assert all(isinstance(item, ast.RawStmt) and isinstance(item.stmt, ast.SelectStmt)
               for item in statements)
    first, second = (item.stmt for item in statements)
    assert isinstance(first.targetList[0], ast.ResTarget)
    assert isinstance(first.targetList[0].val, ast.A_Const)
    assert isinstance(first.targetList[0].val.val, ast.String)
    assert first.targetList[0].val.val.sval == "élan Ж 😀"
    assert isinstance(first.targetList[1].val.val, ast.Integer)
    assert first.targetList[1].val.val.ival == 7
    assert isinstance(second.fromClause[0], ast.RangeVar)
    assert second.fromClause[0].schemaname == "public"
    assert second.fromClause[0].relname == "events"
    assert isinstance(second.whereClause, ast.A_Expr)
    assert second.whereClause.lexpr.fields[0].sval == "id"
    assert second.whereClause.rexpr.val.ival == 42

    tokens = []
    for token in scan(SQL_SOURCE):
        # pglast scan uses inclusive Python character offsets.  Record the
        # derived UTF-8 span too, to expose Unicode displacement regressions.
        assert 0 <= token.start <= token.end < len(SQL_SOURCE)
        value = SQL_SOURCE[token.start:token.end + 1]
        byte_start = len(SQL_SOURCE[:token.start].encode("utf-8"))
        byte_end = len(SQL_SOURCE[:token.end + 1].encode("utf-8"))
        tokens.append({
            "name": token.name,
            "kind": token.kind,
            "start": token.start,
            "end": token.end,
            "text": value,
            "byte_span": [byte_start, byte_end],
            "text_hex": value.encode("utf-8").hex(),
        })
    assert len(tokens) == 22
    assert [item["text"] for item in tokens if item["name"] == "SELECT"] == ["SELECT", "SELECT"]
    assert [item["text"] for item in tokens if item["name"] == "SCONST"] == ["'élan Ж 😀'"]
    assert [item["name"] for item in tokens if "COMMENT" in item["name"]] == ["SQL_COMMENT", "C_COMMENT"]

    invalid = "SELECT FROM;"
    try:
        parse_sql(invalid)
    except ParseError as exc:
        error = {"class": type(exc).__name__, "args": list(exc.args)}
    else:
        raise AssertionError("pglast accepted invalid SQL")

    # AST's native serializer exposes concrete node classes, enum names,
    # optional fields, values, and locations.  JSON normalization below turns
    # its tuple children into lists, identically in the two interpreters.
    return {
        "source": SQL_SOURCE,
        "ast": [item() for item in statements],
        "tokens": tokens,
        "invalid_sql": {"source": invalid, "error": error},
    }


def probe_parsers():
    """Exercise all four pinned native extensions and return stable JSON data."""
    import json
    from importlib.metadata import version

    from tree_sitter import Language
    import tree_sitter_javascript
    import tree_sitter_typescript

    versions = {name: version(name) for name in PARSER_VERSIONS}
    assert versions == PARSER_VERSIONS, (versions, PARSER_VERSIONS)
    languages = {
        "typescript": Language(tree_sitter_typescript.language_typescript()),
        "tsx": Language(tree_sitter_typescript.language_tsx()),
        "javascript": Language(tree_sitter_javascript.language()),
    }
    result = {
        "schema_version": 1,
        "versions": versions,
        "tree_sitter": {name: _tree_probe(name, language) for name, language in languages.items()},
        "pglast": _sql_probe(),
    }
    return json.loads(json.dumps(result, ensure_ascii=True, allow_nan=False))
