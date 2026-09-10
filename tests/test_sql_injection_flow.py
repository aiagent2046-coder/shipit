"""SQL findings must follow the value reaching the sink in its local scope."""

from __future__ import annotations

import io
import textwrap
import zipfile

import pytest

from app.scan.sql_injection import scan_sql_injection
from app.scan.sql_injection_js import scan_sql_injection_js


def scan(source: str, extension: str):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("README.md", "Synthetic SQL flow regression")
        zf.writestr(f"src/queries.{extension}", textwrap.dedent(source).strip())
    scanner = scan_sql_injection if extension == "py" else scan_sql_injection_js
    return scanner(archive)


@pytest.mark.parametrize("source, lines", [
    pytest.param('''
        query = "SELECT * FROM users"
        cur.execute(query)
        query = "SELECT * FROM users WHERE id = " + user_id
    ''', [], id="later-assignment-cannot-taint-earlier-call"),
    pytest.param('''
        query = "SELECT * FROM users WHERE id = " + user_id
        query = "SELECT * FROM users WHERE id = %s"
        cur.execute(query, (user_id,))
    ''', [], id="safe-reassignment"),
    pytest.param('''
        query = "SELECT * FROM users WHERE id = %s"
        query = "SELECT * FROM users WHERE id = " + user_id
        cur.execute(query)
    ''', [3], id="unsafe-reassignment"),
    pytest.param('''
        def label(user):
            query = "user:" + user
            return query
        def users(cur):
            query = "SELECT * FROM users"
            cur.execute(query)
    ''', [], id="sibling-function-bindings"),
    pytest.param('''
        query = "SELECT * FROM users WHERE id = " + user_id
        def users(cur, query):
            cur.execute(query)
    ''', [], id="parameter-shadows-module-query"),
    pytest.param('''
        def users(cur, user_id):
            query = "SELECT * FROM users"
            def build():
                query = "SELECT * FROM users WHERE id = " + user_id
                return query
            cur.execute(query)
    ''', [], id="nested-function-assignment-does-not-run"),
    pytest.param('''
        def users(cur, user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            def count():
                query = "SELECT count(*) FROM users"
                cur.execute(query)
            cur.execute(query)
    ''', [6], id="nested-safe-query-does-not-erase-outer-query"),
    pytest.param('''
        def users(cur, user_id):
            query: str = "SELECT * FROM users WHERE id = " + user_id
            query: str
            cur.execute(query)
    ''', [4], id="annotated-assignment-and-annotation-only"),
    pytest.param('''
        query = "SELECT * FROM users"
        if filtered:
            query = "SELECT * FROM users WHERE id = " + user_id
        cur.execute(query)
    ''', [4], id="possible-unsafe-branch"),
    pytest.param('''
        query = "SELECT * FROM users WHERE id = " + user_id
        if filtered:
            query = "SELECT * FROM users WHERE id = %s"
        else:
            query = "SELECT * FROM users WHERE email = %s"
        cur.execute(query, (value,))
    ''', [], id="all-branches-replace-unsafe-query"),
    pytest.param('''
        TABLES = ("users", "messages")
        def count(cur):
            for table in TABLES:
                query = f"SELECT count(*) FROM {table}"
                cur.execute(query)
    ''', [], id="literal-loop-query-through-variable"),
    pytest.param('''
        TABLES = {"users": "id", "messages": "user_id"}
        def count(cur):
            for table, column in TABLES.items():
                query = f"SELECT {column} FROM {table}"
                cur.execute(query)
    ''', [], id="literal-dict-loop"),
    pytest.param('''
        def count(cur, tables):
            for table in tables:
                query = f"SELECT count(*) FROM {table}"
                cur.execute(query)
    ''', [4], id="request-controlled-loop"),
    pytest.param('''
        table = "users"
        table, unused = request.args.get("table"), 0
        cur.execute(f"SELECT * FROM {table}")
    ''', [3], id="destructuring-invalidates-constant"),
    pytest.param('''
        TABLE = "users"
        query = f"SELECT * FROM {TABLE}"
        cur.execute(query)
    ''', [], id="constant-f-string-through-variable"),
    pytest.param('''
        query = "SELECT * FROM users WHERE id = "
        query += user_id
        query += " ORDER BY id"
        sql = query
        cur.execute(sql)
    ''', [5], id="incremental-query-and-alias"),
    pytest.param('''
        query = "SELECT * FROM users"
        for user_id in ids:
            cur.execute(query)
            query = "SELECT * FROM users WHERE id = " + user_id
    ''', [3], id="query-reaches-next-loop-iteration"),
])
def test_python_reaching_query_values(source, lines):
    assert [finding.line for finding in scan(source, "py")] == lines


@pytest.mark.parametrize("source, lines", [
    pytest.param('''
        const key = "user:" + userId;
        new Map().get(key);
        cache.get(key);
        jobs.run(key);
    ''', [], id="non-sql-variables-at-weak-sinks"),
    pytest.param('''
        const query = "SELECT * FROM users WHERE id = " + userId;
        db.execute(query);
    ''', [2], id="sql-variable-at-weak-sink"),
    pytest.param('''
        let query = "SELECT * FROM users WHERE id = ";
        query += userId;
        query += " ORDER BY id";
        const statement = query;
        db.all(statement);
    ''', [5], id="sql-evidence-survives-plus-equals-and-alias"),
    pytest.param('''
        let query = "SELECT * FROM users";
        db.query(query);
        query = "SELECT * FROM users WHERE id = " + userId;
    ''', [], id="later-assignment-cannot-taint-earlier-call"),
    pytest.param('''
        let query = "SELECT * FROM users WHERE id = " + userId;
        query = "SELECT * FROM users WHERE id = $1";
        db.query(query, [userId]);
    ''', [], id="safe-reassignment"),
    pytest.param('''
        let query = "SELECT * FROM users WHERE id = $1";
        query = "SELECT * FROM users WHERE id = " + userId;
        db.query(query);
    ''', [3], id="unsafe-reassignment"),
    pytest.param('''
        function label(id) { const query = "user:" + id; return query; }
        function users(db) { const query = "SELECT * FROM users"; db.query(query); }
    ''', [], id="sibling-function-bindings"),
    pytest.param('''
        const query = "SELECT * FROM users WHERE id = " + userId;
        const users = (query: string) => db.query(query);
    ''', [], id="arrow-parameter-shadows-module-query"),
    pytest.param('''
        function users(db, userId) {
          const query = "SELECT * FROM users";
          function build() { const query = "SELECT * FROM users WHERE id = " + userId; }
          db.query(query);
        }
    ''', [], id="nested-function-assignment-does-not-run"),
    pytest.param('''
        const query = "SELECT * FROM users WHERE id = " + userId;
        { const query = "SELECT * FROM users"; db.query(query); }
        db.query(query);
    ''', [3], id="lexical-block-shadow-restores-outer-binding"),
    pytest.param('''
        let query = "SELECT * FROM users WHERE id = " + userId;
        { query = "SELECT * FROM users WHERE id = $1"; }
        db.query(query, [userId]);
    ''', [], id="block-assignment-updates-visible-binding"),
    pytest.param('''
        function users(db, id) {
          { var query = "SELECT * FROM users WHERE id = " + id; }
          db.query(query);
        }
    ''', [3], id="var-is-function-scoped"),
    pytest.param('''
        let query = "SELECT * FROM users";
        if (filtered) { query = "SELECT * FROM users WHERE id = " + userId; }
        db.query(query);
    ''', [3], id="possible-unsafe-branch"),
    pytest.param('''
        let query = "SELECT * FROM users WHERE id = " + userId;
        if (filtered) { query = "SELECT * FROM users WHERE id = $1"; }
        else { query = "SELECT * FROM users WHERE email = $1"; }
        db.query(query, [value]);
    ''', [], id="all-branches-replace-unsafe-query"),
    pytest.param('''
        const tables = ["users", "messages"];
        function count(db) {
          for (const table of tables) {
            const query = `SELECT count(*) FROM ${table}`;
            db.query(query);
          }
        }
    ''', [], id="literal-loop-query-through-variable"),
    pytest.param('''
        function count(db, tables) {
          for (const table of tables) { db.query(`SELECT count(*) FROM ${table}`); }
        }
    ''', [2], id="request-controlled-loop"),
    pytest.param('''
        db.query(["SELECT ", "1"].join(""));
        const table = "users";
        db.query(`SELECT * FROM ${table}`);
    ''', [], id="literal-assemblies-are-safe"),
    pytest.param('''
        let query = "SELECT * FROM users";
        for (const userId of ids) {
          db.query(query);
          query = "SELECT * FROM users WHERE id = " + userId;
        }
    ''', [3], id="query-reaches-next-loop-iteration"),
])
def test_javascript_reaching_query_values(source, lines):
    assert [finding.line for finding in scan(source, "ts")] == lines


@pytest.mark.parametrize("expression", [
    '("SELECT * FROM users WHERE id = " + userId)',
    '("SELECT * FROM users WHERE id = " + userId) as string',
    '(("SELECT * FROM users WHERE id = " + userId) as string)!',
    '<string>("SELECT * FROM users WHERE id = " + userId)',
    '("SELECT * FROM users WHERE id = " + userId) satisfies string',
])
@pytest.mark.parametrize("through_variable", [False, True])
def test_typescript_transparent_wrappers_preserve_unsafe_query(expression, through_variable):
    source = (f"const query = {expression};\ndb.query((query as string)!);"
              if through_variable else f"db.query({expression});")
    findings = scan(source, "ts")
    assert [finding.line for finding in findings] == [2 if through_variable else 1]


def test_typescript_transparent_wrappers_preserve_parameterization():
    assert not scan('db.query(("SELECT * FROM users WHERE id = $1" as string)!, [userId]);', "ts")


@pytest.mark.parametrize("extension, source, lines", [
    pytest.param("py", '''
        def users(cur, user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            def run():
                cur.execute(query)
            return run
    ''', [4], id="python-stable-closure-binding"),
    pytest.param("ts", '''
        function users(db, userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.transaction(async tx => tx.query(query));
        }
    ''', [3], id="typescript-transaction-closure-binding"),
    pytest.param("py", '''
        def users(cur, user_id):
            query = "SELECT * FROM users WHERE id = " + user_id
            def run():
                cur.execute(query, (user_id,))
            query = "SELECT * FROM users WHERE id = %s"
            return run
    ''', [], id="python-do-not-freeze-reassigned-capture"),
    pytest.param("ts", '''
        function users(db, userId) {
          let query = "SELECT * FROM users WHERE id = " + userId;
          const run = () => db.query(query, [userId]);
          query = "SELECT * FROM users WHERE id = $1";
          return run;
        }
    ''', [], id="typescript-do-not-freeze-reassigned-capture"),
])
def test_stable_closure_captures(extension, source, lines):
    assert [finding.line for finding in scan(source, extension)] == lines


@pytest.mark.parametrize("extension", ["py", "ts"])
def test_deep_expression_does_not_abort_later_files(extension):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("README.md", "Synthetic parser depth regression")
        zf.writestr(f"src/deep.{extension}", "x" + ".a" * 1200)
        zf.writestr(f"src/query.{extension}", 'db.execute("SELECT * FROM users WHERE id = " + user_id)')
    scanner = scan_sql_injection if extension == "py" else scan_sql_injection_js
    findings = scanner(archive)
    assert [(finding.file, finding.line) for finding in findings] == [(f"src/query.{extension}", 1)]
