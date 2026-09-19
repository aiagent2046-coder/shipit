"""SQL source observations retain precise locations without claiming runtime proof."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import zipfile

import pytest

from app.scan import sql_injection


def scan(source: str | bytes, *, coverage: dict | None = None):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("src/query.py", source)
    return sql_injection.scan_sql_injection(archive, coverage=coverage)


def test_assignment_chain_binds_exact_assembly_and_sink_to_original_bytes():
    raw = ('query = (\r\n'
           '    "SELECT SQL_SECRET_TOKEN, \'ж\' WHERE id = " + private_user_id\r\n'
           ')\r\n'
           'alias = query\r\n'
           'cursor.execute(alias)\r\n').encode()
    finding, = scan(raw)
    evidence = finding.claim_evidence
    observation = evidence["sql_observation"]
    assert observation == {
        "version": 2,
        "method": "python_ast_local_flow",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "file": "src/query.py",
        "assembly_line": 2,
        "assembly_kind": "concatenation",
        "sink_line": 5,
        "sink_method": "execute",
        "flow_status": "possible_local_flow",
        "driver_status": "unknown",
        "input_control_status": "not_checked",
    }
    assert evidence["source_check"] == {"kind": "static_rule"}
    assert evidence["conditions_status"] == evidence["consequence_status"] == "not_checked"
    assert evidence["required_conditions"] is None
    assert finding.explanation.startswith(evidence["observation"])
    assert "at line 2" in evidence["observation"]
    assert "SQL_SECRET_TOKEN" not in json.dumps(evidence)
    assert "private_user_id" not in json.dumps(evidence)
    assert scan(raw)[0].claim_evidence == evidence
    changed, = scan(raw + b"# same query, different source snapshot\r\n")
    assert changed.claim_evidence["sql_observation"]["source_sha256"] != observation["source_sha256"]


@pytest.mark.parametrize("expression,kind", [
    ('"SELECT " + user_value', "concatenation"),
    ('"SELECT %s" % user_value', "percent_format"),
    ('f"SELECT {user_value}"', "f_string"),
    ('"SELECT {}".format(user_value)', "format_call"),
    ('" ".join(user_values)', "join_call"),
])
def test_existing_assembly_shapes_have_stable_machine_names(expression, kind):
    source = f"query = {expression}\ncursor.execute(query)\n"
    finding, = scan(source)
    observation = finding.claim_evidence["sql_observation"]
    assert observation["assembly_kind"] == kind
    assert observation["assembly_line"] == 1
    assert observation["sink_line"] == finding.line == 2


def test_branch_evidence_is_a_possible_flow_not_an_unconditional_runtime_path():
    source = ('query = "SELECT 1"\n'
              'if choose_filter:\n'
              '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
              'cursor.execute(query)\n')
    finding, = scan(source)
    observation = finding.claim_evidence["sql_observation"]
    assert observation["assembly_line"] == 3
    assert observation["sink_line"] == 4
    assert observation["flow_status"] == "possible_local_flow"
    assert finding.claim_evidence["conditions_status"] == "not_checked"
    assert finding.claim_evidence["consequence_status"] == "not_checked"


def test_import_resolved_wrapper_preserves_the_inner_assembly_location():
    source = ('from sqlalchemy import text as statement\n'
              'query = "SELECT * FROM users WHERE id = " + user_id\n'
              'session.execute(\n'
              '    statement(query)\n'
              ')\n')
    finding, = scan(source)
    assert finding.line == 3
    observation = finding.claim_evidence["sql_observation"]
    assert observation["assembly_line"] == 2
    assert observation["sink_line"] == 3
    assert observation["sink_method"] == "execute"
    # A transparent SQLAlchemy text() binding cannot establish the actual
    # execution receiver's driver, much less authorize the Psycopg recipe.
    assert observation["driver_status"] == "unknown"


@pytest.mark.parametrize("source", [
    'cursor.execute("SELECT " + "1")\n',
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n',
    'query = "SELECT " + user_id\nquery = "SELECT 1"\ncursor.execute(query)\n',
    'from sqlalchemy import text\nsession.execute(text("SELECT :id"), {"id": user_id})\n',
])
def test_literals_and_parameterized_queries_do_not_create_observations(source):
    observations = {}
    assert sql_injection._find_in_module(ast.parse(source), observations=observations) == []
    assert observations == {}
    assert scan(source) == []


def test_optional_observations_preserve_legacy_signal_triples():
    source = ('query = f"SELECT {user_id}"\n'
              'cursor.execute(query)\n'
              'cursor.executemany("SELECT %s" % user_id, values)\n')
    tree = ast.parse(source)
    legacy = [(2, "execute", "an f-string at line 1"), (3, "executemany", "%-formatting")]
    observations = {}
    assert sql_injection._find_in_module(tree) == legacy
    assert sql_injection._find_in_module(tree, observations=observations) == legacy
    assert set(observations) == set(legacy)
    assert observations[legacy[0]]["assembly_line"] == 1
    assert observations[legacy[1]]["assembly_line"] == 3


def test_resource_exhaustion_preserves_only_already_observed_sink_traces(monkeypatch):
    monkeypatch.setattr(sql_injection, "_MAX_NODES", 64)
    source = ('cursor.execute("SELECT " + user_id)\n' + '0\n' * 100
              + 'cursor.execute(f"SELECT {other_id}")\n')
    coverage = {}
    finding, = scan(source, coverage=coverage)
    assert finding.line == 1
    assert finding.claim_evidence["sql_observation"]["sink_line"] == 1
    assert coverage["skip_reasons"] == {"analysis_limit": 1}
    assert coverage["partial"] is True
    assert finding.claim_evidence["conditions_status"] == "not_checked"


def test_interrupted_safe_expression_never_leaves_an_observation(monkeypatch):
    source = 'cursor.execute("SELECT " + "1")\n'
    for budget in range(30):
        monkeypatch.setattr(sql_injection, "_MAX_NODES", budget)
        observations = {}
        assert sql_injection._find_in_module(ast.parse(source), observations=observations) == []
        assert observations == {}
