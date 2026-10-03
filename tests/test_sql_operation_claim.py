"""Oct 3 production report replay and source-bound selectors; no model calls."""

from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from app.scan.claim_narrative import narrative_projection
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import compute_scores
from tests.test_python_sql_identity import SOURCES, Responses, archive, observations


def report_rows():
    rows = json.loads((Path(__file__).parent / "fixtures/python_sql_review_paraphrases.json").read_text())
    for row in rows:
        row["evidence"] = SOURCES[row["file"]].splitlines()[row["line_start"] - 1].strip()
    return rows


def selector(row):
    return dict(kind="sql_table_interpolation", target="table", line_start=row["line_start"], line_end=row["line_end"])


def run(rows):
    return run_llm_scan(archive(SOURCES), Responses([rows]), rubrics=("security",))


def test_production_report_six_paraphrases_become_three_source_bound_groups():
    findings, stats = run(report_rows())
    assert stats.verified == 6 and stats.discarded == 0
    assert len(findings) == 3
    for finding in findings:
        assert "literal list" in finding.title
        assert len(finding.claim_evidence["grouped_originals"]) == 2
        assert finding.verification_status == "unverified"
        assert narrative_projection(asdict(finding)) is not None
    original_titles = sorted(r["title"] for r in report_rows())
    leaves = [leaf for f in findings for leaf in f.claim_evidence["grouped_originals"]]
    assert sorted(r["title"] for r in leaves) == original_titles
    assert compute_scores(dedup_cross_rubric(findings + findings)) == compute_scores(findings)


def test_structured_selection_ignores_title_phrasing_and_survives_serialization():
    rows = [deepcopy(report_rows()[0]) for _ in range(3)]
    for row, title in zip(
        rows,
        [
            "Database identifier assembled from a loop value",
            "Имя таблицы подставляется в запрос",
            "Review the interpolated relation identifier",
        ],
    ):
        row.update(title=title, operation_claim=selector(row))
    findings, stats = run(rows)
    assert stats.verified == 3 and len(findings) == 1
    finding = findings[0]
    assert "literal list" in finding.title
    assert len(finding.claim_evidence["grouped_originals"]) == 3
    assert narrative_projection(json.loads(json.dumps(asdict(finding)))) is not None
    assert len(dedup_cross_rubric(findings + findings)) == 1


@pytest.mark.parametrize(
    "change", ["target", "range", "bool", "kind", "extra", "list", "compound", "where", "premises"]
)
def test_wrong_or_compound_selector_never_gets_a_source_identity(change):
    row = deepcopy(report_rows()[0])
    row["operation_claim"] = selector(row)
    if change == "target":
        row["operation_claim"]["target"] = "another_table"
    elif change == "range":
        row["operation_claim"].update(line_start=3, line_end=3)
    elif change == "bool":
        row["operation_claim"]["line_start"] = True
    elif change == "kind":
        row["operation_claim"]["kind"] = "sql_value_interpolation"
    elif change == "extra":
        row["operation_claim"]["verified"] = True
    elif change == "list":
        row["operation_claim"] = [row["operation_claim"]]
    elif change == "compound":
        row["title"] += " and missing authorization"
    elif change == "where":
        row["title"] += " and missing WHERE"
    else:
        row["premises"] = [dict(kind="sql_update_where", target="table", line_start=4, line_end=4)]
    assert SourceIssueResolver(archive(SOURCES)).identity(row) is None
    findings, stats = run([row])
    assert stats.verified == 1 and len(findings) == 1
    assert not findings[0].claim_evidence.get("narrative_projection")


@pytest.mark.parametrize(
    "title",
    [
        "Table name interpolation causes unbounded query cost",
        "SQL table name interpolation and missing WHERE clause",
        "SQL table name interpolation bypasses ownership checks",
        "SQL table name interpolation and another independent concern",
        "Unrelated Python concern",
        "SQL table name interpolation и обход проверки владельца",
    ],
)
def test_legacy_compound_and_unrelated_titles_abstain(title):
    row = {**observations()[0], "title": title}
    assert SourceIssueResolver(archive(SOURCES)).identity(row) is None


def test_structured_identity_does_not_prove_external_source_safe():
    row = report_rows()[0]
    row["operation_claim"] = selector(row)
    source = SOURCES["sqlite.py"].replace(
        "['messages', 'sessions', 'freelance_projects', 'dialog_history']", "untrusted_tables"
    )
    findings, stats = run_llm_scan(archive({"sqlite.py": source}), Responses([[row]]), rubrics=("security",))
    assert stats.verified == 1
    assert findings[0].claim_evidence["source_issue_identity"] is not None
    assert not findings[0].claim_evidence.get("narrative_projection")


@pytest.mark.parametrize(
    "source",
    [
        'db.execute(f"SELECT * FROM {table}"); db.execute(f"SELECT * FROM {other}")\n',
        'db.execute(f"SELECT * FROM {table} WHERE id = {value}")\n',
        'db.execute(f"SELECT * FROM {table.upper()}")\n',
    ],
)
def test_selector_cannot_choose_from_ambiguous_or_unsupported_sql(source):
    row = {**report_rows()[0], "line_start": 1, "line_end": 1}
    row["operation_claim"] = selector(row)
    assert SourceIssueResolver(archive({row["file"]: source})).identity(row) is None
