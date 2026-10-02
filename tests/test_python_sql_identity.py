"""Regression from the six SQL hypotheses in Kristina audit d2c2e5ef.

Original narratives, minimized source, remapped coordinates; no LLM requests.
Grouping must never claim that injection or attacker control was verified.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.llm.client import LLMClient, LLMUsage
from app.scan import python_sql_identity as sql
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.llm_scan import _iter_code_files, run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores


SOURCES = {
    "migrate.py": '''async def migrate(db):
    tables = ['freelance_projects', 'projects']
    for table in tables:
        cursor = await db.execute(f"SELECT * FROM {table}")
        rows = await cursor.fetchall()
    return rows
''',
    "sqlite.py": '''async def get_stats(conn):
    stats = {}
    for table in ['messages', 'sessions', 'freelance_projects', 'dialog_history']:
        cursor = await conn.execute(f"SELECT COUNT(*) FROM {table}")
        row = await cursor.fetchone()
        stats[table] = row[0] if row else 0
    return stats
''',
    "postgres.py": '''async def get_stats(conn):
    stats = {}
    tables = ['messages', 'sessions', 'freelance_projects', 'dialog_history', 'knowledge']
    for table in tables:
        count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
        stats[table] = count
    return stats
''',
}


def archive(sources):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zf:
        for path, source in sources.items():
            zf.writestr(path, source)
    result.seek(0)
    return result


def observations():
    data = json.loads((Path(__file__).parent / "fixtures/python_sql_review_pairs.json").read_text())
    for row in data:
        row["evidence"] = "\n".join(SOURCES[row["file"]].splitlines()[2:6])
    return data


def scored(raw, identity):
    return ScoredFinding(
        rule_id="llm-security", title=raw["title"], file=raw["file"], line=raw["line_start"],
        explanation=raw["explanation"], fix_hint=raw["fix_hint"], severity="high", confidence=0.85,
        category="Security", source="llm", verification_method="model_review",
        claim_evidence={"source_issue_identity": identity,
                        "source_check": {"kind": "quote_match", "line_start": raw["line_start"],
                                         "line_end": raw["line_end"]},
                        "producer": {"model": "fake", "rubric": "security", "response": raw["report_id"]},
                        "observation": raw["observation"], "required_conditions": raw["required_conditions"],
                        "conditions_status": "not_checked", "consequence_status": "not_checked"})


def pairs():
    resolver = SourceIssueResolver(archive(SOURCES))
    return [scored(raw, resolver.identity(raw)) for raw in observations()]


def test_six_report_hypotheses_form_three_groups_preserving_originals_and_scores():
    rows = pairs()
    assert all(sql.valid_sql_identity(row.claim_evidence["source_issue_identity"], row.file) for row in rows)
    grouped = dedup_cross_rubric(rows)
    assert len(grouped) == 3
    assert compute_scores(grouped) == compute_scores(rows[:3])
    assert sorted(leaf["claim_evidence"]["producer"]["response"] for row in grouped
                  for leaf in row.claim_evidence["grouped_originals"]) == [7, 8, 9, 19, 20, 21]
    for row in grouped:
        assert row.title == "SQL table-name interpolation requires review"
        assert row.verification_status == "unverified"
        assert len(row.claim_evidence["grouped_originals"]) == 2
    originals = sorted((asdict(row) for row in rows), key=lambda r: r["claim_evidence"]["producer"]["response"])
    for replay in (grouped, grouped + rows, rows + grouped, grouped + grouped):
        result = dedup_cross_rubric(replay)
        assert len(result) == 3
        assert compute_scores(result) == compute_scores(grouped)
        leaves = [leaf for row in result for leaf in row.claim_evidence["grouped_originals"]]
        assert sorted(leaves, key=lambda r: r["claim_evidence"]["producer"]["response"]) == originals


@pytest.mark.parametrize("change", ["status", "hash", "compound", "premise", "quote", "producer", "conditions"])
def test_incompatible_or_unbound_claims_do_not_merge(change):
    rows = pairs()
    left, right = rows[0], deepcopy(rows[3])
    evidence = right.claim_evidence
    if change == "status":
        right = replace(right, verification_status="observed")
    elif change == "hash":
        evidence["source_issue_identity"]["source_sha256"] = "f" * 64
    elif change == "compound":
        right = replace(right, explanation=right.explanation + " A separate authentication issue exists.")
    elif change == "premise":
        evidence["premise_checks"] = [{"kind": "other", "result": "observed"}]
    elif change == "quote":
        evidence["source_check"]["line_end"] = 3
    elif change == "producer":
        evidence["producer"]["response"] = True
    else:
        evidence["conditions_status"] = "observed"
    assert len(dedup_cross_rubric([left, right])) == 2


@pytest.mark.parametrize("source", [
    'db.execute(f"SELECT * FROM {table} WHERE id = {value}")\n',
    'db.execute(f"SELECT * FROM {table!r}")\n',
    'db.execute(f"SELECT * FROM {table.upper()}")\n',
    'db.execute(f"SELECT * FROM {table}"); db.execute("SELECT 1")\n',
    'db.execute(f"SELECT * FROM {table}"); db.fetchval(f"SELECT * FROM {other}")\n',
    'db.execute("SELECT * FROM users")\n',
    'def invalid(\n',
])
def test_ambiguous_or_unsupported_source_abstains(source):
    raw = {**observations()[0], "file": "migrate.py", "line_start": 1, "line_end": 1}
    assert SourceIssueResolver(archive({"migrate.py": source})).identity(raw) is None


def test_nearby_calls_keep_distinct_identities_and_uncited_call_is_not_selected():
    source = 'db.execute(f"SELECT * FROM {table}")\ndb.execute(f"SELECT * FROM {other}")\n# comment\n'
    resolver = SourceIssueResolver(archive({"migrate.py": source}))
    first = {**observations()[0], "line_start": 1, "line_end": 1}
    second = {**first, "line_start": 2, "line_end": 2}
    a, b = resolver.identity(first), resolver.identity(second)
    assert a and b and a != b
    assert len(dedup_cross_rubric([scored(first, a), scored(second, b)])) == 2
    assert resolver.identity({**first, "line_start": 3, "line_end": 3}) is None


@pytest.mark.parametrize("limit", ["MAX_CHECKS", "MAX_NODES", "MAX_DEPTH", "MAX_BYTES", "MAX_TOTAL_BYTES",
                                  "MAX_FILES", "MAX_WORK_NODES"])
def test_exhausted_budgets_abstain(monkeypatch, limit):
    monkeypatch.setattr(sql, limit, 0)
    assert SourceIssueResolver(archive(SOURCES)).identity(observations()[0]) is None


def test_paths_duplicate_members_and_symlinks_abstain():
    raw = observations()[0]
    for path in ("../migrate.py", "/migrate.py", "a\\migrate.py"):
        assert SourceIssueResolver(archive({path: SOURCES[raw["file"]]})).identity({**raw, "file": path}) is None
    data = archive(SOURCES)
    with zipfile.ZipFile(data, "a") as zf, pytest.warns(UserWarning):
        zf.writestr(raw["file"], SOURCES[raw["file"]])
    assert SourceIssueResolver(data).identity(raw) is None
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        info = zipfile.ZipInfo(raw["file"])
        info.external_attr = 0o120777 << 16
        zf.writestr(info, SOURCES[raw["file"]])
    assert SourceIssueResolver(data).identity(raw) is None


def test_unsupported_python_claims_do_not_exhaust_other_identity_checks():
    resolver = SourceIssueResolver(archive(SOURCES))
    raw = observations()[0]
    for _ in range(sql.MAX_CHECKS + 1):
        assert resolver.identity({**raw, "title": "Unrelated Python concern"}) is None
    assert resolver.identity(raw) is not None


class Responses(LLMClient):
    def __init__(self, batches):
        super().__init__(providers=[])
        self.batches = iter(batches)
        self.prompts = []

    def complete(self, system, user, max_tokens=4096):
        self.prompts.append(user)
        return json.dumps(next(self.batches)), LLMUsage(model="fake", input_tokens=100, output_tokens=50)


def test_two_pass_pipeline_groups_actual_report_narratives():
    rows = observations()
    client = Responses([rows[:3], rows[3:]])
    findings, stats = run_llm_scan(archive(SOURCES), client, rubrics=("security",), passes=2)
    assert stats.calls == 2
    assert stats.verified == 6 and stats.discarded == 0
    assert len(findings) == 3
    assert sum(len(row.claim_evidence["grouped_originals"]) for row in findings) == 6


@pytest.mark.parametrize("suffix", ["mjs", "cjs"])
def test_module_files_reach_model_and_quote_admission(suffix):
    path = f"src/documents.{suffix}"
    source = "function render(input) { document.body.innerHTML = input; }\n"
    source += "export { render };\n" if suffix == "mjs" else "module.exports = { render };\n"
    raw = {"file": path, "line_start": 1, "line_end": 1, "evidence": source.splitlines()[0],
           "severity": "medium", "confidence": 0.8, "title": "Unescaped HTML content",
           "explanation": "Input may contain HTML.", "fix_hint": "Use textContent."}
    client = Responses([[raw]])
    findings, stats = run_llm_scan(archive({path: source}), client, rubrics=("security",))
    assert path in client.prompts[0]
    assert len(findings) == stats.verified == 1
    assert findings[0].file == path
    with zipfile.ZipFile(archive({path: source, f"node_modules/vendor.{suffix}": source,
                               f"dist/bundle.{suffix}": source})) as zf:
        assert [name for name, _ in _iter_code_files(zf)] == [path]
