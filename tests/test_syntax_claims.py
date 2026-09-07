"""Source counterexamples, unknown cases and storage/reporting boundaries."""
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.report.evidence import finding_counts, source_severity_counts
from app.report.html import render_report
from app.scan.claim_evidence import syntax_contradicted
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.syntax_claims import MAX_CHECKS, MAX_FILE_BYTES, SyntaxVerifier
from tests.conftest import run_audit_job
from tests.test_audit_llm_wiring import FakeLLM, make_zip


HOOK_TITLE = "useState calls follow an early return — hook order changes"
SQL_TITLE = "UPDATE without a WHERE clause"


def check(source, *, sql=False, start=1, end=None, title=None):
    path = "migration.sql" if sql else "Component.tsx"
    data = source.encode() if isinstance(source, str) else source
    archive = make_zip({path: data})
    raw = {"file": path, "line_start": start, "line_end": end or len(data.splitlines()),
           "title": title or (SQL_TITLE if sql else HOOK_TITLE)}
    return SyntaxVerifier(archive).check(raw)


@pytest.mark.parametrize(("body", "expected"), [
    ("const [x]=useState(0); if (!ok) return null; return x;", "contradicted"),
    ("if (!ok) return null; const [x]=useState(0); return x;", "observed"),
    ("if (!ok) {return null;} const [x]=useState(0); return x;", "observed"),
    ("const [x]=useState(0); const cb=()=>{return 1;}; if(!ok)return null; return x;", "contradicted"),
    ('const text="return null; useState(0)"; const [x]=useState(0); return x;', "contradicted"),
    ("// if (!ok) return null;\nconst [x]=useState(0); return x;", "contradicted"),
    ("if(ok){const [x]=useState(0);} return null;", "not_checked"),
    ("const [x]=useState(0); if (!ok) return null; useCustom(); return x;", "not_checked"),
    ("const [x]=useState(0); const alias=useState; if (!ok)return null; alias(1); return x;", "not_checked"),
    ("function useState(){return 1;} const x=useState(); return x;", "not_checked"),
    ("const [x]=useState(0); if (!ok) return null; useState = fake; return x;", "not_checked"),
    ("try {if(!ok)return null;} finally {} const [x]=useState(0); return x;", "not_checked"),
    ("const [x]=useState(0); if (", "not_checked"),
])
def test_react_order(body, expected):
    source = 'import {useState} from "react";\nexport function Component({ok}) {\n' + body + '\n}'
    assert check(source, start=2)["result"] == expected


@pytest.mark.parametrize("source", [
    'import {useState as state} from "react";\nconst Component=()=>{const [x]=state(0); return x;};',
    'import React from "react";\nfunction Component(){const [x]=React.useState(0);return x;}',
    'import * as R from "react";\nfunction Component(){const [x]=R.useState(0);return x;}',
])
def test_react_import_aliases(source):
    assert check(source, start=2)["result"] == "contradicted"


@pytest.mark.parametrize("source", [
    'import {useState} from "elsewhere";\nfunction Component(){const x=useState();return x;}',
    'import {useState} from "react";\nfunction Component(useState){const x=useState();return x;}',
    'import {use} from "react";\nfunction Component(){if(x)return null; return use(promise);}',
    'import {useState} from "react";\nfunction A(){return null;} function B(){useState();return null;}',
    'import {useState} from "react";\n// useState calls after early return\nconst x=1;',
    'import {useState} from "react";\nfunction A(){useState();return null;} function B(){useState();return null;}',
    'import type {useState} from "react";\nfunction Component(){useState();return null;}',
])
def test_react_unknown_binding_or_location(source):
    assert check(source, start=2)["result"] == "not_checked"


@pytest.mark.parametrize(("binding", "callee"), [("useState", "useState"), ("React", "React.useState")])
def test_enclosing_function_parameter_can_shadow_react_import(binding, callee):
    source = ('import React, {useState} from "react";\n'
              f'function wrapper({binding}) {{\n'
              f'  function Component() {{const [x]={callee}(0); return x;}}\n'
              '  return Component;\n}')
    assert check(source, start=3, end=3)["result"] == "not_checked"


@pytest.mark.parametrize(("source", "expected"), [
    ("UPDATE payments SET amount=1 WHERE id=2;", "contradicted"),
    ("UPDATE payments SET amount=1;", "observed"),
    ("UPDATE payments SET amount=1 WHERE true;", "contradicted"),
    ("WITH c AS (SELECT 1 WHERE true) UPDATE payments SET amount=1;", "observed"),
    ("UPDATE payments SET amount=(SELECT 1 WHERE true);", "observed"),
    ("UPDATE payments SET note='WHERE id=2'; -- WHERE false", "observed"),
    ("UPDATE payments SET note=$tag$WHERE id=2$tag$;", "observed"),
    ("UPDATE payments SET amount=1 /* WHERE id=2 */;", "observed"),
    ("WITH c AS (SELECT 1) UPDATE payments SET amount=1 WHERE id IN (SELECT * FROM c);", "contradicted"),
    ("UPDATE payments SET amount=1; UPDATE payments SET amount=2 WHERE id=1;", "not_checked"),
    ("WITH c AS (UPDATE a SET n=1 RETURNING *) UPDATE b SET n=2 WHERE id=1;", "not_checked"),
    ("DO $$ BEGIN UPDATE payments SET amount=1; END $$;", "not_checked"),
    ("UPDATE payments SET ;", "not_checked"),
    ("UPDATE `payments` SET amount=1 WHERE id=2;", "not_checked"),
    ("-- UPDATE payments SET amount=1\nSELECT 1;", "not_checked"),
])
def test_sql_own_where_not_comments_or_other_statements(source, expected):
    assert check(source, sql=True)["result"] == expected


def test_sql_statement_binding_with_unicode_and_multiple_statements():
    source = "-- Пример\nSELECT 'данные';\nUPDATE a SET n=1;\nUPDATE a SET n=2 WHERE id=1;"
    assert check(source, sql=True, start=3, end=3)["result"] == "observed"
    assert check(source, sql=True, start=4, end=4)["result"] == "contradicted"
    assert check(source, sql=True, start=1, end=1)["result"] == "not_checked"


def test_real_report_counterexamples():
    react = Path("web/src/components/RlsCheck.tsx").read_text()
    assert check(react, start=96, end=118)["result"] == "contradicted"
    sql = Path("migrations/0035_payments_fixpack_job_id.sql").read_text()
    assert check(sql, sql=True, start=56, end=67)["result"] == "contradicted"


def test_contradicting_one_premise_must_not_dismiss_a_compound_title():
    assert check("UPDATE a SET n=1 WHERE id=2;", sql=True,
                 title="UPDATE without WHERE and missing authorization")["result"] == "not_checked"


def test_fail_closed_on_invalid_encoding_and_limits():
    assert check(b"\xff UPDATE a SET n=1;", sql=True)["result"] == "not_checked"
    assert check(" " * MAX_FILE_BYTES + "UPDATE a SET n=1;", sql=True)["result"] == "not_checked"
    data = b"UPDATE a SET n=1;"
    verifier = SyntaxVerifier(make_zip({"a.sql": data}))
    raw = {"file": "a.sql", "title": SQL_TITLE, "line_start": 1, "line_end": 1}
    verifier.remaining = len(data) - 1
    assert verifier.check(raw)["result"] == "not_checked"
    verifier.remaining = len(data) * (MAX_CHECKS + 1)
    verifier.checks = MAX_CHECKS
    assert verifier.check(raw)["result"] == "not_checked"
    verifier.checks = 0
    assert verifier.check({**raw, "title": "Missing access control"})["result"] == "not_checked"
    assert verifier.check({**raw, "line_start": 10})["result"] == "not_checked"


def test_duplicate_archive_paths_are_ambiguous():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.sql", "UPDATE a SET n=1 WHERE id=1;")
        with pytest.warns(UserWarning):
            zf.writestr("a.sql", "UPDATE a SET n=1;")
    assert SyntaxVerifier(archive).check({"file": "a.sql", "title": SQL_TITLE,
                                          "line_start": 1, "line_end": 1})["result"] == "not_checked"


async def test_storage_reports_counts_and_scores_keep_contradictions_separate():
    raw = {"file": "migration.sql", "line_start": 1, "line_end": 1,
           "evidence": "UPDATE payments", "title": SQL_TITLE, "severity": "critical", "confidence": 1,
           "explanation": "All rows might change.", "fix_hint": "<script>original suggestion</script>",
           "claim_evidence": {"syntax_check": {"result": "observed"}}}
    archive = make_zip({"migration.sql": b"UPDATE payments SET n=1 WHERE id=2;"})
    row = await run_audit_job(archive.getvalue(), llm_client=FakeLLM(response=json.dumps([raw])),
                             account_id="44444444-4444-4444-4444-444444444444")
    model = next(f for f in row["findings_json"] if f["source"] == "llm")
    assert syntax_contradicted(model["claim_evidence"])
    assert model["claim_evidence"]["consequence_status"] == "not_checked"
    assert finding_counts([model]) == (0, 0)
    assert source_severity_counts([model])["critical"] == 0
    scored = ScoredFinding(rule_id="llm-money", title=SQL_TITLE, severity="critical", confidence=1,
                           category="Money & Data", claim_evidence=model["claim_evidence"])
    assert compute_scores([scored]) == compute_scores([])
    html = render_report({"score": row["score_json"], "findings": [model]})
    assert "Contradicted syntax premises" in html
    assert "Potential critical impact" not in html
    assert "&lt;script&gt;original suggestion&lt;/script&gt;" in html
    assert "<script>original suggestion" not in html
    # A different unresolved claim at the same line must survive deduplication.
    other = ScoredFinding(rule_id="llm-security", title="Unauthorized caller", severity="high", confidence=1,
                          category="Security")
    assert len(dedup_cross_rubric([scored, other])) == 2
