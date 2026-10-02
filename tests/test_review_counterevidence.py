"""Real report narratives, bounded source mutations and mocked model admission."""
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from app.report.html import _finding_row
from app.scan import review_counterevidence as review
from app.scan.claim_evidence import model_claim_evidence, narrative_review_checks
from app.scan.claim_narrative import narrative_projection, project_claim_narrative
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores
from tests.test_python_sql_identity import SOURCES, Responses, archive, observations

CORS = '''function createApp({ extensionId = process.env.SCOUT_EXTENSION_ID || "" } = {}) {
  const app = express();
  const origin = extensionId ? `chrome-extension://${extensionId}` : null;
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    if (!/^(127\\.0\\.0\\.1|localhost)(:\\d{1,5})?$/.test(req.get("host") || "")) {
      return res.status(403).json({ error: "local_host_required" });
    }
    if (req.get("origin") && req.get("origin") !== origin) return res.status(403).json({ error: "origin_denied" });
    res.set("Cache-Control", "no-store");
    next();
  });
  app.use(cors({ origin: origin || false }));
  return app;
}
'''


def cors_raw():
    return json.loads((Path(__file__).parent / "fixtures/cors_review_retraction.json").read_text())


def raw_for(kind, source=None):
    raw = observations()[0] if kind == "sql" else cors_raw()
    source = (SOURCES[raw["file"]] if kind == "sql" else CORS) if source is None else source
    # Binding is selected by actual source coordinates, not copied metadata.
    marker = 'db.execute(' if kind == "sql" else 'app.use((req'
    raw["line_start"] = raw["line_end"] = next(i for i, line in enumerate(source.splitlines(), 1) if marker in line)
    raw["evidence"] = source.splitlines()[raw["line_start"] - 1]
    return raw, {raw["file"]: source}


def observation(kind, source=None):
    raw, sources = raw_for(kind, source)
    checks = review.ReviewCounterevidence(archive(sources)).checks_for(raw)
    finding = ScoredFinding(rule_id="llm-security", title=raw["title"], explanation=raw["explanation"],
                            fix_hint=raw["fix_hint"], severity=raw["severity"], confidence=raw["confidence"],
                            category="Security", file=raw["file"], line=raw["line_start"], source="llm",
                            verification_method="model_review", claim_evidence={
                                **model_claim_evidence(raw, sources), "source_assessments": checks,
                                "producer": {"model": "fake", "response": 1, "rubric": "security"}})
    hashes = {path: sha256(source.encode()).hexdigest() for path, source in sources.items()}
    return finding, hashes


@pytest.mark.parametrize("kind", ["sql", "cors"])
def test_source_observation_corrects_report_and_preserves_model_original_and_score(kind):
    finding, hashes = observation(kind)
    before = deepcopy(finding)
    assert len(narrative_review_checks(finding.claim_evidence)) == 1
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert projected != finding and finding == before
    assert compute_scores([projected]) == compute_scores([finding])
    assert projected.verification_status == "unverified"
    saved = narrative_projection(asdict(projected))
    assert saved and saved["original"]["explanation"] == finding.explanation
    assert saved["original"]["title"] == finding.title
    assert project_claim_narrative(projected, current_source_hashes=hashes) is projected
    html = _finding_row(asdict(projected))
    assert "Outcome needs review" in html
    assert projected.title in html
    assert "Potential high impact" not in html
    if kind == "sql":
        assert "2 literal table names" in projected.explanation
        assert "exploitable injection" in projected.explanation
    else:
        assert "absent Origin" in projected.explanation
        assert "authentication" in projected.fix_hint


def test_original_six_sql_hypotheses_still_group_with_source_observations():
    rows = observations()
    findings, stats = run_llm_scan(archive(SOURCES), Responses([rows[:3], rows[3:]]),
                                  rubrics=("security",), passes=2)
    assert stats.verified == 6 and len(findings) == 3
    for finding in findings:
        assert "literal list" in finding.title
        assert len(finding.claim_evidence["grouped_originals"]) == 2
        assert narrative_projection(asdict(finding)) is not None
        assert len(narrative_review_checks(finding.claim_evidence)) == 1


def test_original_cors_self_retraction_is_corrected_in_model_pipeline():
    raw, sources = raw_for("cors")
    findings, stats = run_llm_scan(archive(sources), Responses([[raw]]), rubrics=("security",))
    assert stats.verified == len(findings) == 1
    finding = findings[0]
    assert "rejection guard" in finding.title
    assert "Wait — re-reading" not in finding.explanation
    assert "Wait — re-reading" in finding.claim_evidence["narrative_projection"]["original"]["explanation"]


@pytest.mark.parametrize("source", [
    'async def f(db, tables):\n    for table in tables:\n        await db.execute(f"SELECT * FROM {table}")\n',
    'async def f(db, value):\n    for table in [value]:\n        await db.execute(f"SELECT * FROM {table}")\n',
    'async def f(db):\n    for table in ["bad;SQL"]:\n        await db.execute(f"SELECT * FROM {table}")\n',
    SOURCES["migrate.py"].replace('        cursor =', '        table = user_input\n        cursor ='),
    SOURCES["migrate.py"].replace('        cursor =', '        unknown_call()\n        cursor ='),
    SOURCES["migrate.py"].replace('    for table', '    alias = tables\n    for table'),
    SOURCES["migrate.py"].replace('        rows =', '        tables.append(user_input)\n        rows ='),
    SOURCES["migrate.py"].replace('        rows =', '        mutate(tables)\n        rows ='),
    SOURCES["migrate.py"].replace('        rows =', '        tables = user_input\n        rows ='),
    SOURCES["migrate.py"].replace('        cursor =', '        if enabled:\n            cursor ='),
    SOURCES["migrate.py"].replace('        cursor =', '        def deferred():\n            cursor ='),
])
def test_external_mutated_aliased_or_unsupported_sql_sources_do_not_gain_counterevidence(source):
    raw, sources = raw_for("sql", source)
    assert review.ReviewCounterevidence(archive(sources)).checks_for(raw) == []
    finding, hashes = observation("sql", source)
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


@pytest.mark.parametrize("old,new", [
    (' !== origin', ' === origin'),
    (' && req.get', ' || req.get'),
    (': null;', ': "*";'),
    ('const origin', 'let origin'),
    ('status(403)', 'status(200)'),
    ('status(403).json', 'status(403)?.json'),
    ('return res.status', 'res.status'),
    ('req.get("origin")', 'req.get("host")'),
    ('SCOUT_EXTENSION_ID', 'OTHER_CONFIG'),
    ('  app.use((req', '  origin = null;\n  app.use((req'),
    ('    if (req.get', '    next();\n    if (req.get'),
    ('    if (req.get', '    req.get = other;\n    if (req.get'),
    ('    if (req.get', '    mutate(req);\n    if (req.get'),
    ('function createApp({ extensionId = process.env.SCOUT_EXTENSION_ID || "" } = {})', 'const createApp = config =>'),
])
def test_changed_cors_predicate_or_binding_remains_unresolved(old, new):
    source = CORS.replace(old, new)
    raw, sources = raw_for("cors", source)
    assert review.ReviewCounterevidence(archive(sources)).checks_for(raw) == []


def test_broad_cors_quote_cannot_select_safe_neighbor_of_unsupported_callback():
    source = CORS.replace('  app.disable(', '  app.use((req, res, next) => { next(); });\n  app.disable(')
    raw, sources = raw_for("cors", source)
    raw.update(line_start=1, line_end=len(source.splitlines()))
    assert review.ReviewCounterevidence(archive(sources)).checks_for(raw) == []


@pytest.mark.parametrize("kind", ["sql", "cors"])
@pytest.mark.parametrize("change", ["hash", "span", "quote", "outcome", "scope", "metadata"])
def test_stale_or_malformed_evidence_cannot_rewrite_a_report(kind, change):
    finding, hashes = observation(kind)
    check = finding.claim_evidence["source_assessments"][0]
    if change == "hash":
        hashes[finding.file] = "f" * 64
    elif change == "span":
        check["source_binding"]["span"] = [1, 0]
    elif change == "quote":
        finding = replace(finding, line=1)
        finding.claim_evidence["source_check"].update(line_start=1, line_end=1)
    elif change == "outcome":
        check["result"] = "contradicted"
    elif change == "scope":
        check["whole_finding"] = True
    else:
        check["narrative_review"]["premise"] = "different_claim"
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


@pytest.mark.parametrize("kind", ["sql", "cors"])
def test_work_and_check_limits_abstain(kind):
    raw, sources = raw_for(kind)
    for attr in ("work", "checks"):
        verifier = review.ReviewCounterevidence(archive(sources))
        setattr(verifier, attr, 0 if attr == "work" else review.MAX_CHECKS)
        assert verifier.checks_for(raw) == []


@pytest.mark.parametrize("kind", ["sql", "cors"])
def test_model_cannot_supply_the_new_proof(kind):
    forged, _ = observation(kind)
    source = (SOURCES["migrate.py"].replace("['freelance_projects', 'projects']", "user_input") if kind == "sql"
              else CORS.replace(' !== origin', ' === origin'))
    raw, sources = raw_for(kind, source)
    raw["source_assessments"] = forged.claim_evidence["source_assessments"]
    raw["claim_evidence"] = forged.claim_evidence
    findings, _ = run_llm_scan(archive(sources), Responses([[raw]]), rubrics=("security",))
    assert findings[0].title == raw["title"]
    assert "narrative_projection" not in findings[0].claim_evidence
