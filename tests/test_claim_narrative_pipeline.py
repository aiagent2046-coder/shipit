"""The production stage must project after grouping using current ZIP bytes."""
from dataclasses import asdict
import hashlib
import json
import zipfile

from app.scan.claim_narrative import narrative_projection, project_claim_narrative
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.llm_scan import _iter_code_files, run_llm_scan
from tests.test_audit_llm_wiring import FakeLLM
from tests.test_source_claim_assessment import CALLER, HELPER, archive


def test_stage_projects_group_without_replacing_originals_and_reapplication_is_stable():
    sources = {"app/auth.ts": CALLER, "app/helper.ts": HELPER}
    raw = {
        "file": "app/auth.ts", "line_start": 3, "line_end": 3, "evidence": "{data: facts}",
        "title": "All facts are injected into every model prompt", "severity": "medium", "confidence": 0.8,
        "explanation": "Every saved fact increases the prompt and cost without any limit.",
        "observation": "All database facts reach the rendered prompt.",
        "fix_hint": "Limit the number of facts before rendering.",
    }
    findings, stats = run_llm_scan(archive(sources), FakeLLM(response=json.dumps([raw])),
                                    rubrics=("auth",), passes=2)
    row, = findings
    p = narrative_projection(asdict(row))
    assert p and "40 items" in p["active"]["observation"]
    assert p["original"]["title"] == raw["title"]
    originals = row.claim_evidence["grouped_originals"]
    assert len(originals) == 2
    assert {o["claim_evidence"]["producer"]["response"] for o in originals} == {1, 2}
    assert all(o["title"] == raw["title"] and "narrative_projection" not in o["claim_evidence"] for o in originals)
    hashes = {path: hashlib.sha256(source.encode()).hexdigest() for path, source in sources.items()}
    repeated = [project_claim_narrative(f, current_source_hashes=hashes) for f in dedup_cross_rubric(findings)]
    assert repeated == findings
    assert stats.model_findings[0]["accepted"] == 2
    assert stats.model_findings[0]["saved"] == 1
    assert stats.model_findings[0]["merged"] == 1


def test_file_collection_hashes_raw_bytes_without_changing_prompt_decoding():
    raw = b"// invalid byte: \xff\nexport const facts = [];\n"
    stream = archive({"src/caller.ts": raw, "tsconfig.json": '{"compilerOptions":{}}'})
    hashes = {}
    with zipfile.ZipFile(stream) as zf:
        files = dict(_iter_code_files(zf, source_hashes=hashes))
    assert files["src/caller.ts"] == raw.decode("utf-8", errors="ignore")
    assert hashes["src/caller.ts"] == hashlib.sha256(raw).hexdigest()
    assert hashes["src/caller.ts"] != hashlib.sha256(files["src/caller.ts"].encode()).hexdigest()
    assert "tsconfig.json" in hashes
