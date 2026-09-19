#!/usr/bin/env python3
"""Pinned, source-only detector and researcher processes; never run client code."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile
import uuid
import shutil

ARCHIVE_SHA256 = "dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d"
SCENARIO_SHA256 = "080d9eae864c8ca7e98cd0d3dd7b132b1b19b1fd12236357b4c81e356efaea20"
SCENARIO_ID = "cumora-project-tenant-isolation-v1"
ROUTER = "server/src/api/router.ts"
START = "api.get('/projects', async (req, res) => {"
END = "api.post('/projects', async (req, res) => {"
BEFORE = "WHERE company_id = $1"
AFTER = "WHERE $1::text IS NOT NULL"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def write(path, value):
    with path.open("xb") as stream:
        stream.write(encoded(value))


def pin_archive(archive):
    if file_hash(archive) != ARCHIVE_SHA256:
        raise ValueError("Archive SHA256 mismatch; no preparation performed")


def route_span(text):
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("Expected unique project list and create route anchors")
    start = text.index(START)
    end = text.index(END, start)
    segment = text[start:end]
    if segment.count(BEFORE) != 1 or "FROM projects" not in segment or "[tenant]" not in segment:
        raise ValueError("Expected unique parameterized project tenant predicate")
    if "await requireCompany(req)" not in segment:
        raise ValueError("Missing tenant authentication binding")
    return start, end


def source_detection(archive):
    pin_archive(archive)
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        roots = {name.split("/")[0] for name in names if name}
        if len(roots) != 1:
            raise ValueError("Expected one archive root")
        root = next(iter(roots))
        manifest_raw = bundle.read(root + "/package.json")
        router_raw = bundle.read(root + "/" + ROUTER)
        manifest = json.loads(manifest_raw)
    if not {"express", "pg"}.issubset(manifest.get("dependencies", {})):
        raise ValueError("Scenario requires Express and PostgreSQL dependencies")
    route_span(router_raw.decode())
    return {
        "schema_version": 1,
        "role": "detector",
        "status": "completed",
        "input_sha256": ARCHIVE_SHA256,
        "output": {
            "archive_sha256": ARCHIVE_SHA256,
            "manifest_sha256": digest(manifest_raw),
            "router_sha256": digest(router_raw),
            "router_path": ROUTER,
            "selected_scenario_id": SCENARIO_ID,
            "selection_reason": (
                "Pinned Express/pg source contains authenticated GET "
                "/projects with a parameterized company_id predicate"
            ),
            "source_facts": [
                "express_dependency",
                "pg_dependency",
                "authenticated_project_list",
                "tenant_sql_predicate",
            ],
            "runtime_executed": False,
        },
        "llm_calls": 0,
    }


def receipt_detection(archive):
    result = source_detection(archive)
    result["output_sha256"] = digest(encoded(result["output"]))
    return result


def tree_entries(source):
    return {p.relative_to(source).as_posix(): file_hash(p) for p in sorted(source.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    detect = sub.add_parser("detect")
    detect.add_argument("archive", type=Path)
    detect.add_argument("resultdir", type=Path)
    plan = sub.add_parser("plan")
    plan.add_argument("archive", type=Path)
    plan.add_argument("workdir", type=Path)
    plan.add_argument("resultdir", type=Path)
    args = parser.parse_args()
    args.resultdir.mkdir(parents=True, exist_ok=True)
    detector = receipt_detection(args.archive)
    if args.action == "detect":
        write(args.resultdir / "detector.json", detector)
        print("detector: selected " + SCENARIO_ID + " from pinned source signatures")
        return
    prior = json.loads((args.resultdir / "detector.json").read_text())
    if prior != detector:
        raise ValueError("Detector receipt does not match independently rechecked archive facts")
    kit = Path(__file__).resolve().parent
    if file_hash(kit / "scenario.mjs") != SCENARIO_SHA256:
        raise ValueError("Scenario SHA256 mismatch")
    for name in ("baseline", "mutant"):
        source = args.workdir / name / "source"
        if source.exists():
            raise ValueError("Source destination already exists: " + str(source))
        subprocess.run(
            [sys.executable, str(kit / "extract.py"), str(args.archive), str(source)],
            check=True,
            timeout=120,
            capture_output=True,
            text=True,
        )
    baseline = args.workdir / "baseline" / "source"
    mutant = args.workdir / "mutant" / "source"
    router = mutant / ROUTER
    original = router.read_bytes()
    text = original.decode()
    start, end = route_span(text)
    mutated = text[:start] + text[start:end].replace(BEFORE, AFTER, 1) + text[end:]
    router.write_bytes(mutated.encode())
    base_entries, mutant_entries = tree_entries(baseline), tree_entries(mutant)
    changed = sorted(
        p for p in base_entries.keys() | mutant_entries.keys() if base_entries.get(p) != mutant_entries.get(p)
    )
    if changed != [ROUTER]:
        raise ValueError("Mutation changed unexpected source files")
    # Restore from the mutant tree, rather than substituting the baseline tree.
    restored = args.workdir / "restored" / "source"
    shutil.copytree(mutant, restored)
    restored_router = restored / ROUTER
    mutant_text = restored_router.read_text()
    begin = mutant_text.index(START)
    finish = mutant_text.index(END, begin)
    segment = mutant_text[begin:finish]
    if segment.count(AFTER) != 1 or BEFORE in segment:
        raise ValueError("Unexpected mutant predicate before restoration")
    repaired = mutant_text[:begin] + segment.replace(AFTER, BEFORE, 1) + mutant_text[finish:]
    restored_router.write_bytes(repaired.encode())
    restored_entries = tree_entries(restored)
    if restored_entries != base_entries:
        raise ValueError("Restoration did not recover the exact original source tree")
    restoration = {
        "method": "inverse_predicate_on_mutant_copy",
        "from_variant": "mutant",
        "changed_files": [ROUTER],
        "exact_original_tree": True,
    }
    plan = {
        "schema_version": 1,
        "archive_sha256": ARCHIVE_SHA256,
        "scenario_id": SCENARIO_ID,
        "scenario_sha256": SCENARIO_SHA256,
        "router_path": ROUTER,
        "mutation": {
            "id": "remove-project-list-tenant-predicate",
            "before": BEFORE,
            "after": AFTER,
            "changed_files": changed,
            "scope": "GET /projects only; one predicate substitution; parameter count unchanged",
        },
        "restoration": restoration,
        "variants": {
            name: {
                "router_sha256": entries[ROUTER],
                "tree_sha256": digest(encoded(entries)),
                "run_id": str(uuid.uuid4()),
            }
            for name, entries in [
                ("baseline", base_entries),
                ("mutant", mutant_entries),
                ("restored", restored_entries),
            ]
        },
        "tree_hash_algorithm": (
            "sha256 of sorted, indented JSON mapping relative POSIX paths to file sha256, with trailing newline"
        ),
        "detector_output_sha256": detector["output_sha256"],
        "llm_calls": 0,
        "fixture_setup": "clear_projects_in_disposable_database",
        "fixture_requirement": (
            "All three disposable databases must contain zero projects before the unchanged "
            "scenario starts; default p-aurora seed otherwise makes mutant fail at list_owner"
        ),
        "runtime_executed": False,
    }
    write(args.resultdir / "plan.json", plan)
    write(
        args.resultdir / "researcher.json",
        {
            "schema_version": 1,
            "role": "researcher",
            "status": "completed",
            "input_sha256": file_hash(args.resultdir / "detector.json"),
            "output_sha256": file_hash(args.resultdir / "plan.json"),
            "output_artifact": "plan.json",
            "llm_calls": 0,
            "runtime_executed": False,
        },
    )
    print("researcher: prepared baseline, mutant and restored; restored tree exactly matches baseline")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error))
