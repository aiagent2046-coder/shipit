#!/usr/bin/env python3
"""Compare Sonnet/MiMo on identical pinned repository prompts, without deploying.

Prepare-only by default. Raw responses are hypotheses, not production findings.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.llm.client import LLMClient, Provider  # noqa: E402
from app.scan import llm_scan  # noqa: E402
from app.scan.source_facts import collect_source_facts, facts_prompt  # noqa: E402
from scripts.env_file import read_values  # noqa: E402
from scripts.evaluate_audit_models import run, save  # noqa: E402

MODELS = ("claude-sonnet-4.6", "mimo-v2.6-pro")


def prepare_archive(data: bytes, revision: str) -> dict:
    # Deliberately use the SAME production Sonnet selection budget for both
    # models. MiMo is not yet in production model metadata (unknown => 200K).
    sizing = LLMClient(providers=[Provider("openai_compat", "", "", MODELS[0])])
    budget = llm_scan.content_budget(sizing)
    limit = llm_scan.request_limit_for(sizing)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = llm_scan._iter_code_files(archive)
    originals = dict(files)
    source_facts = collect_source_facts(io.BytesIO(data))
    context = facts_prompt(source_facts, min(16_000, max(0, (limit - len(llm_scan.SYSTEM_PROMPT)) // 5)))
    cases = []
    for rubric in llm_scan.ALL_RUBRICS:
        selected = llm_scan.select_files(files, rubric, budget)
        if not selected:
            continue
        selected, prompt = llm_scan.fit_to_window(
            selected, rubric, limit - len(llm_scan.SYSTEM_PROMPT), context)
        cases.append({"id": rubric, "prompt": prompt,
                      "prompt_sha256": hashlib.sha256((llm_scan.SYSTEM_PROMPT + "\0" + prompt).encode()).hexdigest(),
                      "files": {name: originals[name] for name, _ in selected},
                      "submitted_chars": sum(len(text) for _, text in selected),
                      "submitted_files": [name for name, _ in selected],
                      "trimmed_files": [name for name, text in selected if text != originals[name]]})
    if not cases:
        raise ValueError("No rubric selected source files")
    return {"version": 1, "suite": "pinned-repository", "revision": revision,
            "archive_sha256": hashlib.sha256(data).hexdigest(),
            "system_prompt": llm_scan.SYSTEM_PROMPT, "models": list(MODELS),
            "cases": cases, "repeats": 2, "results": [], "state": "prepared",
            "requested_max_tokens": llm_scan.RUBRIC_MAX_TOKENS,
            "candidate_files": len(files), "source_facts": source_facts,
            "input_character_limit": limit,
            "judgement": "Raw model responses and quote checks only; no production semantic filtering/dedup/scoring."}


def resume_results(expected: dict, previous: dict) -> dict:
    for field in ("revision", "archive_sha256", "system_prompt", "models", "cases",
                  "repeats", "requested_max_tokens", "source_facts", "input_character_limit"):
        if previous.get(field) != expected[field]:
            raise ValueError("Resume mismatch: " + field)
    hashes = {c["id"]: c["prompt_sha256"] for c in expected["cases"]}
    seen = set()
    for row in previous["results"]:
        key = (row["repeat"], row["case"], row["requested_model"])
        if (key in seen or row["repeat"] not in (1, 2) or row["case"] not in hashes
                or row["requested_model"] not in MODELS
                or row["prompt_sha256"] != hashes[row["case"]]):
            raise ValueError("Invalid saved attempt")
        seen.add(key)
    expected["results"] = previous["results"]
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--revision", required=True, help="Full immutable commit SHA")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be a full commit SHA")
    if args.output.exists() or args.output.with_suffix(args.output.suffix + ".partial").exists():
        parser.error("Use a NEW output path; previous results are preserved")
    sha = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse",
                                   args.revision + "^{commit}"], text=True).strip()
    if sha != args.revision:
        parser.error("Revision does not resolve to the requested commit")
    # No checkout, build, dependency installation or execution of scanned code.
    data = subprocess.check_output(["git", "-C", str(args.repo), "archive", "--format=zip", sha])
    report = prepare_archive(data, sha)
    report["scanner_revision"] = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if args.resume:
        try:
            report = resume_results(report, json.loads(args.resume.read_text()))
        except (ValueError, KeyError, TypeError):
            parser.error("Saved trial does not match snapshot, prompts, budget or model selection")
        report["resumed_from"] = str(args.resume)
    calls = len(report["cases"]) * 2 * len(MODELS) - len(report["results"])
    print(f"Snapshot {sha}: {report['candidate_files']} candidate files; {calls} remaining requests", flush=True)
    for case in report["cases"]:
        print(f"{case['id']}: {len(case['submitted_files'])} files, "
              f"{case['submitted_chars']} source characters, {len(case['trimmed_files'])} trimmed", flush=True)
    print(f"Requested output limit: {report['requested_max_tokens']} tokens per call", flush=True)
    if not args.run:
        save(args.output, report)
        print("Prepared only. No provider requests made.")
        return 0
    key = os.environ.get("AITUNNEL_API_KEY") or (
        read_values(args.env).get("AITUNNEL_API_KEY") if args.env else None)
    if not key:
        parser.error("AITUNNEL_API_KEY unavailable")
    return run(report, key, args.output, report["requested_max_tokens"], continue_invalid=True)


if __name__ == "__main__":
    raise SystemExit(main())
