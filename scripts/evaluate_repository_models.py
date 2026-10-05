#!/usr/bin/env python3
"""Compare Sonnet/MiMo on identical pinned repository prompts, without deploying.

Prepare-only by default. Raw responses are hypotheses, not production findings.
"""
from __future__ import annotations

import argparse
import ast
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


AUTH_FILES = (
    "app/accounts.py", "app/routes/session.py", "app/routes/accounts.py",
    "app/routes/_shared.py", "app/routes/dependencies.py", "app/ratelimit.py",
)
AUTH_EXCERPTS = {
    "app/main.py": {"lifespan", "configure_cors", "add_security_headers",
                    "new_request_id", "bind_request_context"},
    "app/db.py": {"DatabaseNotConfigured", "database_url_from_env", "get_pool",
                  "close_pool", "_row_to_account", "AccountRepository"},
}


def auth_excerpt(source: str, names: set[str]) -> str:
    """Omit unrelated definitions, retaining original line numbers and wiring."""
    lines = source.splitlines(keepends=True)
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name not in names:
            start = min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1
            lines[start:node.end_lineno] = ["\n"] * (node.end_lineno - start)
    return "".join(lines)


AUTH_MUTATIONS = (
    ("app/accounts.py",
     "    return await account_repo.get_by_key_hash(hash_api_key(api_key))",
     "    return await account_repo.get_by_key_hash(hash_api_key(api_key)) or await account_repo.get_by_id(api_key)"),
    ("app/routes/accounts.py",
     '    rotated = await account_repo.rotate_key(account["id"])',
     '    rotated = await account_repo.rotate_key(str((await _json_object_body(request))'
     '.get("account_id") or account["id"]))'),
)


def seed_auth_files(files: dict[str, str]) -> dict[str, str]:
    """Return an in-memory mutation; never write application sources."""
    mutated = dict(files)
    for name, before, after in AUTH_MUTATIONS:
        if mutated[name].count(before) != 1:
            raise ValueError("Mutation anchor missing or ambiguous: " + name)
        mutated[name] = mutated[name].replace(before, after, 1)
        ast.parse(mutated[name])
    return mutated


def prepare_auth(data: bytes, revision: str, *, seeded: bool = False) -> dict:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {name: archive.read(name).decode("utf-8") for name in (*AUTH_FILES, *AUTH_EXCERPTS)}
    if seeded:
        files = seed_auth_files(files)
    selected = [(name, auth_excerpt(text, AUTH_EXCERPTS[name]) if name in AUTH_EXCERPTS else text)
                for name, text in files.items()]
    context = ("\nScope: account API-key login/logout, account routes, cookie handling, "
               "dependencies, rate limiter, application middleware/router wiring and account storage. "
               "main.py and db.py are excerpts: unrelated top-level definitions are omitted as blank lines; "
               "original line numbers are retained. Other dependencies and deployment configuration are "
               "not supplied. Do not assume omitted guards are absent. Evaluate only this scope.")
    prompt = llm_scan.build_prompt(selected, "auth", context)
    limit = 180_000
    if len(prompt) + len(llm_scan.SYSTEM_PROMPT) > limit:
        raise ValueError("Small auth prompt exceeds 180000 characters; no request sent")
    case = {"id": "auth", "prompt": prompt,
            "prompt_sha256": hashlib.sha256((llm_scan.SYSTEM_PROMPT + "\0" + prompt).encode()).hexdigest(),
            "files": dict(selected), "submitted_chars": sum(len(t) for _, t in selected),
            "submitted_files": list(files), "trimmed_files": list(AUTH_EXCERPTS)}
    report = {"version": 1, "suite": "pinned-auth-seeded" if seeded else "pinned-auth-small", "revision": revision,
            "archive_sha256": hashlib.sha256(data).hexdigest(),
            "system_prompt": llm_scan.SYSTEM_PROMPT, "models": list(MODELS),
            "cases": [case], "repeats": 1, "results": [], "state": "prepared",
            "requested_max_tokens": 8192, "candidate_files": len(files),
            "source_facts": {}, "input_character_limit": limit,
            "read_timeout_seconds": 600,
            "judgement": "Partial source scope; raw hypotheses require manual review. No automatic retries."}
    if seeded:
        report["mutations"] = [{"file": name, "before": before, "after": after}
                               for name, before, after in AUTH_MUTATIONS]
        report["expected_findings"] = [
            "Existing account UUID accepted as API key via get_by_id fallback; requires configured pepper/database.",
            "Authenticated caller can rotate another known account UUID supplied in body and receive its new API key.",
        ]
    return report


def resume_results(expected: dict, previous: dict) -> dict:
    for field in ("revision", "archive_sha256", "system_prompt", "models", "cases",
                  "repeats", "requested_max_tokens", "source_facts", "input_character_limit"):
        if previous.get(field) != expected[field]:
            raise ValueError("Resume mismatch: " + field)
    hashes = {c["id"]: c["prompt_sha256"] for c in expected["cases"]}
    seen = set()
    for row in previous["results"]:
        key = (row["repeat"], row["case"], row["requested_model"])
        if (key in seen or row["repeat"] not in range(1, expected["repeats"] + 1) or row["case"] not in hashes
                or row["requested_model"] not in MODELS
                or row["prompt_sha256"] != hashes[row["case"]]):
            raise ValueError("Invalid saved attempt")
        seen.add(key)
    expected["results"] = previous["results"]
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("full", "auth-small", "auth-seeded"), default="full")
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
    report = (prepare_archive(data, sha) if args.scope == "full"
              else prepare_auth(data, sha, seeded=args.scope == "auth-seeded"))
    report["scanner_revision"] = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if args.resume:
        try:
            report = resume_results(report, json.loads(args.resume.read_text()))
        except (ValueError, KeyError, TypeError):
            parser.error("Saved trial does not match snapshot, prompts, budget or model selection")
        report["resumed_from"] = str(args.resume)
    calls = len(report["cases"]) * report["repeats"] * len(MODELS) - len(report["results"])
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
    return run(report, key, args.output, report["requested_max_tokens"], continue_invalid=True,
               read_timeout=report.get("read_timeout_seconds", 180))


if __name__ == "__main__":
    raise SystemExit(main())
