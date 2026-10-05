#!/usr/bin/env python3
"""Small, manually judged model trial. Default: prepare only, no API calls.

Uses production prompts/payloads/quote checks, but bypasses retries and fallback.
This is a fixture trial, not a full scan or a claim of measured accuracy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.llm.client import LLMClient, Provider  # noqa: E402
from app.scan.llm_scan import SYSTEM_PROMPT, build_prompt, rejection_reason  # noqa: E402
from scripts.env_file import read_values  # noqa: E402

MODELS = ("claude-sonnet-4.6", "deepseek-v4-pro-0813", "minimax-m3")
AVAILABLE_MODELS = MODELS + ("mimo-v2.6-pro", "glm-5.3")
CASES = (
    ("sql-risk", "sql-injection-string-built-query/positive/concatenated-query", "app/queries.py",
     "SQL construction is unsafe if arguments are attacker-controlled; caller provenance is absent."),
    ("sql-control", "sql-injection-string-built-query/negative/parameterised-query", "app/queries.py",
     "Bound value and constant column interpolation do not establish SQL injection."),
    ("shell-risk", "command-injection-shell-built-command/positive/shell-c-keyword", "app/command.py",
     "Request name becomes bash -c program text: command injection."),
    ("shell-control", "command-injection-shell-built-command/negative/shell-c-positional-data", "app/command.py",
     "Name is a quoted positional argument to a fixed program, not shell program text."),
    ("yaml-risk", "unsafe-deserialization/positive/unsafe-yaml-safe-named-alias", "app/restore.py",
     "UnsafeLoader is aliased SafeLoader; object construction risk requires untrusted data."),
    ("yaml-control", "unsafe-deserialization/negative/safe-yaml-import-alias", "app/restore.py",
     "The imported loader is SafeLoader; its alias SL does not make it unsafe."),
)


def prepare(suite: str = "baseline", repeats: int = 1, models: tuple[str, ...] = MODELS) -> dict:
    if not models or len(set(models)) != len(models) or any(m not in AVAILABLE_MODELS for m in models):
        raise ValueError("Unknown, empty or duplicate model selection")
    rows = []
    for case_id, fixture, name, expectation in CASES:
        source = (ROOT / "tests/detectors" / fixture / (name + ".fixture")).read_text()
        prompt = build_prompt([(name, source)], "security")
        rows.append({"id": case_id, "files": {name: source}, "prompt": prompt,
                     "prompt_sha256": hashlib.sha256((SYSTEM_PROMPT + "\0" + prompt).encode()).hexdigest(),
                     "review_expectation": expectation})
    if suite == "context":
        for original in list(rows):
            if not original["id"].startswith(("sql-", "yaml-")):
                continue
            files = dict(original["files"])
            if original["id"].startswith("sql-"):
                caller = (
                    "from fastapi import APIRouter\n"
                    "import psycopg\n"
                    "import os\n"
                    "from app.queries import find_user\n\n"
                    "router = APIRouter()\n\n"
                    "@router.get('/user')\n"
                    "def user(user_id: str):\n"
                    "    with psycopg.connect(os.environ['DATABASE_URL']) as conn:\n"
                    "        return find_user(conn, user_id)\n"
                )
            else:
                caller = (
                    "from fastapi import APIRouter, Body\n"
                    "from app.restore import restore\n\n"
                    "router = APIRouter()\n\n"
                    "@router.post('/restore')\n"
                    "def import_data(data: str = Body(media_type='text/plain')):\n"
                    "    return restore(data)\n"
                )
            files["app/routes.py"] = caller
            prompt = build_prompt(list(files.items()), "security")
            rows.append({"id": original["id"] + "-http", "files": files, "prompt": prompt,
                         "prompt_sha256": hashlib.sha256((SYSTEM_PROMPT + "\0" + prompt).encode()).hexdigest(),
                         "review_expectation": original["review_expectation"] +
                         " HTTP caller supplies user_id/data; deployed reachability is still not established.",
                         "paired_case": original["id"]})
    return {"version": 2, "suite": suite, "repeats": repeats, "system_prompt": SYSTEM_PROMPT, "models": list(models),
            "cases": rows, "results": [], "state": "prepared",
            "judgement": "Manual review required. Valid quotes are not proof of a true finding."}


def assess(raw: str, files: dict) -> dict:
    try:
        parsed = json.loads(raw)
    except (ValueError, RecursionError):
        return {"strict_json_array": False, "quote_checks": None}
    if not isinstance(parsed, list):
        return {"strict_json_array": False, "quote_checks": None}
    return {"strict_json_array": True,
            "quote_checks": [rejection_reason(finding, files) for finding in parsed]}


def save(path: Path, report: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def run(report: dict, key: str, output: Path, max_tokens: int,
        transport: httpx.BaseTransport | None = None, *, continue_invalid: bool = False,
        read_timeout: float = 180) -> int:
    # Fixed endpoint: credentials cannot be redirected by model output/configuration.
    report["state"] = "running"
    report["requested_max_tokens"] = max_tokens
    save(output, report)
    timeout = httpx.Timeout(read_timeout, connect=30)
    with httpx.Client(timeout=timeout, transport=transport, follow_redirects=False) as client:
        jobs = [(repeat, case, model)
                for repeat in range(1, report.get("repeats", 1) + 1)
                for case in report["cases"]
                for model in (report["models"][(repeat - 1) % len(report["models"]):]
                              + report["models"][:(repeat - 1) % len(report["models"])])]
        attempted = {(r["repeat"], r["case"], r["requested_model"]) for r in report["results"]}
        for repeat, case, model in jobs:
            if (repeat, case["id"], model) in attempted:
                continue
            provider = Provider("openai_compat", "https://api.aitunnel.ru/v1", key, model)
            payload = LLMClient._payload_openai(provider, report["system_prompt"],
                                                case["prompt"], max_tokens)
            row = {"repeat": repeat, "case": case["id"], "requested_model": model,
                   "prompt_sha256": case["prompt_sha256"], "manual_verdict": None}
            started = time.monotonic()
            try:
                response = client.post(provider.base_url + "/chat/completions",
                                       headers={"Authorization": "Bearer " + key}, json=payload)
                response.raise_for_status()
                data = response.json()
                # Save usage before parsing the answer: malformed/empty output may be billed.
                row["usage"] = data.get("usage")
                usage = data.get("usage") or {}
                row["cost_rub"] = usage.get("cost_rub")
                if row["cost_rub"] is None:
                    row["cost_rub"] = data.get("cost_rub")
                row["served_model"] = data.get("model")
                choice = data["choices"][0]
                row["finish_reason"] = choice.get("finish_reason")
                raw = choice["message"].get("content")
                row["answer"] = raw
                row.update(assess(raw, case["files"]) if isinstance(raw, str)
                           else {"strict_json_array": False, "quote_checks": None})
                if row["finish_reason"] != "stop" or not row["strict_json_array"]:
                    row["error"] = "incomplete_or_invalid_answer"
            except Exception as exc:
                # Do not save exception text/response bodies: they can echo credentials.
                row["error"] = type(exc).__name__
                if isinstance(exc, httpx.HTTPStatusError):
                    row["http_status"] = exc.response.status_code
            row["seconds"] = round(time.monotonic() - started, 3)
            report["results"].append(row)
            save(output, report)
            print(f"{len(report['results'])}/{len(jobs)} {case['id']} {model}: "
                  f"{row.get('error', 'saved')}", flush=True)
            if "error" in row and not (continue_invalid and row["error"] == "incomplete_or_invalid_answer"):
                report["state"] = "stopped_on_error"
                save(output, report)
                return 1
    report["state"] = ("completed_with_errors_needs_review" if any("error" in r for r in report["results"])
                       else "completed_needs_review")
    save(output, report)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", type=Path,
                        help="Continue saved trial into a NEW output; never retry saved attempts")
    parser.add_argument("--continue-invalid", action="store_true",
                        help="Record invalid answers and continue; HTTP/network errors still stop")
    parser.add_argument("--run", action="store_true", help="Execute the prepared suite (billable API calls)")
    parser.add_argument("--models", nargs="+", choices=AVAILABLE_MODELS,
                        help="Models in trial order; default preserves original comparison")
    parser.add_argument("--suite", choices=("baseline", "context"), default="baseline")
    parser.add_argument("--repeats", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--env", type=Path, help="Read AITUNNEL_API_KEY only; never shell-source this file")
    parser.add_argument("--max-tokens", type=int, default=4096,
                        help="Requested output limit, not a guaranteed spending cap")
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.with_suffix(args.output.suffix + ".partial").exists():
        parser.error("Output already exists; use a new filename to preserve previous results")
    if not 1 <= args.max_tokens <= 16384:
        parser.error("max-tokens must be between 1 and 16384")
    if args.models and len(set(args.models)) != len(args.models):
        parser.error("Duplicate models are not allowed")
    report = prepare(args.suite, args.repeats, tuple(args.models or MODELS))
    if args.resume:
        report = json.loads(args.resume.read_text())
        if args.models is not None and args.models != report["models"]:
            parser.error("Resume must preserve model selection and order")
        expected = prepare(report["suite"], report["repeats"], tuple(report["models"]))
        for field in ("system_prompt", "models", "cases"):
            if report[field] != expected[field]:
                parser.error("Saved trial does not match current prompts/cases/models")
        if report.get("requested_max_tokens") != args.max_tokens:
            parser.error("Resume must preserve requested_max_tokens")
        known = {c["id"]: c["prompt_sha256"] for c in report["cases"]}
        seen = set()
        for row in report["results"]:
            identity = (row["repeat"], row["case"], row["requested_model"])
            if (identity in seen or row["case"] not in known
                    or row["prompt_sha256"] != known[row["case"]]
                    or row["requested_model"] not in report["models"]
                    or row["repeat"] not in range(1, report["repeats"] + 1)):
                parser.error("Invalid or duplicate saved attempt")
            seen.add(identity)
        report["resumed_from"] = str(args.resume)
    report["continue_invalid"] = args.continue_invalid
    if not args.run:
        save(args.output, report)
        remaining = len(report["cases"]) * len(report["models"]) * report["repeats"] - len(report["results"])
        print(f"Prepared {remaining} remaining calls. No API requests made.")
        return 0
    key = os.environ.get("AITUNNEL_API_KEY")
    if not key and args.env:
        key = read_values(args.env).get("AITUNNEL_API_KEY")
    if not key:
        parser.error("AITUNNEL_API_KEY is required for --run")
    return run(report, key, args.output, args.max_tokens, continue_invalid=args.continue_invalid)


if __name__ == "__main__":
    raise SystemExit(main())
