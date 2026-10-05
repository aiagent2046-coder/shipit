#!/usr/bin/env python3
"""Private, isolated repository trial; dry-run unless --execute is explicit.

Admission reserves use UTF-8 bytes + 1024 as an assumed token upper bound,
25/100 RUB per million input/output tokens, doubled input / 1.5x output above
272K input tokens (pilot rates checked 2026-10-05). This is an intentionally
conservative planning assumption, NOT a provider-enforced billing cap.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import signal
import tempfile
import time

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.llm.client import LLMClient, LLMError, LLMUsage, Provider  # noqa: E402
from app.ingest.validators import MAX_ARCHIVE_BYTES, validate_zip  # noqa: E402
from app.scan.llm_scan import parse_response  # noqa: E402
from app.scan.pipeline import AUDIT_ENGINE_VERSION as PIPELINE_ENGINE_VERSION  # noqa: E402
from app.scan.pipeline import content_digest, run_scan  # noqa: E402
from app.scan.version import AUDIT_ENGINE_VERSION  # noqa: E402
from scripts.env_file import read_values  # noqa: E402

MODEL = "gpt-6-luna"
ENDPOINT = "https://api.aitunnel.ru/v1"
OUTPUT_TOKENS = 8192
MAX_CALLS = 16


def checkpoint(path: Path, result: dict) -> None:
    """Atomic private checkpoints, including a durable pre-request marker."""
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def reservation(system: str, user: str) -> Decimal:
    tokens = len(system.encode()) + len(user.encode()) + 1024
    inp, out = (Decimal(50), Decimal(150)) if tokens > 272000 else (Decimal(25), Decimal(100))
    return (tokens * inp + OUTPUT_TOKENS * out) / Decimal(1000000)


def engine_identity() -> str:
    identity = {"policy": "luna-medium-v1", "providers": [["openai_compat", MODEL]]}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
    return f"{AUDIT_ENGINE_VERSION}-luna-{digest}"


class TrialClient(LLMClient):
    def __init__(self, key, result, output, budget, deadline, *, transport=None):
        super().__init__([Provider("openai_compat", ENDPOINT, key, MODEL)], transport)
        self.result, self.output, self.budget, self.deadline = result, output, budget, deadline
        self.stopped = None
        self.current = None

    def stop(self, reason, attempts=()):
        self.stopped = reason
        self.result["state"] = reason
        checkpoint(self.output, self.result)
        raise LLMError(reason, attempts=tuple(attempts))

    def _request(self, p, system, user, max_tokens):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise httpx.ReadTimeout("trial_deadline")
        with httpx.Client(timeout=httpx.Timeout(min(180, remaining), connect=min(10, remaining)),
                          transport=self._transport) as client:
            response = client.post(f"{ENDPOINT}/chat/completions",
                                   headers={"Authorization": f"Bearer {p.api_key}"},
                                   json=self._payload_openai(p, system, user, max_tokens))
            response.raise_for_status()
            data = response.json()
        # Save only answer content; provider error bodies and headers are excluded.
        if isinstance(data, dict):
            choices = data.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                message = choices[0].get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    self.current["answer"] = message["content"]
        return data

    def complete(self, system, user, max_tokens=4096):
        if self.stopped:
            raise LLMError(self.stopped)
        if time.monotonic() >= self.deadline:
            self.stop("stopped_time_limit")
        if len(self.result["requests"]) >= MAX_CALLS:
            self.stop("stopped_call_limit")
        if max_tokens != OUTPUT_TOKENS or len(system) + len(user) > self.input_char_budget():
            self.stop("stopped_unexpected_prompt_or_output_limit")
        reserve = reservation(system, user)
        if Decimal(self.result["known_spend_rub"]) + reserve > self.budget:
            self.result["next_reservation_rub"] = str(reserve)
            self.stop("stopped_admission_budget")
        prompt = {"system": system, "user": user}
        record = {"request": len(self.result["requests"]) + 1, "state": "in_flight",
                  "prompts": prompt, "prompt_sha256": hashlib.sha256(
                      json.dumps(prompt, ensure_ascii=False, sort_keys=True).encode()).hexdigest(),
                  "prompt_utf8_bytes": len(system.encode()) + len(user.encode()),
                  "reservation_rub": str(reserve), "attempts": [], "answer": None}
        self.current = record
        self.result["requests"].append(record)
        self.result["state"] = "running_request_in_flight_charge_unknown"
        checkpoint(self.output, self.result)
        failure = None
        try:
            # Intentionally bypass complete(): one production _call, no retry/fallback.
            answer, usage = self._call(self.providers[0], system, user, OUTPUT_TOKENS)
            record["answer"] = answer
            attempts = list(usage.attempts)
            if parse_response(answer) is None:
                failure = "stopped_invalid_answer"
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            attempts = list(getattr(exc, "attempts", ()))
            failure = "stopped_provider_error"
            record["error_type"] = type(exc).__name__
        record["attempts"] = attempts
        if not attempts:
            attempts.append({"cost_rub": None, "error": "missing_attempt_metadata"})
        known = Decimal(self.result["known_spend_rub"])
        for attempt in attempts:
            cost = attempt.get("cost_rub")
            if cost is None:
                self.result["unknown_charge_count"] += 1
                failure = failure or "stopped_unknown_charge"
            else:
                known += Decimal(cost)
        self.result["known_spend_rub"] = str(known)
        if known > self.budget:
            failure = failure or "stopped_reported_cost_exceeds_budget"
        if time.monotonic() >= self.deadline:
            failure = failure or "stopped_time_limit"
        record["state"] = failure or "completed"
        self.result["state"] = failure or "running"
        checkpoint(self.output, self.result)
        print(json.dumps({"request": record["request"], "model": MODEL,
                          "cost_rub": attempts[-1].get("cost_rub"),
                          "seconds": attempts[-1].get("seconds"),
                          "finish_reason": attempts[-1].get("finish_reason"),
                          "error": failure}), flush=True)
        if failure:
            self.stop(failure, attempts)
        return answer, usage


class TrialDeadline(BaseException):
    """Escape scanner degradation handlers when the absolute deadline expires."""


def deadline_handler(signum, frame):
    raise TrialDeadline()


class PlanningClient(LLMClient):
    """Synthetic [] responses only: never a quality result or a billable call."""
    def __init__(self):
        super().__init__([Provider("openai_compat", ENDPOINT, "", MODEL)])
        self.prompts = []

    def complete(self, system, user, max_tokens=4096):
        if max_tokens != OUTPUT_TOKENS or len(system) + len(user) > self.input_char_budget():
            raise LLMError("unexpected_prompt_or_output_limit")
        self.prompts.append({"request": len(self.prompts) + 1,
                             "prompt_utf8_bytes": len(system.encode()) + len(user.encode()),
                             "reservation_rub": str(reservation(system, user))})
        return "[]", LLMUsage(MODEL, (len(system) + len(user) + 2) // 3, 1)


def positive_decimal(value):
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("expected a positive finite amount") from None
    if not number.is_finite() or number <= 0:
        raise argparse.ArgumentTypeError("expected a positive finite amount")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path("/opt/shipit/.env"))
    parser.add_argument("--budget-rub", type=positive_decimal, default=Decimal(50))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-content-hash")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo) or not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("--repo must be owner/repo and --revision a full lowercase commit SHA")
    if args.archive.stat().st_size > MAX_ARCHIVE_BYTES:
        parser.error("archive exceeds production compressed-size limit")
    data = args.archive.read_bytes()
    validate_zip(io.BytesIO(data), size_bytes=len(data))
    digest = content_digest(data)
    if args.expected_content_hash and args.expected_content_hash != digest:
        parser.error("archive content hash does not match the saved comparison baseline")
    result = {"schema_version": 1, "state": "prepared_no_paid_calls", "repo": args.repo,
              "revision": args.revision, "content_hash": digest, "archive_sha256": hashlib.sha256(data).hexdigest(),
              "engine_version": PIPELINE_ENGINE_VERSION, "model_policy_identity": engine_identity(),
              "model": MODEL, "passes": 2,
              "reasoning_effort": "medium", "max_completion_tokens": OUTPUT_TOKENS,
              "max_calls": MAX_CALLS, "runtime_limit_seconds": 1200,
              "budget_rub": str(args.budget_rub), "known_spend_rub": "0",
              "unknown_charge_count": 0, "requests": [], "scan": None,
              "admission_assumption": ("UTF8 bytes + 1024 tokens; 25/100 RUB per million; "
                                       "above 272K input: 2x/1.5x. Not a provider hard cap."),
              "scope": ("Production full scan with two LLM passes; no DB, remote OSV or synthetic SQL executor. "
                        "Source identity is operator-supplied; inspect coverage and findings.")}
    # Exclusive initial creation prevents rerunning into an existing result.
    fd = os.open(args.json, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    checkpoint(args.json, result)
    if not args.execute:
        planner = PlanningClient()
        planned = run_scan(data, planner, llm_passes=2, sca_client=None,
                           synthetic_sql_executor=None, llm_cost_cap=Decimal("13"))
        result["dry_run"] = {"synthetic_empty_answers_only": True, "prompts": planner.prompts,
                             "llm_plan": planned.get("llm"),
                             "maximum_request_reservation_rub": str(max(
                                 (Decimal(p["reservation_rub"]) for p in planner.prompts), default=Decimal(0))),
                             "sum_reservations_rub": str(sum(
                                 (Decimal(p["reservation_rub"]) for p in planner.prompts), Decimal(0)))}
        if not isinstance(planned.get("llm"), dict) or planned["llm"].get("failure"):
            result["state"] = "stopped_dry_run_planning_error"
        checkpoint(args.json, result)
        print(f"Prepared {len(planner.prompts)} requests; no env file read or model requests sent.")
        print(f"Largest request reservation RUB: {result['dry_run']['maximum_request_reservation_rub']}")
        print(f"Plan: {args.json}")
        return 0 if result["state"] == "prepared_no_paid_calls" else 1
    key = os.environ.get("AITUNNEL_API_KEY") or read_values(args.env_file).get("AITUNNEL_API_KEY")
    if not key:
        result["state"] = "stopped_missing_key"
        checkpoint(args.json, result)
        print("AITUNNEL_API_KEY is missing")
        return 1
    started = time.monotonic()
    client = TrialClient(key, result, args.json, args.budget_rub, started + 1200)
    old_handler = signal.signal(signal.SIGALRM, deadline_handler)
    old_timer = signal.setitimer(signal.ITIMER_REAL, 1200)
    try:
        result["scan"] = run_scan(data, client, llm_passes=2, sca_client=None,
                                  synthetic_sql_executor=None, llm_cost_cap=Decimal("13"))
        llm = result["scan"].get("llm")
        incomplete = not isinstance(llm, dict) or any(llm.get(k) for k in (
            "failure", "skipped_reason", "cost_cap_exceeded", "invalid_responses", "input_truncated"))
        result["state"] = client.stopped or (
            "completed_incomplete_needs_review" if incomplete else "completed_needs_review")
    except TrialDeadline:
        result["state"] = "stopped_on_timeout"
    except KeyboardInterrupt:
        result["state"] = "interrupted_charge_may_be_unknown"
    except Exception as exc:  # Do not serialize exception text or provider bodies.
        result["state"] = "stopped_scan_error"
        result["error_type"] = type(exc).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        if old_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, old_timer[0] - (time.monotonic() - started)), old_timer[1])
        if result["requests"] and result["requests"][-1]["state"] == "in_flight":
            result["unknown_charge_count"] += 1
            result["requests"][-1]["state"] = "interrupted_charge_unknown"
        result["seconds"] = round(time.monotonic() - started, 3)
        if result["seconds"] >= 1200 and result["state"] == "completed_needs_review":
            result["state"] = "stopped_time_limit"
        checkpoint(args.json, result)
    print(f"State: {result['state']}")
    print(f"Known spend RUB: {result['known_spend_rub']}; unknown charges: {result['unknown_charge_count']}")
    print(f"Result: {args.json}")
    return 0 if result["state"] == "completed_needs_review" else 1


if __name__ == "__main__":
    raise SystemExit(main())
