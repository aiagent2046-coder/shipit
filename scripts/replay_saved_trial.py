"""Replay a saved full-model trial through run_scan, with networking blocked.

Run with PYTHONPATH pointing to the checkout being measured. Both archive SHA
and every reconstructed prompt must match before accepting a saved response.
The output's scan token/cost estimates describe reused responses, not new spend.
No credentials, environment file, provider client or OSV client are loaded.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.scan.llm_scan import RUBRICS
from app.scan.pipeline import run_scan
from app.scan.version import AUDIT_ENGINE_VERSION


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


class ReplayMismatch(ValueError):
    """A mismatch must escape the product's provider-failure fallback."""


class SavedClient(LLMClient):
    def __init__(self, record: dict):
        super().__init__([Provider("openai_compat", "https://offline.invalid", "offline", record["model"])])
        self.record = record
        self.consumed = 0
        self.prompt_checks: list[dict] = []

    def input_char_budget(self) -> int:
        return self.record["effective_input_char_budget"]

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> tuple[str, LLMUsage]:
        if self.consumed >= len(self.record["calls"]):
            raise ReplayMismatch("Pipeline requested an unsaved response")
        call = self.record["calls"][self.consumed]
        req = call["request"]
        expected_max = call.get("request_changes", {}).get("max_tokens", {}).get("from", req["max_tokens"])
        messages_hash = canonical_sha256([
            {"role": "system", "content": system}, {"role": "user", "content": user},
        ])
        if (messages_hash != req["messages_sha256"] or max_tokens != expected_max
                or RUBRICS[req["rubric"]]["instructions"] not in user):
            raise ReplayMismatch(f"Saved request mismatch at slot {call['slot']}")
        response = call["response"]
        if response["http_status"] != 200 or response["reported_model"] != self.record["model"]:
            raise ReplayMismatch("Unsupported saved response status/model")
        self.consumed += 1
        self.prompt_checks.append({
            "slot": call["slot"], "rubric": req["rubric"], "pass": req["pass"],
            "messages_sha256": messages_hash, "matches_saved_request": True,
            "product_max_tokens": max_tokens, "saved_effective_max_tokens": req["max_tokens"],
        })
        answer = response.get("answer_text")
        if call.get("response_issue"):
            saved_llm = self.record.get("scan", {}).get("llm")
            saved_failure = saved_llm.get("failure") if isinstance(saved_llm, dict) else None
            # The original operator harness may wrap the underlying issue.
            # Keep its product failure and the underlying issue separately.
            raise LLMError(saved_failure or call["response_issue"])
        if not isinstance(answer, str) or not answer.strip() or response["finish_reason"] != "stop":
            raise ReplayMismatch("Unsupported saved completion without a recorded failure")
        usage = response["numeric_usage_details"]
        return answer, LLMUsage(response["reported_model"], usage["prompt_tokens"], usage["completion_tokens"])


def replay(report: dict, archive: bytes) -> dict:
    archive_hash = hashlib.sha256(archive).hexdigest()
    if archive_hash != report["input"]["archive_sha256"]:
        raise ReplayMismatch("Archive SHA does not match saved trial")
    network_attempts: list[str] = []

    def no_network(*_args, **_kwargs):
        network_attempts.append("blocked")
        raise ReplayMismatch("Networking is forbidden during saved-response replay")

    models = []
    with ExitStack() as stack:
        for name in ("socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection",
                     "httpx.Client.send", "httpx.AsyncClient.send"):
            stack.enter_context(patch(name, no_network))
        for record in report["models"]:
            client = SavedClient(record)
            scan = run_scan(
                archive, client, llm_passes=report["passes"], llm_rubrics=tuple(report["rubrics"]),
                # Consume the saved run; estimates are historical and never a
                # spending authorization. There is no provider transport.
                llm_cost_cap=Decimal("1000000"), sca_client=None,
            )
            if client.consumed != len(record["calls"]):
                raise ReplayMismatch("Pipeline did not consume every saved response")
            if network_attempts:
                raise ReplayMismatch("A product path attempted networking")
            response_issues = [c["response_issue"] for c in record["calls"] if c.get("response_issue")]
            actual_failure = scan["llm"].get("failure") if isinstance(scan["llm"], dict) else scan["llm"]
            saved_llm = record.get("scan", {}).get("llm")
            saved_failure = saved_llm.get("failure") if isinstance(saved_llm, dict) else saved_llm
            if response_issues and not actual_failure:
                raise ReplayMismatch("A saved failed response became a successful scan")
            if saved_llm is not None and saved_failure != actual_failure:
                raise ReplayMismatch("Saved and replayed product failure states differ")
            saved_basis = record.get("scan", {}).get("score", {}).get("basis")
            if saved_basis is not None and scan["score"].get("basis") != saved_basis:
                raise ReplayMismatch("Saved and replayed scan completeness differ")
            findings = [f for f in scan["findings"] if f.get("source") == "llm"]
            models.append({
                "model": record["model"], "reused_responses": client.consumed,
                "saved_state": record.get("state"), "saved_stop_reason": record.get("stop_reason"),
                "saved_product_failure": saved_failure, "saved_response_issues": response_issues,
                "saved_basis": saved_basis,
                "prompt_checks": client.prompt_checks,
                "saved_findings": len(findings),
                "projected_findings": [f["title"] for f in findings
                                       if f.get("claim_evidence", {}).get("narrative_projection")],
                "query_groups": [f["title"] for f in findings if f.get("claim_evidence", {})
                                 .get("grouped_claim_scope", {}).get("mechanism") == "query_read_volume"],
                "scan": scan,
            })
    return {
        "mode": "saved_responses_only", "engine_version": AUDIT_ENGINE_VERSION,
        "saved_trial_state": report.get("state"),
        "saved_full_comparison_complete": report.get("full_comparison_complete"),
        "archive_sha256": archive_hash, "new_network_attempts": 0, "new_cost_rub": "0",
        "cost_semantics": "All token counts and scan cost estimates belong to reused historical responses.",
        "models": models,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("output already exists; choose a new path")
    raw_report = args.report.read_bytes()
    result = replay(json.loads(raw_report), args.archive.read_bytes())
    result["saved_report_sha256"] = hashlib.sha256(raw_report).hexdigest()
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, ensure_ascii=False, indent=2, default=str)
        out.write("\n")
    print(json.dumps({
        "new_network_attempts": result["new_network_attempts"],
        "new_cost_rub": result["new_cost_rub"],
        "models": [{k: v for k, v in m.items() if k not in {"scan", "prompt_checks"}} for m in result["models"]],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
