"""Combined static + LLM scan pipeline, shared by the API and the CLI.

Static scan always runs. The LLM auth/security stage runs only when the
client has configured providers, and degrades to static-only findings
instead of raising if the provider chain fails at request time — the
caller can still see what happened via the `llm` field ("failed: ...").
"""

from __future__ import annotations

import io

from app.llm.client import LLMClient, LLMError
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.static import run_static_scan


def run_scan(data: bytes, llm_client: LLMClient) -> dict:
    """Returns {"score": {...}, "findings": [...], "llm": <stats | status>}.

    `llm` is a stats dict when the stage ran, or one of two honest
    strings: "skipped (no providers configured)" / "failed: <reason>".
    """
    static = run_static_scan(io.BytesIO(data))
    findings = static["findings"]
    llm_summary: object = "skipped (no providers configured)"

    if llm_client.providers:
        try:
            llm_findings, stats = run_llm_scan(io.BytesIO(data), llm_client)
        except LLMError as exc:
            llm_summary = f"failed: {exc}"
        else:
            findings = findings + [vars(f) for f in llm_findings]
            llm_summary = vars(stats)

    return {
        "score": {
            **compute_scores([ScoredFinding(**f) for f in findings]),
            # An audit whose LLM stage was skipped or failed must not
            # look like a clean bill of health: a repo that scored 0.0
            # with the LLM stage present scored 9.2 without it (seen in
            # a real batch run when the provider returned 402 mid-run).
            # The basis travels inside score_json so it persists to the
            # DB and reaches every consumer of the score, not just ones
            # that also read `llm`.
            "basis": "static+llm" if isinstance(llm_summary, dict) else "static_only",
        },
        "findings": findings,
        "llm": llm_summary,
    }
