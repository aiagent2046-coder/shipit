"""Proof-of-Exploit → Proof-of-Fix.

For eligible findings, run the same exploit template against the original
workspace and the patched workspace, then record whether the attack
succeeded before and failed after.

MVP posture: informational only. Results are written to
``fixpack_jobs.proof_json`` and rendered into the PR body; they do not
block delivery. A later increment can flip the gate without changing the
data contract.

Templates live in ``app.proof.templates``. Only ``secrets_leak`` is
implemented; ``sqli`` and ``cors_open`` are registered stubs that return
skipped attempts so the registry shape is stable from day one.
"""

from app.proof.compare import build_proof_report, run_proof_pair
from app.proof.registry import TEMPLATE_IDS, get_template, list_templates
from app.proof.render import render_proof_markdown
from app.proof.types import ExploitAttempt, ProofReport, proof_report_to_json

__all__ = [
    "TEMPLATE_IDS",
    "ExploitAttempt",
    "ProofReport",
    "build_proof_report",
    "get_template",
    "list_templates",
    "proof_report_to_json",
    "render_proof_markdown",
    "run_proof_pair",
]
