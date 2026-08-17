"""Proof-of-Exploit → Proof-of-Fix.

For eligible findings, run the same exploit template against the original
workspace and the patched workspace, then record whether the attack
succeeded before and failed after.

Delivery gate is controlled by ``PROOF_GATE_MODE`` (see ``app.proof.gate``):

* ``off``  — informational only (record + PR section, never blocks)
* ``soft`` — default; still delivers, but surfaces a strong warning when
  the exploit still succeeds after the proposed fix
* ``hard`` — non-verified reproducible exploit becomes ``blocked``
  (same shape as a semantic-check regression)

Templates live in ``app.proof.templates``. Only ``secrets_leak`` is
implemented; ``sqli`` and ``cors_open`` are registered stubs that return
skipped attempts so the registry shape is stable from day one.
"""

from app.proof.compare import build_proof_report, run_proof_pair
from app.proof.gate import decide_proof_gate, proof_gate_mode
from app.proof.workspace import apply_plan_to_zip
from app.proof.stage import run_proof_stage
from app.proof.registry import TEMPLATE_IDS, get_template, list_templates
from app.proof.render import render_proof_markdown
from app.proof.types import ExploitAttempt, ProofReport, proof_report_to_json

__all__ = [
    "TEMPLATE_IDS",
    "ExploitAttempt",
    "ProofReport",
    "build_proof_report",
    "decide_proof_gate",
    "get_template",
    "list_templates",
    "proof_gate_mode",
    "proof_report_to_json",
    "render_proof_markdown",
    "run_proof_pair",
    "apply_plan_to_zip",
    "run_proof_stage",
]
