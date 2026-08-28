"""Proof-of-Exploit → Proof-of-Fix.

For eligible findings, run the same exploit template against the original
workspace and the patched workspace, then record whether the attack
succeeded before and failed after.

Delivery gate is controlled by ``PROOF_GATE_MODE`` (see ``app.proof.gate``):

* ``off``  — informational only (record + PR section, never blocks)
* ``soft`` — still delivers, but surfaces a strong warning when the exploit
  still succeeds after the proposed fix
* ``hard`` — default; a non-verified reproducible exploit becomes ``blocked``
  (same shape as a semantic-check regression)

The default blocks one state only: reproduced before, same check after, still
succeeding. "We could not prove anything" is a different state and still
delivers — see ``app.proof.gate`` for why that line is drawn there.

Templates live in ``app.proof.templates``. Stage routing (``app.proof.routing``)
picks which templates to run based on the Fix Pack plan and whether
findings sit in files the plan rewrites.
"""

from app.proof.compare import build_proof_report, run_proof_pair
from app.proof.gate import decide_proof_gate, proof_gate_mode
from app.proof.registry import TEMPLATE_IDS, get_template, list_templates
from app.proof.render import (
    render_proof_markdown,
    render_proof_sections,
    render_proof_with_artifacts,
)
from app.proof.stage import ProofStageResult, run_proof_stage
from app.proof.types import ExploitAttempt, ProofReport, proof_report_to_json
from app.proof.workspace import apply_plan_to_zip

__all__ = [
    "TEMPLATE_IDS",
    "ExploitAttempt",
    "ProofReport",
    "ProofStageResult",
    "build_proof_report",
    "decide_proof_gate",
    "get_template",
    "list_templates",
    "proof_gate_mode",
    "proof_report_to_json",
    "render_proof_markdown",
    "render_proof_sections",
    "render_proof_with_artifacts",
    "run_proof_pair",
    "apply_plan_to_zip",
    "run_proof_stage",
]
