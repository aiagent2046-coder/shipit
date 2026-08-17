"""When the runtime CORS probe may run, and what to do with its answer (P2).

The probe itself lives in app/proof/cors_probe.py and executes on the runner.
This module decides whether to spend two container builds on a job at all,
and it is deliberately conservative: every condition below is a reason NOT to
boot, and the default is not to.

OFF BY DEFAULT (`PROOF_RUNTIME_CORS=0`). Not caution theatre — no customer
workspace has ever been booted by this code path. Every test behind it drives
injected doubles, because the environment it was written in has no docker.
Turning it on is an operator's decision, taken on a host where the first real
boot can be watched; see PROOF_RUNTIME_CORS_PLAN.md, P2.

WHAT A RUNTIME REPORT MAY NOT DO: replace the static one. If the scanner found
an open-CORS pattern and the booted app did not reproduce it, both reports go
in the PR. The code says one thing and the running app another, and that
disagreement is information the reader needs — not licence to publish the
quieter half. See `app/proof/stage.py`, which appends rather than substitutes.
"""

from __future__ import annotations

import io
import os
import zipfile

from app.proof.types import ProofReport

# Ports for probe containers. Distinct from app/deploypack/preview.py's
# PORT_RANGE (20000-30000) on purpose: a preview lives for hours and is
# tracked in a registry, a probe container lives for seconds and is torn down
# in a finally. Overlapping the two ranges would let a probe collide with a
# paying customer's live preview.
PROBE_PORT_RANGE = range(31000, 31500)


def runtime_cors_enabled() -> bool:
    """Default off. Anything other than an explicit on-value keeps it off."""
    raw = (os.environ.get("PROOF_RUNTIME_CORS") or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def runtime_cors_applicable(
    static_reports: list[ProofReport],
    original_zip: bytes,
) -> tuple[bool, str]:
    """Should this job get a runtime CORS probe? Returns (yes, reason).

    The reason is returned even when the answer is yes, so the log line and
    the skip detail come from one place rather than two.
    """
    if not runtime_cors_enabled():
        return False, "runtime probe disabled (PROOF_RUNTIME_CORS)"

    # The static scanner is the trigger, not an independent opinion. routing.py
    # only selects cors_open when its evidence file is in the plan's changed
    # set, so a static report existing already carries "the plan touches it".
    static = _static_cors_report(static_reports)
    if static is None:
        return False, "static cors_open did not run for this job"
    if not (static.before.success and static.before.status == "success"):
        return False, "static cors_open found nothing to reproduce"

    if not _has_root_dockerfile(original_zip):
        # Booting a repo through a Deploy Pack Dockerfile we generated would
        # conflate two questions: is the app's CORS open, and is our generated
        # Dockerfile right. When the answer is "the stand did not come up",
        # nobody can tell which. Only self-buildable repos qualify.
        return False, "workspace has no root Dockerfile — nothing to boot"

    return True, "static cors_open hit a file the plan changes; repo is buildable"


def _static_cors_report(reports: list[ProofReport]) -> ProofReport | None:
    for report in reports or []:
        if report.template_id == "cors_open":
            return report
    return None


def _has_root_dockerfile(zip_bytes: bytes) -> bool:
    """A Dockerfile at the archive root, tolerating the single-folder wrapper
    GitHub zips add (`repo-main/Dockerfile`)."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
    except Exception:  # noqa: BLE001 — an unreadable zip is simply not bootable
        return False

    for name in names:
        parts = name.replace("\\", "/").split("/")
        if parts and parts[-1] == "Dockerfile" and len(parts) <= 2:
            return True
    return False
