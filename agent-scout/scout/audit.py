"""Authorized deep audit (phase 3): the full drydock run, static + LLM,
behind a contract.

Passive scouting matches public manifests against the offline catalog. An
active audit runs the shipped engine end to end on the artifacts a contract
covers, and the discipline differences matter:

  - guard.require_active() is called FIRST, before any work - an expired or
    missing authorization refuses the audit outright;
  - the LLM stage runs on the deployment's providers (providers_from_env)
    and its outcome is reported exactly as it happened (stats, skipped
    reason, or "failed: ...") - a paid audit must never present a
    static-only run as a full one;
  - the SCA stage would send the target's dependency inventory to a third
    party (OSV). Looking at someone else's repository must send nothing by
    default: the inventory leaves only on an explicit opt-in.

Scope is enforced where it protects third-party data: DB connections check
the contract scope (guard/active). Artifact audits are gated by the
authorization record itself - the artifacts are what the contract brought.
"""
from __future__ import annotations

import io
import zipfile
from typing import Any

from scout import paths
from scout.guard import require_active


def archive_of(files: dict[str, bytes]) -> bytes:
    """Zip the artifact set the way run_scan wants it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def run_audit(contract_id: str, files: dict[str, bytes], *, target: str = "",
              osv: bool = False, llm_passes: int = 1,
              llm_cost_cap: Any = None) -> dict:
    """Full static+llm run for one contract. The gate runs before anything.

    Returns {"contract_id", "target", "engine_commit", "result"} where
    result is the shipped pipeline's own dict (score, findings, llm,
    llm_usage, sca) - unmodified, so its honesty contracts travel with it.
    """
    auth = require_active(contract_id)  # THE gate, before any work
    if not files:
        raise ValueError("no artifacts to audit")
    paths.bootstrap()
    try:
        from app.llm.client import LLMClient, providers_from_env
        from app.sca.stage import sca_client_for
        from app.scan.pipeline import run_scan
    except ImportError as exc:
        raise RuntimeError(
            "the active audit needs the pipeline dependencies; "
            "install them with: pip install -e '.[active]'") from exc

    llm_client = LLMClient(providers=providers_from_env())
    # requested=False is shipit's own CLI stance: an operator looking at
    # someone else's repository sends no inventory anywhere unless told to.
    sca_client = sca_client_for(paid=True, requested=bool(osv))
    extra = {} if llm_cost_cap is None else {"llm_cost_cap": llm_cost_cap}
    result = run_scan(archive_of(files), llm_client, llm_passes=llm_passes,
                      sca_client=sca_client, **extra)
    return {
        "contract_id": auth.contract_id,
        "target": target,
        "engine_commit": paths.engine_commit(),
        "result": result,
    }
