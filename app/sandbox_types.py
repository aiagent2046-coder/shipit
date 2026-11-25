"""Shared result contract for sandbox operations.

The local docker implementation (app.deploypack.sandbox) and the
out-of-process sandbox-runner client (app.sandbox_client) expose the SAME
return types; the type lives here, below both, so neither imports the
other's package. Moved during the import-cycles fix phase.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SandboxResult:
    ok: bool
    detail: str
    build_log: str = ""
    # Populated whenever a container actually started, success or not,
    # so a caller that wants to keep it alive (previews) can find it.
    container: str | None = None
    image_tag: str | None = None
