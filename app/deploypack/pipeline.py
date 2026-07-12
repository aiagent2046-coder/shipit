"""Deploy Pack pipeline: generate + verify, wired for the API.

Writes the real repo bytes plus the generated files to a temp dir, runs
the sandbox check against it, and always cleans the dir up regardless
of outcome.
"""

from __future__ import annotations

import io
import shutil
import tempfile
from pathlib import Path

from app.deploypack.generate import extract_repo, generate_deploy_pack, read_all_files
from app.deploypack.sandbox import verify_deploy_pack
from app.ingest.stack_detect import Stack

# (host_port, container_port) — matches what generate.py puts in the
# Pack's own docker-compose.yml for each stack.
_PORTS: dict[Stack, tuple[int, int]] = {
    Stack.FASTAPI: (8000, 8000),
    Stack.VITE_REACT: (8080, 80),
}


def run_deploy_pack(raw: bytes, stack: Stack) -> dict:
    """Generate the Pack, verify it in a real sandbox, clean up.

    Returns {"files": {path: content}, "verified": bool | None,
    "detail": str, "build_log": str}. `verified` is None when Docker
    itself isn't available on this host — that's an environment gap,
    not a verdict on the generated files. Raises
    app.deploypack.generate.UnsupportedForDeployPack for any stack
    without a template (propagates to the caller as a 4xx).
    """
    files = read_all_files(io.BytesIO(raw))
    pack_files = generate_deploy_pack(stack, files)  # may raise

    build_dir = Path(tempfile.mkdtemp(prefix="shipit-deploypack-"))
    try:
        extract_repo(io.BytesIO(raw), build_dir)
        for rel_path, content in pack_files.items():
            dest = build_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        host_port, container_port = _PORTS[stack]
        result = verify_deploy_pack(build_dir, host_port, container_port)

        verified: bool | None = result.ok
        if not result.ok and "docker binary not found" in result.detail:
            verified = None

        return {
            "files": pack_files,
            "verified": verified,
            "detail": result.detail,
            "build_log": result.build_log,
        }
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
