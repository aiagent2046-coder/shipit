"""Deploy Pack pipeline: generate + verify, wired for the API.

Writes the real repo bytes plus the generated files to a temp dir, runs
the sandbox check against it, and always cleans the dir up regardless
of outcome.
"""

from __future__ import annotations

import io
import shutil
import socket
import tempfile
from pathlib import Path

from app.deploypack.generate import extract_repo, generate_deploy_pack, read_all_files
from app.deploypack.preview import PreviewRegistry
from app.deploypack.sandbox import verify_deploy_pack
from app.ingest.stack_detect import Stack

# (compose_host_port, container_port) — matches what generate.py puts in
# the Pack's own docker-compose.yml for each stack. Only the container
# port is used for sandbox verification; the host side is picked fresh
# per run by _free_port (see below), never the fixed value here.
_PORTS: dict[Stack, tuple[int, int]] = {
    Stack.FASTAPI: (8000, 8000),
    Stack.VITE_REACT: (8080, 80),
}


def _free_port() -> int:
    """An ephemeral host port the OS confirms is free right now.

    The non-preview verify path used to bind the fixed _PORTS host port
    (8000/8080). Two concurrent same-stack requests — the API offloads
    run_deploy_pack to a threadpool — then raced for it, and the loser's
    `docker run -p` failed with "port is already allocated", reporting a
    perfectly good Pack as unverified. Binding :0 hands back a port the
    kernel just reserved; the tiny bind→close→reuse gap is acceptable
    here (docker grabs it within the same call), and the preview path
    keeps its own reservation-based allocator — see app/deploypack/preview.py."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_deploy_pack(
    raw: bytes,
    stack: Stack,
    *,
    preview: PreviewRegistry | None = None,
    owner_key: str | None = None,
) -> dict:
    """Generate the Pack, verify it in a real sandbox, clean up.

    Returns {"files": {path: content}, "verified": bool | None,
    "detail": str, "build_log": str, "preview": dict | None}. `verified`
    is None when Docker itself isn't available on this host — that's an
    environment gap, not a verdict on the generated files. Raises
    app.deploypack.generate.UnsupportedForDeployPack for any stack
    without a template (propagates to the caller as a 4xx).

    Pass `preview` + `owner_key` to keep the container alive after a
    successful boot instead of tearing it down (see
    app/deploypack/preview.py). The build directory is deleted either
    way — docker build already baked its contents into the image, the
    running container doesn't read from it afterwards.
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

        container_port = _PORTS[stack][1]
        preview_info: dict | None = None

        if preview is not None:
            assert owner_key is not None, "owner_key required when preview is set"
            preview_result = preview.start(build_dir, container_port, owner_key)
            verified = preview_result.ok
            detail = preview_result.detail
            build_log = preview_result.build_log
            if preview_result.ok:
                preview_info = {
                    "local_url": preview_result.local_url,
                    "expires_at": preview_result.expires_at,
                }
        else:
            result = verify_deploy_pack(build_dir, _free_port(), container_port)
            verified = result.ok
            detail = result.detail
            build_log = result.build_log

        if not verified and "docker binary not found" in detail:
            verified = None

        return {
            "files": pack_files,
            "verified": verified,
            "detail": detail,
            "build_log": build_log,
            "preview": preview_info,
        }
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
