"""TEMP diagnostic: reproduce the vite Pack boot under the exact hardened
`docker run` flags, but WITHOUT `--rm`, so nginx's real boot error survives
for `docker logs`. The production path uses `--rm`, which deletes the
container the instant nginx exits, leaving only "No such container" — see the
smoke failures on run 29913408188.

Not part of the suite. Invoked from smoke-deploy-pack.yml only. Delete once the
vite read-only regression is understood and fixed.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.deploypack import sandbox  # noqa: E402
from app.deploypack.generate import extract_repo, generate_deploy_pack, read_all_files  # noqa: E402
from app.ingest.stack_detect import Stack  # noqa: E402
from scripts.smoke_verify_deploy_pack import zip_dir  # noqa: E402


def main() -> int:
    root = REPO_ROOT / "smoke" / "vite_sample"
    raw = zip_dir(root)
    files = read_all_files(io.BytesIO(raw))
    pack_files = generate_deploy_pack(Stack.VITE_REACT, files)

    build_dir = Path(tempfile.mkdtemp(prefix="shipit-vite-diag-"))
    extract_repo(io.BytesIO(raw), build_dir)
    for rel_path, content in pack_files.items():
        dest = build_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    tag = f"shipit-vite-diag-{uuid.uuid4().hex[:8]}"
    container = f"{tag}-run"

    print("=== docker build ===", flush=True)
    build = subprocess.run(
        ["docker", "build", *sandbox._build_proxy_argv(), "-t", tag, str(build_dir)],
        capture_output=True, text=True,
    )
    print(build.stdout[-2000:])
    print(build.stderr[-2000:])
    if build.returncode != 0:
        print("BUILD FAILED", flush=True)
        return 1

    # Exactly the production run flags (sandbox.verify_deploy_pack), MINUS --rm
    # so the exited container is inspectable.
    run_cmd = [
        "docker", "run", "-d", "--name", container,
        "-p", "127.0.0.1:8080:80",
        *sandbox._network_argv(), *sandbox._user_argv(), *sandbox._readonly_argv(),
        *sandbox._RUN_HARDENING, tag,
    ]
    print("\n=== docker run (no --rm) ===", flush=True)
    print(" ".join(run_cmd), flush=True)
    run = subprocess.run(run_cmd, capture_output=True, text=True)
    print(run.stdout)
    print(run.stderr)

    time.sleep(5)

    print("\n=== docker ps -a (state) ===", flush=True)
    subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container}",
         "--format", "{{.Status}}"],
    )
    print("\n=== docker inspect (exit code / error) ===", flush=True)
    subprocess.run(
        ["docker", "inspect", container, "--format",
         "ExitCode={{.State.ExitCode}} Error={{.State.Error}} OOMKilled={{.State.OOMKilled}}"],
    )
    print("\n=== docker logs (nginx's real boot error) ===", flush=True)
    subprocess.run(["docker", "logs", container])

    print("\n=== cleanup ===", flush=True)
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
