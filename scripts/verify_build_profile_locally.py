#!/usr/bin/env python3
"""Run this YOURSELF, on a host with Docker, against a real repository.

What it proves that no unit test can: that the commands
`detect_verification_profile` plans actually RUN. The profile is built from
package.json and lockfiles, so a test can only assert the strings we meant to
emit -- it cannot tell you that `pnpm --filter web run build` succeeds inside
node:20-slim, that corepack really puts pnpm on PATH, or that a workspace
member's tsconfig is found. Those are facts about Docker and about npm/pnpm
/yarn, and the only honest way to learn them is to execute the thing.

This matters most for workspaces. Before member support, a monorepo produced
no profile at all and every Fix Pack for it fell back to the semantic check.
Now it produces one -- and a profile that is generated but never executed is
exactly the "builds green, boots never" shape this repository refuses to ship
elsewhere.

Usage:
    python scripts/verify_build_profile_locally.py https://github.com/owner/repo
    python scripts/verify_build_profile_locally.py path/to/repo.zip
    python scripts/verify_build_profile_locally.py <target> --plan-only

`--plan-only` prints the profile and stops, needing no Docker. Without it the
containers really run: an install with network, then every step offline, with
the same restrictions a customer's Fix Pack gets.

Expect the full run to take minutes on a large repository, and expect it to
cost real disk in the Docker cache.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.fixpack.verification import detect_verification_profile  # noqa: E402


def load(target: str) -> bytes:
    path = Path(target)

    if path.exists():
        return path.read_bytes()

    if not target.startswith("https://github.com/"):
        raise SystemExit(
            f"not a file and not a github.com URL: {target}"
        )

    from app.ingest.github_fetch import fetch_repo_zip

    owner, _, repo = target.removeprefix(
        "https://github.com/").rstrip("/").partition("/")

    if not owner or not repo:
        raise SystemExit(f"cannot read owner/repo from {target}")

    return fetch_repo_zip(owner, repo)


def debug_install(raw: bytes, profile) -> int:
    """Reproduce the install step exactly, and show what it said.

    The pipeline deliberately never copies container output into a stored
    field, and it is right not to: that output is the client's, it can be
    enormous, and it can contain their secrets. But that leaves an operator
    debugging a failure with nothing but an exit code, and an exit code sent
    me chasing three wrong theories -- a proxy that was not configured, a
    zipball that was identical, and ulimits that were not the difference --
    while the same command run by hand succeeded every time.

    So this reuses the pipeline's OWN argv builder and OWN extraction rather
    than a hand-written approximation, because an approximation is what made
    those three rounds worthless. It prints to the operator's terminal, on
    their machine, for a repository they chose. It keeps the work directory
    so the half-finished tree can be inspected.
    """
    import subprocess
    import tempfile

    from app.fixpack.semantic_check import (
        INSTALL_TIMEOUT_SECONDS,
        _chown_workdir,
        _docker_install_argv,
        _extract_repo_relative,
    )

    workdir = tempfile.mkdtemp(prefix="shipit-verify-debug-")
    _extract_repo_relative(raw, workdir)
    _chown_workdir(workdir)

    argv = _docker_install_argv(profile.image, workdir, profile.install_command)

    print(f"\nwork directory (kept): {workdir}")
    print(f"argv: {' '.join(argv)}\n")

    try:
        proc = subprocess.run(
            argv,
            timeout=INSTALL_TIMEOUT_SECONDS,
            text=True,
            capture_output=True,
        )
    except subprocess.TimeoutExpired:
        print(f"timed out after {INSTALL_TIMEOUT_SECONDS}s")
        return 1

    tail = 6000
    print(f"exit code: {proc.returncode}")
    print(f"--- stdout (last {tail} chars) ---\n{proc.stdout[-tail:]}")
    print(f"--- stderr (last {tail} chars) ---\n{proc.stderr[-tail:]}")

    return 0 if proc.returncode == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="a github.com repo URL or a .zip path")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the planned profile and stop; needs no Docker",
    )
    parser.add_argument(
        "--debug-install",
        action="store_true",
        help=(
            "run ONLY the install step, print the container's output, and "
            "keep the work directory for inspection"
        ),
    )
    args = parser.parse_args()

    raw = load(args.target)
    profile = detect_verification_profile(raw)

    if profile is None:
        print(
            "No verification profile.\n"
            "The Fix Pack falls back to the semantic check for this "
            "repository, which is the weaker guarantee. If you expected a "
            "profile, the framework was not found at the repository root or "
            "in a workspace member."
        )
        return 1

    print(f"ecosystem : {profile.ecosystem}")
    print(f"framework : {profile.framework}")
    print(f"image     : {profile.image}")
    print(f"install   : {profile.install_command}")

    for step in profile.steps:
        required = "required" if step.required else "optional"
        print(f"  {step.name:<10} {required:<9} {step.command}")

    if args.plan_only:
        return 0

    if args.debug_install:
        return debug_install(raw, profile)

    # Imported here, not at module scope: the plan-only path must work on a
    # host with no Docker, and this module reaches for the sandbox at import.
    from app.fixpack.semantic_check import run_verification_profile

    print("\nRunning the profile (this really builds; minutes, not seconds)…")
    stages = run_verification_profile(raw, profile)

    failed = False

    for stage in stages:
        # detail and exit_code are the whole point when something fails: they
        # separate "the install timed out" from "the install exited 1", and
        # those have opposite fixes. They are generated by ShipIt, never
        # copied from client output, so printing them leaks nothing.
        note = " ".join(
            part for part in (
                stage.detail or "",
                f"exit {stage.exit_code}" if stage.exit_code is not None else "",
                f"{stage.duration_ms / 1000:.0f}s" if stage.duration_ms else "",
            ) if part
        )
        print(f"  {stage.name:<10} {stage.status:<12} {note}")
        if stage.status not in ("passed", "skipped"):
            failed = True

    print(
        "\nThe planned commands do not run."
        if failed else
        "\nEvery planned command ran. The profile is real, not just plausible."
    )

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
