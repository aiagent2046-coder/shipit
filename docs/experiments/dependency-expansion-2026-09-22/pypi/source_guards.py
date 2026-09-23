"""Prepare pinned experiment sources without importing code from either checkout."""

from pathlib import Path, PurePosixPath
import subprocess


def _git(source: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.PIPE)


def export_tracked_snapshot(source: Path, destination: Path, revision: str, *paths: str) -> Path:
    """Export Git objects only; working-tree changes, ignored files and hooks stay out."""
    if _git(source, "rev-parse", "HEAD").decode().strip() != revision:
        raise ValueError("source_commit_mismatch")
    entries = _git(source, "ls-tree", "-r", "-z", "--full-tree", revision, "--", *paths)
    destination.mkdir(parents=True, exist_ok=False)
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        relative = PurePosixPath(name.decode("utf-8"))
        if relative.is_absolute() or ".." in relative.parts or kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("unsupported_snapshot_entry: " + str(relative))
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_git(source, "cat-file", "blob", object_id))
        target.chmod(int(mode, 8) & 0o777)
    return destination


def prepare_scanner_snapshot(source: Path, destination: Path, revision: str) -> Path:
    """Reject dirty tracked scanner code, then exclude every untracked import input."""
    if _git(source, "rev-parse", "HEAD").decode().strip() != revision:
        raise ValueError("scanner_commit_mismatch")
    if _git(source, "diff", "--no-ext-diff", "--no-textconv", revision, "--", "app", "scripts"):
        raise ValueError("scanner_tracked_code_modified")
    return export_tracked_snapshot(source, destination, revision, "app", "scripts")
