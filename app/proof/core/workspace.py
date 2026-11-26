"""Build a patched workspace zip from original bytes + a FixpackPlan.

Used by the informational proof stage: run the same template against the
original tree and the tree the PR will deliver, without touching disk or
docker. Paths in ``files`` / ``deletions`` are repo-relative, matching
``FixpackPlan``.
"""

from __future__ import annotations

import io
import zipfile


def apply_plan_to_zip(
    zip_bytes: bytes,
    files: dict[str, str],
    deletions: list[str] | tuple[str, ...] = (),
) -> bytes:
    """Return a new zipball with ``files`` applied and ``deletions`` removed.

    Preserves the original entry-name layout (including any single wrapper
    folder GitHub zipballs use) so downstream scanners see the same paths
    the audit did. Unknown deletion paths are ignored; new ``files`` keys
    that did not exist are added under the same wrapper prefix as siblings.
    """
    delete_set = set(deletions)
    buf = io.BytesIO()
    wrapper_prefix = ""

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as src, zipfile.ZipFile(
        buf, "w", compression=zipfile.ZIP_DEFLATED
    ) as dst:
        names = src.namelist()
        if names:
            first = names[0]
            if first.endswith("/") and first.count("/") == 1:
                wrapper_prefix = first
            elif "/" in first:
                # e.g. "repo-main/README.md" — shared first segment
                seg = first.split("/", 1)[0] + "/"
                if all(n.startswith(seg) or n == seg.rstrip("/") for n in names):
                    wrapper_prefix = seg

        written: set[str] = set()
        for info in src.infolist():
            name = info.filename
            if info.is_dir():
                # Keep directory entries only if not wholly deleted
                rel = _repo_relative(name, wrapper_prefix)
                if rel.rstrip("/") in delete_set or rel in delete_set:
                    continue
                dst.writestr(info, b"")
                continue

            rel = _repo_relative(name, wrapper_prefix)
            if rel in delete_set:
                continue
            if rel in files:
                dst.writestr(name, files[rel])
                written.add(rel)
            else:
                dst.writestr(name, src.read(name))
                written.add(rel)

        for rel, content in files.items():
            if rel in written or rel in delete_set:
                continue
            entry = f"{wrapper_prefix}{rel}" if wrapper_prefix else rel
            dst.writestr(entry, content)

    return buf.getvalue()


def _repo_relative(name: str, wrapper_prefix: str) -> str:
    if wrapper_prefix and name.startswith(wrapper_prefix):
        return name[len(wrapper_prefix):]
    if "/" in name and not wrapper_prefix:
        # strip single top folder the same way generate._repo_relative does
        return name.split("/", 1)[1]
    return name
