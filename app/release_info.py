"""Descriptive labels for the running release, read from release metadata.

`release_manager.py build` writes `.shipit-release.json` into the root of every
immutable release. `activate` separately writes `SHIPIT_RELEASE=<sha>` into the
release env file, and that env var is what `/version` and every JSON log record
already report — that pairing is an invariant (a journalctl line and the
endpoint can never disagree about which build is running) and this module does
not touch it.

What the env var cannot carry is a *human-readable* label. `SHIPIT_RELEASE` is
a bare 40-character SHA, so "which release is live" is answerable only by
someone who can map SHAs to commits. This module reads the two descriptive
fields the builder records alongside it — `git_describe` (a tag when the commit
has one) and `built_at` — so `/version` can report them as well.

Deliberately tolerant. A missing or malformed metadata file means "running from
a source checkout, not a built release" — the normal case in development and in
tests — and is reported as nulls, never as an error. Nothing dispatches on
these values; they are descriptive only. A version probe must not be able to
take the API down.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

METADATA_FILE = ".shipit-release.json"

# app/release_info.py -> app/ -> release root, which is where the builder
# writes the metadata file.
_RELEASE_ROOT = Path(__file__).resolve().parent.parent


def _read_metadata(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            loaded = json.load(stream)
    except (OSError, ValueError):
        # No metadata (source checkout) or corrupt metadata. Both mean "we
        # cannot say", which is reported as unknown rather than raising.
        return {}

    if not isinstance(loaded, dict):
        return {}

    return loaded


def _coerce_str(value: Any) -> str | None:
    """Only pass through real strings.

    The metadata file is written by the deploy tooling, not by a user, but it
    is still parsed input: a hand-edited file must not be able to put a dict
    or a list into a JSON response.
    """
    return value if isinstance(value, str) else None


@lru_cache(maxsize=1)
def release_labels() -> dict[str, str | None]:
    """Descriptive labels for the running release.

    Cached: the metadata file cannot change under a live process, because
    activating a release repoints the `current` symlink at a different
    directory and restarts the unit.
    """
    metadata = _read_metadata(_RELEASE_ROOT / METADATA_FILE)

    return {
        # A tag when the built commit had one, else an abbreviated SHA.
        "version": _coerce_str(metadata.get("git_describe")),
        "built_at": _coerce_str(metadata.get("built_at")),
    }
