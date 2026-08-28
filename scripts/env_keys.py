#!/usr/bin/env python3
"""Which variables an env file defines, recorded before an edit and checked after.

    scripts/env_keys.py snapshot      # before you open the file
    <edit /opt/shipit/.env>
    scripts/env_keys.py diff          # after you close it

WHY THIS EXISTS. On 2026-08-28 a hand edit to /opt/shipit/.env replaced the
LLM_MODEL line with a different variable. Nothing noticed. The API served, the
queue drained, jobs finished `succeeded` with no error_code -- and every paid
audit came back static-only under a paid basis, because app/llm/client.py fell
back to a default model name the provider rejects with a 400. The only visible
trace was a `basis` field inside score_json.

deploy/scripts/validate-production-env.py now catches a duplicated key and a
provider with no model pinned, and both of those came out of that same edit.
Neither can catch THIS shape: a variable that was there yesterday and is not
there today. The validator sees one file at one moment and has no memory. The
only thing that knew was a week-old backup, and the reason to keep one of
those around is exactly the reason not to.

So this records the NAMES and nothing else. A list of variable names is not a
secret -- it is roughly what .env.example already publishes -- so the snapshot
can live next to the file and outlive any number of edits, where a backup full
of live credentials should live for minutes.

DELIBERATELY MANUAL, and that is the design rather than laziness. Snapshotting
automatically -- on service start, say -- would record whatever state the file
was in, including the broken one, and the next comparison would call the
breakage the new normal. The snapshot is a claim that a human looked at the
file and considered it correct.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import env_file  # noqa: E402

# Beside the file it describes, so the two travel together and nobody has to
# remember a second path -- which requires an entry in .gitignore, and that is
# not cosmetic. /opt/shipit is a git checkout and deploy-production.sh refuses
# to deploy with ANY untracked file present, so a snapshot written here
# without that line would block the next release, the way a stray
# dub_after.json did on 2026-08-28. The comment here first claimed the suffix
# was already covered by a `.env*` rule; there is no such rule, only `.env`
# and `.env.bak*`, and tests/test_env_keys.py now asks git rather than me.
SNAPSHOT_SUFFIX = ".keys"

_HEADER = "# names only -- never values. taken {when} from {path}\n"


def snapshot_path(env_path: Path) -> Path:
    return env_path.with_name(env_path.name + SNAPSHOT_SUFFIX)


def key_names(env_path: Path) -> list[str]:
    """The variable names the file defines, sorted.

    Through env_file.read_values, so this agrees with the parser the service
    and the validator use about what counts as an assignment -- a second set
    of rules here would disagree about a commented line or a quoted value and
    report a phantom change.
    """
    return sorted(env_file.read_values(env_path))


def write_snapshot(env_path: Path, out: Path) -> int:
    names = key_names(env_path)
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.write_text(
        _HEADER.format(when=when, path=env_path) + "".join(f"{n}\n" for n in names)
    )
    return len(names)


def read_snapshot(path: Path) -> list[str]:
    return sorted(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("snapshot", "diff"))
    ap.add_argument("--env-file", type=Path, default=None)
    ap.add_argument("--snapshot", type=Path, default=None)
    args = ap.parse_args(argv)

    env_path = args.env_file or env_file.env_file_path()
    snap_path = args.snapshot or snapshot_path(env_path)

    if not env_path.is_file():
        print(f"no env file at {env_path}", file=sys.stderr)
        return 78

    if args.action == "snapshot":
        count = write_snapshot(env_path, snap_path)
        print(f"{count} names -> {snap_path}")
        return 0

    if not snap_path.is_file():
        # Not zero. A comparison with nothing to compare against is not a
        # clean bill of health, and returning 0 here would let it read as one
        # in a script.
        print(f"no snapshot at {snap_path}; run `snapshot` BEFORE editing",
              file=sys.stderr)
        return 78

    before = set(read_snapshot(snap_path))
    after = set(key_names(env_path))

    gone = sorted(before - after)
    added = sorted(after - before)

    for name in added:
        print(f"added:   {name}")
    if not gone:
        print(f"nothing lost ({len(after)} names, {len(added)} added)")
        return 0

    # The whole point. Adding a variable is ordinary; losing one is what
    # happened, and what nothing else in this deployment can see.
    for name in gone:
        print(f"MISSING: {name}", file=sys.stderr)
    print(f"{len(gone)} variable(s) present at snapshot time are gone. If that "
          "was deliberate, take a new snapshot; otherwise restore them before "
          "restarting anything.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
