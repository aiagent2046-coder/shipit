#!/usr/bin/env python3
"""Install the build-step egress allowlist into the host's squid.conf.

WHY THIS IS A SCRIPT AND NOT A README STEP. It was a README step twice on
2026-08-17, and twice the operator pasted the command block and the config came
out unchanged — because the actual edit ("replace the three inline acl lines
with a file reference") was prose sitting between two runnable commands. The
verification then reported 403, the detector measurement re-ran against an
unpatched proxy, and the run was wasted. An instruction a human has to
hand-apply in the middle of a copy-paste block is a step that does not happen.

WHAT IT DOES. Replaces every inline `acl allowed_dst dstdomain <domain>` line
with a single reference to the shipped list, in place, keeping position (the
ACL must stay above `http_access allow allowed_dst`). `http_access` is never
touched — the host's rules were already the right shape.

Idempotent: the reference line itself matches the pattern being replaced, so a
second run collapses to the same output.

Safe: writes a timestamped backup, runs `squid -k parse` against the result,
and RESTORES THE BACKUP if the parse fails. A proxy that will not start takes
every build on the host down with it, so a failed parse must not survive.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_SQUID_CONF = Path("/etc/squid/squid.conf")
DEFAULT_INSTALLED_LIST = Path("/etc/squid/squid-build-allowlist.conf")
REPO_LIST = (
    Path(__file__).resolve().parent.parent
    / "sandbox-runner" / "squid-build-allowlist.conf"
)

# `acl allowed_dst dstdomain …` — inline domain or an existing file reference.
# Deliberately anchored on the ACL NAME the host already uses: rewriting an
# arbitrary acl would be a much larger claim on someone else's config.
_ACL_LINE = re.compile(r'^\s*acl\s+allowed_dst\s+dstdomain\s+\S', re.IGNORECASE)


def rewrite(conf_text: str, list_path: Path = DEFAULT_INSTALLED_LIST) -> str:
    """Collapse the inline `allowed_dst` domain lines into one file reference.

    The replacement lands where the FIRST matched line was, so the ACL keeps
    its position relative to the `http_access` rules below it. Every other line
    — SSL_ports, CONNECT, http_access, http_port, logging — is passed through
    untouched.
    """
    reference = f'acl allowed_dst dstdomain "{list_path}"'
    out: list[str] = []
    emitted = False
    for line in conf_text.splitlines():
        if _ACL_LINE.match(line):
            if not emitted:
                out.append(reference)
                emitted = True
            continue  # drop the inline entry (or a stale reference)
        out.append(line)

    if not emitted:
        # No allowed_dst ACL at all: this is not the config we were told about.
        # Refuse rather than invent one — a wrong guess here silently changes
        # what the proxy permits.
        raise SystemExit(
            "refusing to edit: no `acl allowed_dst dstdomain …` line found in "
            "the config. Check the path, or wire the reference by hand:\n"
            f"    {reference}"
        )

    text = "\n".join(out)
    return text + "\n" if conf_text.endswith("\n") else text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--conf", type=Path, default=DEFAULT_SQUID_CONF)
    ap.add_argument("--list-src", type=Path, default=REPO_LIST)
    ap.add_argument("--list-dest", type=Path, default=DEFAULT_INSTALLED_LIST)
    ap.add_argument("--no-reload", action="store_true",
                    help="edit and validate, but do not reload squid")
    args = ap.parse_args()

    if not args.list_src.is_file():
        print(f"missing allowlist source: {args.list_src}", file=sys.stderr)
        return 2
    if not args.conf.is_file():
        print(f"missing squid config: {args.conf}", file=sys.stderr)
        return 2

    shutil.copy2(args.list_src, args.list_dest)
    args.list_dest.chmod(0o644)
    print(f"installed {args.list_dest}")

    original = args.conf.read_text()
    updated = rewrite(original, args.list_dest)
    if updated == original:
        print("squid.conf already references the list — nothing to change")
    else:
        backup = args.conf.with_suffix(f".conf.bak-{int(time.time())}")
        shutil.copy2(args.conf, backup)
        args.conf.write_text(updated)
        print(f"rewrote {args.conf} (backup: {backup})")

        # OSError matters as much as a non-zero exit: the config is ALREADY
        # rewritten by this point, so a missing `squid` binary that escaped as
        # a traceback would leave the host running an unvalidated config with
        # the backup sitting unused next to it.
        try:
            parse = subprocess.run(["squid", "-k", "parse"],
                                   capture_output=True, text=True, timeout=30)
            failure = parse.stderr.strip()[-2000:] if parse.returncode else ""
        except (OSError, subprocess.SubprocessError) as exc:
            failure = f"could not run `squid -k parse`: {type(exc).__name__}: {exc}"

        if failure:
            shutil.copy2(backup, args.conf)
            print(failure, file=sys.stderr)
            print(f"\nvalidation FAILED — restored {args.conf} from {backup}",
                  file=sys.stderr)
            return 1
        print("squid -k parse ok")

    if args.no_reload:
        return 0

    reload_proc = subprocess.run(["systemctl", "reload", "squid"],
                                 capture_output=True, text=True)
    if reload_proc.returncode != 0:
        print(reload_proc.stderr.strip(), file=sys.stderr)
        return 1
    print("squid reloaded")

    # Prove the grant that blocked the 2026-08-17 detector run now resolves.
    # Reporting success without this is how the last two attempts "passed".
    probe = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "-x", "http://127.0.0.1:3128",
         "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz"],
        capture_output=True, text=True, timeout=30,
    )
    code = (probe.stdout or "").strip()
    print(f"alpine APKINDEX through the proxy: HTTP {code or '(no answer)'}")
    if code != "200":
        print("still not allowed — the measurement will report the proxy, "
              "not the applications", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
