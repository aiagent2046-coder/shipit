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


def read_domains(list_src: Path) -> list[str]:
    """The domain entries of the shipped list, comments and blanks dropped."""
    return [
        line.strip()
        for line in list_src.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def rewrite(conf_text: str, list_path: Path = DEFAULT_INSTALLED_LIST,
            domains: list[str] | None = None) -> str:
    """Replace the inline `allowed_dst` domain lines with the shipped list.

    By default this writes ONE line referencing the installed file. Pass
    ``domains`` for --inline, which writes one `acl` line per domain straight
    into squid.conf instead.

    Inline exists because the file form adds a dependency on how this squid
    build parses an included ACL file, and that is a variable worth being able
    to remove: the inline form is what prod ran before any of this, so it is
    known to work here. Same resulting grant either way.

    The replacement lands where the FIRST matched line was, so the ACL keeps
    its position relative to the `http_access` rules below it. Every other line
    — SSL_ports, CONNECT, http_access, http_port, logging — is passed through
    untouched.
    """
    if domains is not None:
        replacement = [f"acl allowed_dst dstdomain {d}" for d in domains]
    else:
        replacement = [f'acl allowed_dst dstdomain "{list_path}"']

    out: list[str] = []
    emitted = False
    for line in conf_text.splitlines():
        if _ACL_LINE.match(line):
            if not emitted:
                out.extend(replacement)
                emitted = True
            continue  # drop the inline entry (or a stale reference)
        out.append(line)

    if not emitted:
        # No allowed_dst ACL at all: this is not the config we were told about.
        # Refuse rather than invent one — a wrong guess here silently changes
        # what the proxy permits.
        raise SystemExit(
            "refusing to edit: no `acl allowed_dst dstdomain …` line found in "
            "the config. Check the path, or wire it by hand:\n    "
            + "\n    ".join(replacement)
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
    ap.add_argument("--inline", action="store_true",
                    help="write the domains straight into squid.conf instead "
                         "of referencing the installed file — removes any "
                         "dependency on how this squid parses an ACL file")
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

    domains = read_domains(args.list_src) if args.inline else None
    if domains is not None:
        print(f"inline mode: {len(domains)} domains written into the config")

    original = args.conf.read_text()
    updated = rewrite(original, args.list_dest, domains)
    backup: Path | None = None
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

    # REGRESSION GATE, checked before the new grant. This edit replaces the
    # inline domains with a file, so if squid loads that file as empty the ACL
    # matches nothing, `http_access deny all` catches everything, and EVERY
    # build on the host breaks — including the npm/pypi ones that worked before
    # this script ran. That failure is far worse than the one being fixed, so
    # it is detected here and rolled back automatically rather than left for
    # whoever runs the next build to discover.
    pypi_code, pypi_probe, endpoint = _probe("https://pypi.org/simple/")
    print(f"pypi via {endpoint} (worked before this change): "
          f"HTTP {pypi_code or '(no answer)'}")
    if pypi_code != "200":
        if pypi_probe.returncode == 7:
            # Nothing listening anywhere we know to look. This is NOT evidence
            # about the allowlist, and must not be reported as if it were.
            print(f"\nCannot reach the proxy at any of "
                  f"{', '.join(proxy_endpoints())} — so this run has said "
                  "NOTHING about the allowlist, in either direction.",
                  file=sys.stderr)
            print(f"curl: {pypi_probe.stderr.strip()}", file=sys.stderr)
            print("\nFind where it actually listens, then re-run:\n"
                  "    ss -lntp | grep 3128\n"
                  "    systemctl status squid --no-pager | head -20\n"
                  "    grep -n http_port /etc/squid/squid.conf",
                  file=sys.stderr)
            _print_squid_log_tail()
            return 1

        print("\nREGRESSION: a grant that worked before this change no longer "
              "resolves.", file=sys.stderr)
        if not args.inline:
            print("This squid is most likely not reading the referenced file "
                  "as a domain list. Re-run with --inline to write the domains "
                  "straight into squid.conf and remove that variable.",
                  file=sys.stderr)
        if pypi_probe.stderr.strip():
            print(f"curl: {pypi_probe.stderr.strip()}", file=sys.stderr)
        _print_squid_log_tail()
        if backup is not None:
            shutil.copy2(backup, args.conf)
            subprocess.run(["systemctl", "reload", "squid"],
                           capture_output=True, text=True)
            print(f"\nrestored {args.conf} from {backup} and reloaded — the "
                  "host is back to the config it had before this run.",
                  file=sys.stderr)
        return 1

    # Prove the grant that blocked the 2026-08-17 detector run now resolves.
    # Reporting success without this is how the last two attempts "passed".
    code, probe, endpoint = _probe(
        "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz"
    )
    print(f"alpine APKINDEX via {endpoint}: HTTP {code or '(no answer)'}")
    if code == "200":
        return 0

    # A status is not a diagnosis — the lesson this whole exercise kept
    # relearning. `000` in particular is not a 403: for an https URL curl
    # tunnels through CONNECT, and when the proxy refuses the tunnel there is
    # no tunnelled response to report a code for. Print what curl actually
    # said and what squid actually logged, so the next step is a decision and
    # not a guess.
    print("still not allowed — the measurement would report the proxy, "
          "not the applications", file=sys.stderr)
    if probe.stderr.strip():
        print(f"\ncurl: {probe.stderr.strip()}", file=sys.stderr)
    _print_squid_log_tail()
    return 1


def docker_bridge_gateway() -> str | None:
    """The address a build container reaches the host on.

    `_build_proxy_argv` in app/deploypack/sandbox.py hands builds
    `HTTP_PROXY=http://host.docker.internal:3128` plus
    `--add-host=host.docker.internal:host-gateway`, so from inside a build the
    proxy is the docker bridge gateway. That name does not resolve on the host
    itself, hence looking the interface up here.
    """
    proc = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "docker0"],
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        return None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout)
    return m.group(1) if m else None


def proxy_endpoints() -> list[str]:
    """Where to look for the proxy, nearest-truth last.

    MEASURED 2026-08-17: squid is NOT listening on loopback on the prod host —
    a probe of 127.0.0.1:3128 fails to connect outright, while the access log
    shows live CONNECT attempts from 172.17.0.2, a build container. Verifying
    on loopback therefore tested an address nothing uses and reported `000`
    twice while saying nothing about the grant.

    A check has to run against the path the thing being checked actually
    takes.
    """
    endpoints = ["127.0.0.1:3128"]
    gateway = docker_bridge_gateway()
    if gateway:
        endpoints.append(f"{gateway}:3128")
    return endpoints


def _probe(url: str) -> tuple[str, subprocess.CompletedProcess, str]:
    """Fetch ``url`` through the proxy, returning (http_code, process, endpoint).

    Tries each candidate endpoint and returns the first that gets an answer of
    any kind — a proxy that answers 403 is still the proxy; one that refuses
    the TCP connection is the wrong address.

    `%{http_code}` is `000` when curl never received an HTTP response at all.
    For an https URL that is either a refused CONNECT or, as here, nothing
    listening. The process is returned so the caller can print what curl said,
    because a status alone has proved twice today to be unactionable.
    """
    last: tuple[str, subprocess.CompletedProcess, str] | None = None
    for endpoint in proxy_endpoints():
        proc = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "-x", f"http://{endpoint}", url],
            capture_output=True, text=True, timeout=30,
        )
        code = (proc.stdout or "").strip()
        last = (code, proc, endpoint)
        # curl exit 7 == could not connect: wrong address, try the next.
        if proc.returncode != 7:
            return last
    assert last is not None
    return last


def _print_squid_log_tail(path: Path = Path("/var/log/squid/access.log"),
                          lines: int = 5) -> None:
    """squid's own verdict on the probe — TCP_DENIED, TCP_TUNNEL, DNS failure.
    Authoritative where curl's exit code is only a symptom."""
    try:
        tail = path.read_text(errors="replace").splitlines()[-lines:]
    except OSError as exc:
        print(f"\n(could not read {path}: {type(exc).__name__})", file=sys.stderr)
        return
    if tail:
        print(f"\n{path} (last {len(tail)}):", file=sys.stderr)
        for line in tail:
            print(f"  {line}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
