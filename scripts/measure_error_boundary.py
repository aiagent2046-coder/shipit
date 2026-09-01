"""How often does a routed React/Next app ship with no error boundary?

The DRYDOCK_LENS_PLAN experiment, made concrete for question 1 of the frontend
rubric — the cheapest of the six, the one the rubric says is "settled by reading
lines". No LLM spend, no browser.

    python scripts/measure_error_boundary.py                    # pinned SERIES
    python scripts/measure_error_boundary.py owner/repo@<sha> ...
    python scripts/measure_error_boundary.py --from-file /root/audited-repos.txt

THREE VERDICTS, NOT TWO. A repository is `MISSING`, `ok`, or `undetermined`, and
the third is the reason app/scan/error_boundary.py returns a BoundaryScan rather
than a list. A repository whose read budget ran out has not been measured, and
folding it into either of the other two would put a number in this report that
nothing established. The incidence is reported over DECIDED repositories, with
the undecided ones counted beside it — a denominator that quietly absorbed them
is how a measurement flatters itself.

THE REASON COMES FROM THE SCAN, NOT FROM A SECOND COPY OF ITS LOGIC. An earlier
version of this script re-derived why a repository was silent, which meant the
report could explain a verdict using logic that did not produce it. The whole
deliverable here is an accountable per-repo call, so the analyzer says why and
this prints what it said.

TWO DENOMINATORS, AND ONLY ONE ANSWERS THE QUESTION. Incidence over every
submitted repository is diluted by servers, CLIs and component libraries — none
of which have a screen to blank, so none of them are evidence either way. The
plan asks what a free frontend tier would have to say to the people it is for,
and that is the incidence among MOUNTED react/next apps. Both are printed, the
useful one first, with the mount classes beside them.

THE CORPUS IS SMALL AND THAT IS THE POINT OF SAYING SO. batch_audit.SERIES pins
three repositories by full commit SHA; three is an anecdote, not an incidence.
`--from-file` reads the audited repositories out of a `repo_url|content_hash`
dump and measures them.

    THE STORED content_hash IS READ AND IGNORED, deliberately. It answers "is
    this the same code the LLM saw", which is the ground-truth question for
    comparing against stored findings. Incidence of a DETERMINISTIC rule does
    not need it — any real repository counts — and requiring a hash match would
    have discarded most of the corpus for a property this measurement never
    uses. The two experiments were conflated in the plan; they are separate.

A head resolved today is not reproducible tomorrow, which is why SERIES pins
SHAs at all. So `--from-file` resolves each default branch to its commit SHA,
measures THAT commit, and prints the `slug@sha` list to replay the run exactly.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.error_boundary import (  # noqa: E402
    COVERAGE_EXHAUSTED,
    MOUNT_WORKSPACE,
    MOUNT_YES,
    scan_error_boundary,
)

try:
    from scripts.batch_audit import SERIES, fetch_repack  # noqa: E402
except Exception:  # noqa: BLE001 — the corpus is optional, the fixtures are not
    SERIES = []
    fetch_repack = None


# --------------------------------------------------------------------------- #
# fixtures — a standalone proof of the decisions before any network is used
# --------------------------------------------------------------------------- #
# tests/test_error_boundary.py is the authoritative set; these are the handful
# that would make the corpus numbers meaningless if they were wrong, kept here
# so running this file alone still proves the analyzer first.

def _zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


_ROUTED_NEXT = {
    "package.json": '{"dependencies":{"next":"14","react":"18","react-dom":"18"}}',
    "app/layout.tsx": "export default function L({children}){return children}",
    "app/page.tsx": "export default function P(){return <div>hi</div>}",
}
_ROUTED_SPA = {
    "package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
    "src/main.tsx": ("import {createRoot} from 'react-dom/client';"
                     "createRoot(el).render(<App/>)"),
    "src/App.tsx": "export default function App(){return <div/>}",
}
_LIB_PKG = '{"name":"ui-kit","dependencies":{"react":"18","react-dom":"18"}}'


def _fixtures() -> bool:
    cases = [
        ("routed Next, no boundary", _ROUTED_NEXT, True),
        ("mounted SPA, no boundary", _ROUTED_SPA, True),
        ("Next with app/error.tsx",
         {**_ROUTED_NEXT,
          "app/error.tsx": "'use client'; export default function E(){return null}"},
         False),
        ("class componentDidCatch present",
         {**_ROUTED_SPA, "src/Boundary.tsx": "class B{componentDidCatch(){}}"},
         False),
        ("react-error-boundary in deps",
         {**_ROUTED_SPA,
          "package.json": ('{"dependencies":{"react":"18","react-dom":"18",'
                           '"react-error-boundary":"4"}}')},
         False),
        # The four shapes the UI gate exists for. Version one fired on all four.
        ("component library with index barrels",
         {"package.json": _LIB_PKG,
          "src/components/Button/index.tsx": "export const B=()=> <button/>"},
         False),
        ("design system barrel",
         {"package.json": _LIB_PKG, "src/index.tsx": "export * from './c'"},
         False),
        ("react-email templates",
         {"package.json": '{"dependencies":{"react":"18"}}',
          "emails/index.tsx": "export default () => <Html/>"},
         False),
        ("docs site with a nested app/ folder",
         {"package.json": '{"dependencies":{"react":"18"}}',
          "website/examples/app/demo/page.tsx": "export default ()=> <div/>"},
         False),
        ("boundary only inside node_modules -> still fires",
         {**_ROUTED_SPA, "node_modules/dep/index.js": "componentDidCatch(){}"},
         True),
        ("non-react repo",
         {"package.json": '{"dependencies":{"express":"4"}}',
          "server.js": "require('express')()"},
         False),
    ]
    ok = True
    print("FIXTURES — the analyzer's decisions")
    for label, files, expect_fire in cases:
        scan = scan_error_boundary(_zip(files))
        fired = bool(scan.findings)
        if fired != expect_fire:
            ok = False
        print(f"  {'OK ' if fired == expect_fire else 'FAIL'}  "
              f"{'FIRES ' if fired else 'silent'}  {label}")
    print(f"  => {'all decisions correct' if ok else 'DECISION FAILURE'}\n")
    return ok


# --------------------------------------------------------------------------- #
# corpus
# --------------------------------------------------------------------------- #

def _slug_sha(arg: str) -> tuple[str, str]:
    slug, _, sha = arg.partition("@")
    if not sha:
        raise SystemExit(f"expected owner/repo@sha, got {arg!r}")
    return slug, sha


def _slug_from_repo_url(raw: str) -> str:
    """`owner/repo` out of whatever the audits table stored."""
    s = raw.strip().removesuffix(".git")
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    parts = [p for p in s.split("/") if p]
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def _resolve_head(slug: str) -> str:
    """The default branch's current commit SHA.

    RESOLVED AND PRINTED, never used implicitly. A corpus fetched at "whatever
    the branch points at today" is not a measurement anyone can repeat — the
    same rule that made batch_audit.SERIES pin full SHAs ("a branch head would
    silently fork the series"). So a run over a URL list resolves each head
    once, measures that exact commit, and emits the `slug@sha` line needed to
    replay the run byte for byte.
    """
    with urllib.request.urlopen(  # noqa: S310
            f"https://api.github.com/repos/{slug}", timeout=60) as resp:
        branch = json.load(resp).get("default_branch") or "HEAD"
    with urllib.request.urlopen(  # noqa: S310
            f"https://api.github.com/repos/{slug}/commits/{branch}",
            timeout=60) as resp:
        return json.load(resp)["sha"]


def _targets_from_file(path: Path) -> list[tuple[str, str]]:
    """`repo_url|content_hash` lines (the audits query) or bare repo URLs.

    The content_hash column is READ AND IGNORED here, deliberately. It answers
    "is this the same code the LLM saw", which is the ground-truth question for
    comparing against stored findings. Incidence of a deterministic rule does
    not need it: any real repository counts, and requiring a hash match would
    have thrown away most of the corpus for a property this measurement never
    uses.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in path.read_text().splitlines():
        raw = line.split("|", 1)[0].strip()
        if not raw:
            continue
        slug = _slug_from_repo_url(raw)
        if not slug or slug in seen:
            continue
        seen.add(slug)
        try:
            out.append((slug, _resolve_head(slug)))
        except Exception as exc:  # noqa: BLE001 — gone private, renamed, deleted
            print(f"  ??  {slug:45s} head unresolved: {type(exc).__name__}")
    return out


def _fetch(slug: str, sha: str) -> bytes:
    if fetch_repack is not None:
        return fetch_repack(slug, sha)
    url = f"https://codeload.github.com/{slug}/zip/{sha}"
    raw = urllib.request.urlopen(url, timeout=120).read()  # noqa: S310
    src = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for zi in src.infolist():
            parts = zi.filename.split("/", 1)
            if len(parts) < 2 or not parts[1] or zi.is_dir():
                continue
            dst.writestr(parts[1], src.read(zi))
    return out.getvalue()


def main() -> int:
    if not _fixtures():
        print("fixtures failed — not running the corpus", file=sys.stderr)
        return 1

    args = sys.argv[1:]
    if args and args[0] == "--from-file":
        if len(args) < 2:
            raise SystemExit("--from-file needs a path")
        print(f"RESOLVING heads from {args[1]}")
        targets = _targets_from_file(Path(args[1]))
        print(f"  {len(targets)} repositories resolved\n")
    elif args:
        targets = [(*_slug_sha(a),) for a in args]
    else:
        targets = [(s.slug, s.sha) for s in SERIES]

    if not targets:
        print("no corpus available (batch_audit SERIES not importable and no "
              "slug@sha args given) — fixtures passed, that is the deliverable "
              "here", file=sys.stderr)
        return 0

    print(f"CORPUS — {len(targets)} repositories\n")
    fired = undetermined = failed = 0
    mounted_decided = other_decided = 0
    by_mount: dict[str, int] = {}
    replay: list[str] = []

    for slug, sha in targets:
        replay.append(f"{slug}@{sha}")
        try:
            data = _fetch(slug, sha)
        except Exception as exc:  # noqa: BLE001 — one bad fetch must not end the run
            failed += 1
            print(f"  ??  {slug:45s} fetch failed: {type(exc).__name__}")
            continue

        scan = scan_error_boundary(io.BytesIO(data))
        by_mount[scan.mount] = by_mount.get(scan.mount, 0) + 1
        # `files_read` can be far below `files_total` on a COMPLETE scan: a
        # boundary token ends the walk. Printed together so nobody reads the
        # small number as a truncated pass.
        span = f"[{scan.coverage}, read {scan.files_read}]"

        if scan.coverage == COVERAGE_EXHAUSTED:
            undetermined += 1
            print(f"  —   {slug:45s} UNDETERMINED {span} — {scan.reason}")
            continue
        if scan.mount == MOUNT_YES:
            mounted_decided += 1
        else:
            other_decided += 1
        if scan.findings:
            fired += 1
            print(f"  ✗   {slug:45s} MISSING {span} — {scan.reason}")
        else:
            print(f"  ✓   {slug:45s} ok {span} — {scan.reason}")

    # TWO DENOMINATORS, AND ONLY ONE OF THEM ANSWERS THE QUESTION. Incidence
    # over every submitted repository is diluted by servers, CLIs and component
    # libraries, none of which have a screen to blank. The plan asks what a
    # free frontend tier would have to say to the people it is for, and those
    # are the MOUNTED apps.
    print()
    total_decided = mounted_decided + other_decided
    if mounted_decided:
        print(f"incidence among MOUNTED react/next apps: "
              f"{fired}/{mounted_decided} = "
              f"{100 * fired / mounted_decided:.0f}%   <- the plan's question")
    else:
        print("incidence among MOUNTED react/next apps: none in this corpus")
    if total_decided:
        print(f"incidence over all decided repositories: {fired}/{total_decided}"
              f" = {100 * fired / total_decided:.0f}%   (diluted by non-apps)")
    classes = ", ".join(f"{k}={v}" for k, v in sorted(by_mount.items()))
    print(f"  mount classes: {classes or 'none — nothing was read'}")
    workspaces = by_mount.get(MOUNT_WORKSPACE, 0)
    if workspaces:
        print(f"  {workspaces} workspace repositories were NOT analyzed — their "
              "react is in a\n  nested manifest, and those are disproportionately "
              "the mature products,\n  so their absence pushes the rate above "
              "what a full analysis would give")
    if undetermined or failed:
        print(f"  not counted: {undetermined} undetermined (read budget), "
              f"{failed} unfetchable")

    print("\nreplay this exact run:\n  python scripts/measure_error_boundary.py "
          + " \\\n    ".join(replay))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
