"""How often does a routed React/Next app ship with no error boundary?

The DRYDOCK_LENS_PLAN experiment, made concrete for question 1 of the frontend
rubric — the cheapest of the six, the one the rubric says is "settled by reading
lines". No LLM spend, no browser.

    python scripts/measure_error_boundary.py
    python scripts/measure_error_boundary.py owner/repo@<sha> owner/repo2@<sha>

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

THE CORPUS IS SMALL AND THAT IS THE POINT OF SAYING SO. batch_audit.SERIES pins
three repositories by full commit SHA. Three is an anecdote, not an incidence,
and no outcome over three repositories decides the plan's question. Widen it
with slug@sha arguments — the plan names the cheap source: re-fetch the audited
repositories and keep the ones that still reproduce their stored content_hash.
"""

from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.error_boundary import (  # noqa: E402
    COVERAGE_EXHAUSTED,
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
    if args:
        targets = [(*_slug_sha(a),) for a in args]
    else:
        targets = [(s.slug, s.sha) for s in SERIES]

    if not targets:
        print("no corpus available (batch_audit SERIES not importable and no "
              "slug@sha args given) — fixtures passed, that is the deliverable "
              "here", file=sys.stderr)
        return 0

    print(f"CORPUS — {len(targets)} pinned repositories\n")
    fired = undetermined = decided = failed = 0
    for slug, sha in targets:
        try:
            data = _fetch(slug, sha)
        except Exception as exc:  # noqa: BLE001 — one bad fetch must not end the run
            failed += 1
            print(f"  ??  {slug:45s} fetch failed: {type(exc).__name__}")
            continue

        scan = scan_error_boundary(io.BytesIO(data))
        if scan.coverage == COVERAGE_EXHAUSTED:
            undetermined += 1
            print(f"  —   {slug:45s} UNDETERMINED — {scan.reason}")
        elif scan.findings:
            fired += 1
            decided += 1
            print(f"  ✗   {slug:45s} MISSING error boundary — {scan.reason}")
        else:
            decided += 1
            print(f"  ✓   {slug:45s} ok — {scan.reason}")

    print()
    if decided:
        print(f"per-repo incidence: {fired}/{decided} = "
              f"{100 * fired / decided:.0f}% of DECIDED repositories")
    else:
        print("per-repo incidence: no repository was decided")
    if undetermined or failed:
        print(f"  not counted: {undetermined} undetermined (read budget), "
              f"{failed} unfetchable")

    print("\nThis is the number DRYDOCK_LENS_PLAN asked for on the cheapest of "
          "the six\nquestions. High incidence => a free static tier has "
          "something to say on most\napps. Three pinned repositories cannot "
          "decide that either way; widen the\ncorpus with slug@sha arguments "
          "before drawing a line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
