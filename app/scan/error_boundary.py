"""The screen goes blank: a React/Next app with no error boundary above its routes.

Question 1 of the frontend rubric in app/scan/llm_scan.py, lifted out of the
model and settled by reading lines — which the rubric itself says is all it
takes: *"No error boundary anywhere above the routes, so one render error
replaces the whole app with a white page. In the Next.js app router an error.tsx
or global-error.tsx file is that boundary; if you see one, there is nothing to
report."* The severity is the rubric's: *"A missing error boundary above the
application's routes is high: it converts every other bug in the app into a
blank page."*

The first STATIC producer for the Frontend category, which app/scan/scoring.py
currently lists in LLM_ONLY_CATEGORIES. Wiring it into the pipeline and dropping
Frontend from that set is a scoring decision this module does not make; it
reports what it found and how much of the repository it managed to look at.

WHAT IT CLAIMS. A fact fully readable from the repository: this is a routed
React or Next application, and NO error-boundary mechanism appears anywhere in
its source — not an app-router error.tsx/global-error.tsx, not a class boundary
(getDerivedStateFromError / componentDidCatch), not react-error-boundary, not an
<ErrorBoundary> in the tree. It does NOT claim a specific render will throw; it
claims that when one does, nothing above the routes catches it.

PRECISION OVER RECALL. The finding fires only when BOTH halves hold: this is a
UI app that can blank, AND not one recognized boundary token exists outside
dependency and build directories. A custom boundary that avoids every standard
name is a MISS, not a false positive, and a miss is the acceptable direction: a
false "you have no boundary" on an app that has one is what makes a free tier's
list untrustworthy.

A RENDER ROOT IS A RENDER CALL, NOT A FILENAME. The first version of this module
decided "can this blank?" from path shapes, and one of them was
`(^|/)(src/)?(main|index|App)\\.(t|j)sx$` — which matches ANY `index.tsx` at any
depth. Measured against the four repository shapes this docstring names as the
reason the gate exists, it fired on 4 of 4:

    component library   src/components/Button/index.tsx  -> FIRED
    design system       src/index.tsx                    -> FIRED
    react-email         emails/index.tsx                 -> FIRED
    docs site           website/examples/app/demo/page.tsx -> FIRED

The gate that was "not optional" was not present. Its fixture used
`src/Button.tsx`, the one library shape with no index file, so the suite agreed
with the code and reality did not. A name cannot carry this: "can go blank"
is a property of mounting an app, so the signal is the mount — `createRoot(`,
`ReactDOM.render(`, `hydrateRoot(` — or a ROOT-level router entry
(`app/layout.*`, `src/app/layout.*`, `pages/_app.*`), which is the file an
`error.tsx` sits beside.

AN EXHAUSTED BUDGET IS NOT AN ABSENCE, and this is the reason for `coverage`.
Reading every file of a large monorepo to find one token is not free, so the
sweep is bounded. When the bound is reached before a boundary is found, we do
not know whether one exists — so no finding is emitted AND `coverage` says
`budget_exhausted`. Measured on the first version, which capped at 1200 files
and fired anyway: a monorepo with a real `componentDidCatch` and 1400 icon
components was reported as having no error boundary.

That is the same defect class as `assets_read` in app/proof/served_bundle.py,
where a fetch we never made had to be distinguishable from a fetch that found
nothing — and it is why `coverage` is a field beside the findings rather than a
finding of its own. A "we did not finish looking" finding would carry a
SEVERITY_WEIGHT and deduct from the Frontend subscore, and scoring.py already
holds the rule this would break: a number nothing measured must not vote on the
total.

WHAT BUYS SILENCE, so a real boundary is never called missing:
  * an app-router error file — basename error.tsx/.jsx/.ts/.js or
    global-error.* under an app/ tree;
  * a class boundary — getDerivedStateFromError or componentDidCatch anywhere;
  * the react-error-boundary library — in dependencies or imported;
  * an <ErrorBoundary ...> element or Sentry.ErrorBoundary in the tree.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from typing import BinaryIO

from app.scan.checks import CheckFinding, archive_root

# Matched on PATH SEGMENTS, never as substrings. `"build/" in name` also
# excludes `src/rebuild/`, which is ordinary source, and excluding it silently
# removes files a boundary could have been in -- an error in the direction of
# accusing.
_SKIP_DIRS = frozenset((
    "node_modules", ".git", "dist", ".next", "build", "out",
    "venv", ".venv", "coverage", "storybook-static", "__pycache__",
))
_SOURCE_SUFFIXES = (".tsx", ".jsx", ".ts", ".js", ".mjs", ".cjs")

# Any one of these, anywhere in source, means a boundary exists.
_BOUNDARY_TOKENS = (
    "getDerivedStateFromError",   # class boundary, the React-official signal
    "componentDidCatch",          # class boundary
    "react-error-boundary",       # the library, imported
    "<ErrorBoundary",             # the library's / any component's element
    "Sentry.ErrorBoundary",       # @sentry/react boundary
    "captureRemixErrorBoundary",  # remix
)

# Mounting an app is what makes a blank page possible. A component library
# exports components and never calls these.
_RENDER_CALLS = ("createRoot(", "ReactDOM.render(", "hydrateRoot(",
                 "ReactDOM.hydrate(")

# The reading budget. Generous, because being wrong here is expensive in both
# directions: too small and large repositories come back undetermined, too
# large and one audit reads a monorepo end to end.
_MAX_SOURCE_FILES = 4000
_MAX_TOTAL_BYTES = 24_000_000
_MAX_FILE_BYTES = 400_000

COVERAGE_COMPLETE = "complete"
COVERAGE_EXHAUSTED = "budget_exhausted"

# What kind of thing this repository is, which is the DENOMINATOR question. An
# incidence over "every repository somebody submitted" answers nothing about a
# frontend tier: most of them are not React apps at all, and a library that
# cannot go blank is not evidence that apps do not blank either.
#
# MOUNT_UNKNOWN is not squeamishness. Finding a boundary token ends the walk --
# correctly, since nothing later could unsee it -- and if no mount was seen in
# the files read before it, we genuinely do not know whether this is an app or a
# component library that ships a boundary. Counting those as apps would inflate
# the denominator with things that were never at risk.
MOUNT_YES = "mounted"
MOUNT_NO = "no_mount"
MOUNT_NOT_REACT = "not_react"
MOUNT_UNKNOWN = "undetermined"

# A ROOT-level router entry: the file an app-router error.tsx sits beside.
# Anchored at the start of the (root-stripped) path, so `website/examples/app/`
# in a docs repository is not somebody's application.
_ROOT_APP_LAYOUT = re.compile(r"^(src/)?app/layout\.(t|j)sx?$")
_ROOT_PAGES_APP = re.compile(r"^(src/)?pages/(_app|index)\.(t|j)sx?$")

# An app-router error boundary file, anywhere under an app/ tree: a nested
# error.tsx still catches for its subtree, and any of them buys silence.
_APP_ERROR_FILE = re.compile(r"(^|/)app/(.*/)?(error|global-error)\.(t|j)sx?$")


@dataclass(frozen=True)
class BoundaryScan:
    """What was found, and how much of the repository was actually read.

    `coverage` is not decoration. `findings == []` with
    `coverage == COVERAGE_EXHAUSTED` means "we stopped looking", and a caller
    that renders it the same as `COVERAGE_COMPLETE` is telling somebody their
    app is fine on the strength of a budget limit. There is no convenience
    wrapper returning only the findings, deliberately: dropping this field has
    to be something a caller writes down.
    """
    findings: list[CheckFinding] = field(default_factory=list)
    coverage: str = COVERAGE_COMPLETE
    # One phrase naming the signal that decided it, so a verdict is
    # accountable without re-deriving it somewhere else.
    reason: str = ""
    # Whether this repository is a thing that can go blank -- the denominator
    # for any incidence measured with this analyzer. See the MOUNT_* constants.
    mount: str = MOUNT_UNKNOWN
    files_read: int = 0
    files_total: int = 0


def _norm(names: list[str]) -> list[str]:
    root = archive_root(names)
    if not root:
        return [n for n in names if not n.endswith("/")]
    return [n[len(root):] for n in names if n != root and not n.endswith("/")]


def _is_source(name: str) -> bool:
    parts = name.split("/")
    if any(p in _SKIP_DIRS for p in parts[:-1]):
        return False
    return name.endswith(_SOURCE_SUFFIXES)


def _read_package_json(zf: zipfile.ZipFile, root: str) -> dict:
    """The root package.json's parsed contents, or {}.

    A nested manifest under `apps/*` or `packages/*` is not the application's
    root manifest and is not read: in a workspace the root file is what
    describes the deployed app. The cost is a miss on monorepos that keep no
    root dependencies, which is the acceptable direction.
    """
    target = root + "package.json" if root else "package.json"
    try:
        raw = zf.read(target)
    except KeyError:
        return {}
    try:
        return json.loads(raw[:_MAX_FILE_BYTES].decode("utf-8", errors="ignore"))
    except ValueError:
        return {}


def _all_deps(pkg: dict) -> dict:
    deps: dict = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        val = pkg.get(key)
        if isinstance(val, dict):
            deps.update(val)
    return deps


def _router_entry(files: list[str]) -> str:
    """A root-level router entry, or "". Names only — no contents needed."""
    for name in files:
        if _ROOT_APP_LAYOUT.search(name):
            return name
        if _ROOT_PAGES_APP.search(name):
            return name
    return ""


def scan_error_boundary(fileobj: BinaryIO) -> BoundaryScan:
    """At most one `missing-error-boundary` finding for the whole repository.

    Whole-repo by nature: the question is whether ANY boundary exists above the
    routes, so the answer is one finding or none, never one per file.

    ONE PASS ANSWERS BOTH QUESTIONS. "Is there a boundary?" and "is this a
    mounted app rather than a library?" are both settled by tokens in source,
    so the sweep collects both and stops early on the one signal that is
    conclusive on its own — a boundary token, which means silence whatever else
    is true. Absence is never conclusive until the pass finishes, which is what
    `coverage` reports.
    """
    with zipfile.ZipFile(fileobj) as zf:
        raw_names = zf.namelist()
        root = archive_root(raw_names)
        files = _norm(raw_names)

        deps = _all_deps(_read_package_json(zf, root))
        if not ({"react", "react-dom", "next"} & set(deps)):
            return BoundaryScan(reason="not a react/next app",
                                mount=MOUNT_NOT_REACT, files_total=len(files))

        # Names settle two things without reading a byte, and one of them is
        # conclusive silence.
        entry = _router_entry(files)
        # A name-only silence cannot see a render call, so the mount is known
        # only when a router entry named it.
        named_mount = MOUNT_YES if entry else MOUNT_UNKNOWN

        if "react-error-boundary" in deps:
            return BoundaryScan(reason="react-error-boundary in dependencies",
                                mount=named_mount, files_total=len(files))
        for name in files:
            if _APP_ERROR_FILE.search(name):
                return BoundaryScan(reason=f"app-router error file: {name}",
                                    mount=named_mount, files_total=len(files))

        source = [n for n in files if _is_source(n)]
        read = 0
        total_bytes = 0
        render_call_in = ""
        exhausted = False

        for name in source:
            if read >= _MAX_SOURCE_FILES or total_bytes >= _MAX_TOTAL_BYTES:
                exhausted = True
                break
            try:
                body = zf.read(root + name if root else name)
            except KeyError:
                continue
            read += 1
            total_bytes += min(len(body), _MAX_FILE_BYTES)
            text = body[:_MAX_FILE_BYTES].decode("utf-8", errors="ignore")
            if any(tok in text for tok in _BOUNDARY_TOKENS):
                # Conclusive on its own: a boundary exists, and nothing later
                # in the walk could change that.
                return BoundaryScan(
                    coverage=COVERAGE_COMPLETE,
                    reason=f"boundary token in {name}",
                    # The walk stopped here, so a mount later in it was never
                    # looked for. Known only if something already named one.
                    mount=(MOUNT_YES if (entry or render_call_in)
                           else MOUNT_UNKNOWN),
                    files_read=read, files_total=len(files))
            if not render_call_in and any(c in text for c in _RENDER_CALLS):
                render_call_in = name

    if exhausted:
        # We do not know whether a boundary exists, so we do not say. NOT a
        # finding with a caveat -- a finding is a claim, and we have none.
        return BoundaryScan(
            coverage=COVERAGE_EXHAUSTED,
            reason=(f"stopped after {read} of {len(source)} source files; "
                    "whether a boundary exists is undetermined"),
            mount=(MOUNT_YES if (entry or render_call_in) else MOUNT_UNKNOWN),
            files_read=read, files_total=len(files))

    render_root = entry or render_call_in
    if not render_root:
        return BoundaryScan(
            reason="react present but nothing mounts an app (library/embedded)",
            mount=MOUNT_NO, files_read=read, files_total=len(files))

    return BoundaryScan(
        findings=[CheckFinding(
            rule_id="missing-error-boundary",
            title="No error boundary above the app's routes",
            severity="high",
            # The fact -- no boundary token in a mounted react/next app -- is
            # certain over what was read. The residual doubt is whether a
            # boundary exists under a name nobody uses.
            confidence=0.8,
            category="Frontend",
            file=render_root,
            explanation=(
                "Your app has no error boundary above its pages. In React, when "
                "any single component hits an error while rendering, there is "
                "nothing to contain it — so instead of one broken section, the "
                "entire app is replaced with a blank white page, and the person "
                "using it has no way forward except to reload and hope. One "
                "small bug anywhere becomes a total outage of the screen."
            ),
            fix_hint=(
                "Add an error boundary above your routes so a render error shows "
                "a fallback instead of a blank page. In the Next.js app router, "
                "create an app/error.tsx (and app/global-error.tsx for the root "
                "layout). In a plain React app, wrap your top-level component in "
                "an <ErrorBoundary> — the react-error-boundary package gives you "
                "one — with a small fallback that offers a reload."
            ),
        )],
        reason=f"mounted at {render_root}, no boundary token in {read} files",
        mount=MOUNT_YES, files_read=read, files_total=len(files))
