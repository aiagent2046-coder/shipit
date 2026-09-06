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
`ReactDOM.render(`, `hydrateRoot(`, `ReactDOM.hydrate(` — or a ROOT-level router
entry (`app/layout.*` optionally under route groups and dynamic segments, or
`pages/_app.*`), which is the file an `error.tsx` sits beside.

A REPOSITORY CAN HOLD SEVERAL APPLICATIONS. A workspace root declares no react
of its own, and reading only that manifest reported `dubinc/dub` — a Next.js
product with its react in `apps/web/package.json` — as "not a react/next app"
after reading zero files. Six of the 41 repositories in the 2026-09-01 corpus
sat in that class, they skewed mature, and their absence is what left the
measured rate as an interval (61-94%) instead of a number. Each react package in
a workspace is now analyzed as the application it is, and each that lacks a
boundary gets its own finding: they are separate deployables that blank
separately, so one repository-level verdict would report an unprotected app as
fine because a sibling was protected.

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
from app.scan.secrets import is_non_production_path

# Matched on PATH SEGMENTS, never as substrings. `"build/" in name` also
# excludes `src/rebuild/`, which is ordinary source, and excluding it silently
# removes files a boundary could have been in -- an error in the direction of
# accusing.
_SKIP_DIRS = frozenset((
    "node_modules", ".git", "dist", ".next", "build", "out",
    "venv", ".venv", "coverage", "storybook-static", "__pycache__",
    # A boundary declared in a test or a story does not stand between a
    # visitor and a blank page. MEASURED 2026-09-04: khuepm/GeniusQA's desktop
    # package was silenced by
    # `packages/desktop/src/__tests__/utils/TestErrorBoundary.tsx` -- a fixture
    # built to be rendered BY a test, holding the app's only boundary token.
    "__tests__", "__mocks__", ".storybook", "cypress", "e2e",
))
_SOURCE_SUFFIXES = (".tsx", ".jsx", ".ts", ".js", ".mjs", ".cjs")

# THE DIRECTION OF THIS ERROR IS THE OPPOSITE OF THE SKIP LIST'S USUAL ONE, so
# the list is short on purpose. Skipping a file removes its power to SILENCE,
# which means a repository can start firing -- and a false finding costs more
# than a missed one for something a customer pays for. Only names where a
# boundary is almost certainly a fixture qualify: `Boundary.test.tsx` is a test
# OF a boundary, never the boundary an app mounts. A plain `test/` or `tests/`
# directory is deliberately NOT here -- some repositories keep real helpers
# there, and being wrong in that direction is the expensive one.
_TEST_FILE_MARKERS = (".test.", ".spec.", ".stories.")

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
# How much of a workspace's per-package detail one `reason` may carry. Spent in
# whole entries by _merge, never mid-name.
_MAX_REASON_CHARS = 400
_MAX_TOTAL_BYTES = 24_000_000
_MAX_FILE_BYTES = 400_000

# The finding this module emits, named once so the Fix Pack and the
# scanner set pin can import it rather than re-spell it.
RULE_ID = "missing-error-boundary"

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
#
# ROUTE GROUPS AND DYNAMIC SEGMENTS ARE STILL THE ROOT LAYOUT, and leaving them
# out cost three real applications in the 2026-09-01 corpus run:
# mckaywrigley/chatbot-ui and ixartz/Next-js-Boilerplate both put theirs at
# `app/[locale]/layout.tsx`, and neither was seen. A Next.js app has no
# createRoot to fall back on, so a missed layout means a missed app -- and the
# apps missed this way were the mature ones, which is the direction that
# quietly inflates any rate measured over what is left.
#
# Only `(group)` and `[param]` segments are allowed through. A plain segment
# would re-admit `website/examples/app/demo/` -- the docs-site false positive
# this anchor exists to stop.
_ROOT_APP_LAYOUT = re.compile(
    r"^(src/)?app/((\([^/]+\)|\[[^/]+\])/)*layout\.(t|j)sx?$")
_ROOT_PAGES_APP = re.compile(r"^(src/)?pages/(_app|index)\.(t|j)sx?$")

# FRAMEWORKS THAT OWN THE MOUNT. Next.js is not the only one where nobody
# writes createRoot: TanStack Start, Remix and Gatsby generate the entry, so
# their applications have no render call anywhere in the author's source and
# looked like libraries.
#
# MEASURED: Moscow2260/ai-productivity-hub, a Lovable-generated app in the
# 2026-09-01 corpus -- `.lovable/`, vite.config.ts, `"dev": "vite dev"`,
# src/routes/index.tsx -- was classified `no_mount` and dropped out of the
# denominator. It is exactly the population a free frontend tier is for, it has
# no error boundary at all, and it was not being counted.
#
# THE DEPENDENCY ALONE IS NOT ENOUGH, and pairing it with the routing directory
# is what keeps this from re-opening the library false positive: a package that
# merely depends on @tanstack/react-router is a consumer of it, while one that
# also carries a routes/ tree is an application built with it.
# MEASURED, 2026-09-04: `GC-CODER1/Karuna-Android` and
# `LuckyYaduvanshi5/Failed_Taska` carry `app/_layout.tsx` and no render call
# anywhere -- Expo Router writes the mount, exactly as the three above do. Both
# were classified `undetermined` and dropped out of the incidence denominator,
# which is the same defect that once cost `Moscow2260/ai-productivity-hub` its
# place. Note the underscore: `_ROOT_APP_LAYOUT` matches Next's `app/layout.tsx`
# and cannot match Expo's `app/_layout.tsx`, so the two conventions do not
# collide and the dependency gates this one anyway.
#
# NOT ADDED HERE, and deliberately: Expo Router has its OWN boundary
# convention -- a route file exporting `ErrorBoundary` -- which none of
# _BOUNDARY_TOKENS matches. All three Expo repositories in the corpus happen to
# be silenced by an existing token in their root layout, so recognising the
# mount does not make them fire, but an Expo app protected ONLY by that export
# would now be a false positive. How often that happens is unmeasured, so the
# token stays unwritten until it is measured rather than guessed.
_FRAMEWORK_MOUNTS = (
    ("@tanstack/react-start", re.compile(r"^(src/)?routes/"), "TanStack Start"),
    ("@tanstack/react-router", re.compile(r"^(src/)?routes/"), "TanStack Router"),
    ("@remix-run/react", re.compile(r"^app/routes/"), "Remix"),
    ("gatsby", re.compile(r"^src/pages/"), "Gatsby"),
    ("expo-router", re.compile(r"^(src/)?app/_layout\.(t|j)sx?$"), "Expo Router"),
)

# A ROOT-level app-router error boundary, anchored exactly like
# _ROOT_APP_LAYOUT: `error.tsx`/`global-error.tsx` beside the root layout,
# through route groups `(group)` and dynamic segments `[param]` only. A plain
# named segment (`app/settings/error.tsx`) is a NESTED boundary that catches
# only its own subtree -- not the root layout, not sibling routes -- so it does
# not answer this finding's question, the whole-app white page.
#
# Crediting any error file anywhere (the previous rule) would read an app
# protected in ONE route as fully covered. Route groups stay credited because
# they add no URL segment (`app/(dashboard)/error.tsx` is still root).
#
# This tightening is a CORRECTNESS change with NO measured effect: replayed
# over the three-strata corpus on identical commits it moved no verdict at all
# (DRYDOCK_LENS_PLAN.md, 2026-09-04). It forbids a false negative this corpus
# does not happen to contain -- a reason to keep the rule, never a claim that
# it caught something. Measured cases live in the plan rather than here, so
# this comment cannot go stale on the next corpus run.
#
# NUANCE, in a comment rather than the rule: even a root `error.tsx` does not
# catch a fault thrown in the root layout itself -- only `global-error.tsx`
# does. Both silence here, because the finding is "a boundary above the ROUTES"
# and a root error.tsx is one; the narrower root-layout gap is a separate,
# noisier finding that would need its own calibration before it may fire.
_ROOT_APP_ERROR = re.compile(
    r"^(src/)?app/((\([^/]+\)|\[[^/]+\])/)*(error|global-error)\.(t|j)sx?$")


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
    if any(marker in parts[-1] for marker in _TEST_FILE_MARKERS):
        return False
    return name.endswith(_SOURCE_SUFFIXES)


def _read_package_json(zf: zipfile.ZipFile, root: str) -> dict:
    """The root package.json's parsed contents, or {}.

    The first question only: is THIS directory an application. A workspace root
    usually declares no react at all, and `_workspace_packages` is what finds
    the applications inside it — see `scan_error_boundary`.
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


def _is_react(deps: dict) -> bool:
    return bool({"react", "react-dom", "next"} & set(deps))


def _workspace_packages(zf: zipfile.ZipFile, files: list[str],
                        root: str) -> list[tuple[str, dict]]:
    """`(directory, deps)` for every nested package that declares react.

    Only asked when the ROOT manifest declares none. Depth-bounded: `apps/web`,
    `packages/ui`, `frontend`, `web` are where a workspace puts its manifests,
    and walking deeper starts reading vendored copies.

    A monorepo can hold SEVERAL applications, and they are separate deployables
    that blank separately — so this returns all of them rather than the first.
    """
    out: list[tuple[str, dict]] = []
    for name in sorted(files):
        if not name.endswith("/package.json") or name.count("/") > 3:
            continue
        if is_non_production_path(name):
            continue
        if any(p in _SKIP_DIRS for p in name.split("/")[:-1]):
            continue
        try:
            raw = zf.read(root + name if root else name)
            pkg = json.loads(raw[:_MAX_FILE_BYTES].decode("utf-8", "ignore"))
        except (KeyError, ValueError):
            continue
        deps = _all_deps(pkg)
        if _is_react(deps):
            out.append((name[: -len("package.json")], deps))
    return out


def _router_entry(files: list[str], deps: dict) -> str:
    """A router entry that means an application, or "". Names only.

    Next.js and the pages router first, then the frameworks that generate the
    mount themselves — see _FRAMEWORK_MOUNTS for why the dependency has to be
    paired with the routing directory rather than trusted on its own.
    """
    for name in files:
        if _ROOT_APP_LAYOUT.search(name) or _ROOT_PAGES_APP.search(name):
            return name
    for dep, route_dir, label in _FRAMEWORK_MOUNTS:
        if dep not in deps:
            continue
        for name in files:
            if route_dir.search(name):
                head = name.split("/")
                where = "/".join(head[:2]) if head[0] == "src" else head[0]
                return f"{where}/ ({label})"
    return ""


@dataclass
class _Budget:
    """Reading allowance, SHARED across the packages of one repository.

    Per-package budgets would let a six-application monorepo cost six times a
    single app's worth of reading for one audit. The allowance is a property of
    what we are willing to spend on a repository, so it lives here and is spent
    down.
    """
    # default_factory, not a plain default: a plain one is evaluated when the
    # class is defined, which silently froze these at import and made the
    # budget untestable -- the tests that set the limits kept passing while
    # exercising the real 4000-file allowance instead.
    files_left: int = field(default_factory=lambda: _MAX_SOURCE_FILES)
    bytes_left: int = field(default_factory=lambda: _MAX_TOTAL_BYTES)
    read: int = 0

    def spent(self) -> bool:
        return self.files_left <= 0 or self.bytes_left <= 0

    def take(self, size: int) -> None:
        self.files_left -= 1
        self.bytes_left -= min(size, _MAX_FILE_BYTES)
        self.read += 1


def _finding(where: str, read: int) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="No error boundary above the app's routes",
        severity="high",
        # The fact -- no boundary token in a mounted react/next app -- is
        # certain over what was read. The residual doubt is whether a boundary
        # exists under a name nobody uses.
        confidence=0.8,
        category="Frontend",
        file=where,
        explanation=(
            "Your app has no error boundary above its pages. In React, when "
            "any single component hits an error while rendering, there is "
            "nothing to contain it — so instead of one broken section, the "
            "entire app is replaced with a blank white page, and the person "
            "using it has no way forward except to reload and hope. One small "
            "bug anywhere becomes a total outage of the screen."
        ),
        fix_hint=(
            "Add an error boundary above your routes so a render error shows a "
            "fallback instead of a blank page. In the Next.js app router, "
            "create an app/error.tsx (and app/global-error.tsx for the root "
            "layout). In a plain React app, wrap your top-level component in "
            "an <ErrorBoundary> — the react-error-boundary package gives you "
            "one — with a small fallback that offers a reload."
        ),
    )


def _analyze_package(zf: zipfile.ZipFile, root: str, prefix: str,
                     files: list[str], deps: dict,
                     budget: _Budget) -> BoundaryScan:
    """One application: the whole decision, on paths relative to `prefix`.

    `prefix` is "" for a single-package repository and `apps/web/` for one
    application inside a workspace. Everything the report names is prefixed
    back, so a finding points at a path that exists in the repository.

    ONE PASS ANSWERS BOTH QUESTIONS. "Is there a boundary?" and "is this a
    mounted app rather than a library?" are both settled by tokens in source,
    so the sweep collects both and stops early on the one signal conclusive on
    its own — a boundary token, which means silence whatever else is true.
    Absence is never conclusive until the pass finishes, which is what
    `coverage` reports.
    """
    entry = _router_entry(files, deps)
    # A name-only silence cannot see a render call, so the mount is known only
    # when a router entry named it.
    named_mount = MOUNT_YES if entry else MOUNT_UNKNOWN

    if "react-error-boundary" in deps:
        return BoundaryScan(reason=f"{prefix}: react-error-boundary in "
                                   "dependencies" if prefix else
                                   "react-error-boundary in dependencies",
                            mount=named_mount)
    for name in files:
        if _ROOT_APP_ERROR.search(name):
            return BoundaryScan(
                reason=f"root app-router error file: {prefix}{name}",
                mount=named_mount)

    source = [n for n in files if _is_source(n)]
    render_call_in = ""
    started = budget.read

    for name in source:
        if budget.spent():
            return BoundaryScan(
                coverage=COVERAGE_EXHAUSTED,
                reason=(f"stopped after {budget.read - started} of "
                        f"{len(source)} source files in {prefix or 'the repo'}; "
                        "whether a boundary exists is undetermined"),
                mount=(MOUNT_YES if (entry or render_call_in)
                       else MOUNT_UNKNOWN),
                files_read=budget.read - started)
        try:
            body = zf.read(root + prefix + name if root else prefix + name)
        except KeyError:
            continue
        budget.take(len(body))
        text = body[:_MAX_FILE_BYTES].decode("utf-8", errors="ignore")
        if any(tok in text for tok in _BOUNDARY_TOKENS):
            return BoundaryScan(
                coverage=COVERAGE_COMPLETE,
                reason=f"boundary token in {prefix}{name}",
                # The walk stopped here, so a mount later in it was never
                # looked for. Known only if something already named one.
                mount=(MOUNT_YES if (entry or render_call_in)
                       else MOUNT_UNKNOWN),
                files_read=budget.read - started)
        if not render_call_in and any(c in text for c in _RENDER_CALLS):
            render_call_in = name

    read = budget.read - started
    render_root = entry or render_call_in
    if not render_root:
        return BoundaryScan(
            reason=(f"react present in {prefix or 'the root manifest'} but "
                    "nothing mounts an app (library/embedded)"),
            mount=MOUNT_NO, files_read=read)

    where = render_root if "(" in render_root else prefix + render_root
    return BoundaryScan(
        findings=[_finding(where, read)],
        reason=f"mounted at {where}, no boundary token in {read} files",
        mount=MOUNT_YES, files_read=read)


def _merge(parts: list[tuple[str, BoundaryScan]], files_total: int
           ) -> BoundaryScan:
    """One verdict for a repository that holds several applications.

    A monorepo's applications are separate deployables, so each that lacks a
    boundary gets its own finding — that is not the "one finding per file" this
    module refuses, it is one per thing that can blank on its own.

    The aggregates take the WEAKER claim in every direction: mounted if any
    application mounts, undetermined coverage if ANY package ran out of budget,
    because "we found one and there may be more we did not read" is the honest
    state and reporting it as complete would hide the second half.
    """
    findings = [f for _, part in parts for f in part.findings]
    mounts = {part.mount for _, part in parts}
    if MOUNT_YES in mounts:
        mount = MOUNT_YES
    elif MOUNT_UNKNOWN in mounts:
        mount = MOUNT_UNKNOWN
    else:
        mount = MOUNT_NO
    coverage = (COVERAGE_EXHAUSTED
                if any(p.coverage == COVERAGE_EXHAUSTED for _, p in parts)
                else COVERAGE_COMPLETE)
    if len(parts) == 1:
        reason = parts[0][1].reason
    else:
        fired = sum(1 for _, p in parts if p.findings)
        # WHOLE ENTRIES OR NONE. Cutting the joined string at a character count
        # sliced a package name mid-word on a wide monorepo, and a clipped list
        # is indistinguishable from a short one -- the reader cannot tell
        # whether the packages they cannot see were reported or dropped. Fit
        # what fits, then say how many were left out.
        entries = [f"{d.rstrip('/')}: {p.reason}" for d, p in parts]
        shown: list[str] = []
        left_in_budget = _MAX_REASON_CHARS
        for entry in entries:
            # The first entry goes in whatever its length: one whole reason
            # beats a truncated one, and dropping all of them says less.
            if shown and len(entry) + 2 > left_in_budget:
                break
            shown.append(entry)
            left_in_budget -= len(entry) + 2
        omitted = len(entries) - len(shown)
        reason = (f"{len(parts)} workspace packages declare react; {fired} "
                  "without a boundary — " + "; ".join(shown)
                  + (f" …(+{omitted} more)" if omitted else ""))
    return BoundaryScan(findings=findings, coverage=coverage, reason=reason,
                        mount=mount,
                        files_read=sum(p.files_read for _, p in parts),
                        files_total=files_total)


def scan_error_boundary(fileobj: BinaryIO) -> BoundaryScan:
    """`missing-error-boundary` for a repository, one finding per application.

    Single-package repositories are the common case and take the first branch.
    A workspace whose root manifest declares no react is not "not a React app"
    — dubinc/dub is a Next.js product with its react in apps/web/package.json,
    and it was reported as non-React after reading zero files. Those packages
    are found and each is analyzed as the application it is.
    """
    with zipfile.ZipFile(fileobj) as zf:
        raw_names = zf.namelist()
        root = archive_root(raw_names)
        files = _norm(raw_names)
        budget = _Budget()

        deps = _all_deps(_read_package_json(zf, root))
        if _is_react(deps):
            part = _analyze_package(zf, root, "", files, deps, budget)
            return _merge([("", part)], len(files))

        packages = _workspace_packages(zf, files, root)
        if not packages:
            return BoundaryScan(
                reason=("no react in the root manifest or any nested one "
                        "within three levels"),
                mount=MOUNT_NOT_REACT, files_total=len(files))

        parts: list[tuple[str, BoundaryScan]] = []
        for directory, pkg_deps in packages:
            scoped = [n[len(directory):] for n in files
                      if n.startswith(directory) and n != directory]
            parts.append((directory, _analyze_package(
                zf, root, directory, scoped, pkg_deps, budget)))
        return _merge(parts, len(files))
