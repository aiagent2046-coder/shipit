"""The decisions of the missing-error-boundary analyzer, asserted rather than hoped for.

Two groups matter more than the rest.

THE FOUR SHAPES THE UI GATE EXISTS FOR. The module's first version named them in
its own docstring as the reason the gate was "not optional", and fired on all
four, because its render-root test was a filename pattern that any `index.tsx`
satisfied. Its fixture used `src/Button.tsx` — the one library shape with no
index file — so the suite agreed with the code and reality did not. Each of the
four is a test here.

COVERAGE IS NOT A FINDING. An exhausted budget must produce NO finding and say
so out loud. The first version capped at 1200 files and fired anyway, reporting
a monorepo with a real `componentDidCatch` as having no error boundary.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.error_boundary import (
    COVERAGE_COMPLETE,
    COVERAGE_EXHAUSTED,
    MOUNT_NO,
    MOUNT_NOT_REACT,
    MOUNT_UNKNOWN,
    MOUNT_WORKSPACE,
    MOUNT_YES,
    scan_error_boundary,
)


def _zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


ROUTED_NEXT = {
    "package.json": '{"dependencies":{"next":"14","react":"18","react-dom":"18"}}',
    "app/layout.tsx": "export default function L({children}){return children}",
    "app/page.tsx": "export default function P(){return <div>hi</div>}",
}
ROUTED_SPA = {
    "package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
    "src/main.tsx": ("import {createRoot} from 'react-dom/client';"
                     "createRoot(el).render(<App/>)"),
    "src/App.tsx": "export default function App(){return <div/>}",
}


# --------------------------------------------------------------------------- #
# it fires where it should
# --------------------------------------------------------------------------- #

def test_a_routed_next_app_with_no_boundary_fires():
    scan = scan_error_boundary(_zip(ROUTED_NEXT))

    assert [f.rule_id for f in scan.findings] == ["missing-error-boundary"]
    assert scan.findings[0].severity == "high"
    assert scan.findings[0].category == "Frontend"
    assert scan.coverage == COVERAGE_COMPLETE


def test_a_mounted_spa_with_no_boundary_fires():
    scan = scan_error_boundary(_zip(ROUTED_SPA))

    assert len(scan.findings) == 1
    assert scan.findings[0].file == "src/main.tsx", (
        "the finding points at what mounts the app, which is where a boundary "
        "would go")


def test_one_finding_for_the_whole_repository():
    """The question is whether ANY boundary exists above the routes, so the
    answer is one finding or none. One per page would be a list of warnings
    about a single fact."""
    many_pages = dict(ROUTED_NEXT)
    for i in range(25):
        many_pages[f"app/section{i}/page.tsx"] = "export default ()=> <div/>"

    assert len(scan_error_boundary(_zip(many_pages)).findings) == 1


# --------------------------------------------------------------------------- #
# the four shapes the UI gate exists for — measured failures of version one
# --------------------------------------------------------------------------- #

LIB_PKG = '{"name":"ui-kit","dependencies":{"react":"18","react-dom":"18"}}'


def test_a_component_library_is_not_an_app():
    """`src/components/Button/index.tsx` is not a render root. Version one's
    pattern `(^|/)(src/)?(main|index|App)\\.(t|j)sx$` matched any index file at
    any depth, so every component library with an index barrel fired."""
    scan = scan_error_boundary(_zip({
        "package.json": LIB_PKG,
        "src/components/Button/index.tsx": "export const Button=()=> <button/>",
        "src/components/Card/index.tsx": "export const Card=()=> <div/>",
    }))

    assert scan.findings == []
    assert "nothing mounts an app" in scan.reason


def test_a_design_system_barrel_is_not_an_app():
    scan = scan_error_boundary(_zip({
        "package.json": LIB_PKG,
        "src/index.tsx": "export * from './components'",
    }))

    assert scan.findings == []


def test_react_email_templates_are_not_an_app():
    scan = scan_error_boundary(_zip({
        "package.json": ('{"dependencies":{"react":"18",'
                         '"@react-email/components":"0.0.1"}}'),
        "emails/index.tsx": "export default () => <Html/>",
    }))

    assert scan.findings == [], (
        "an email template renders to a string on a server; there is no screen "
        "to go blank")


def test_a_nested_app_directory_in_a_docs_site_is_not_the_application():
    """`website/examples/app/demo/page.tsx` is an example inside a docs site.
    Version one anchored the app-router pattern with `(^|/)`, so any `app/`
    segment at any depth counted as somebody's application."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"react":"18"}}',
        "website/examples/app/demo/page.tsx": "export default ()=> <div/>",
    }))

    assert scan.findings == []


# --------------------------------------------------------------------------- #
# anything that looks like a boundary buys silence
# --------------------------------------------------------------------------- #

def test_an_app_router_error_file_silences_it():
    scan = scan_error_boundary(_zip({
        **ROUTED_NEXT,
        "app/error.tsx": "'use client'; export default function E(){return null}",
    }))

    assert scan.findings == []
    assert "app-router error file" in scan.reason


def test_a_nested_error_file_silences_it():
    """A route-group error.tsx catches for its subtree. Nested is still a
    boundary, and a miss is the acceptable direction."""
    scan = scan_error_boundary(_zip({
        **ROUTED_NEXT,
        "app/(dashboard)/error.tsx": "export default function E(){return null}",
    }))

    assert scan.findings == []


def test_a_class_boundary_anywhere_silences_it():
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "src/Boundary.tsx": ("class B extends React.Component{"
                             "componentDidCatch(e){}}"),
    }))

    assert scan.findings == []
    assert "boundary token" in scan.reason


def test_get_derived_state_from_error_silences_it():
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "src/B.tsx": "class B{static getDerivedStateFromError(){}}",
    }))

    assert scan.findings == []


def test_the_library_in_dependencies_silences_it():
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "package.json": ('{"dependencies":{"react":"18","react-dom":"18",'
                         '"react-error-boundary":"4"}}'),
    }))

    assert scan.findings == []
    assert "react-error-boundary" in scan.reason


def test_an_error_boundary_element_silences_it():
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "src/App.tsx": "export default ()=> <ErrorBoundary><X/></ErrorBoundary>",
    }))

    assert scan.findings == []


def test_a_boundary_inside_node_modules_does_not_count():
    """Somebody else's dependency shipping a boundary says nothing about
    whether this app mounts one above its own routes."""
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "node_modules/dep/index.js": "componentDidCatch(){}",
    }))

    assert len(scan.findings) == 1


def test_a_non_react_repo_is_not_examined():
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"express":"4"}}',
        "server.js": "require('express')()",
    }))

    assert scan.findings == []
    assert scan.reason == "not a react/next app"


# --------------------------------------------------------------------------- #
# coverage — an exhausted budget is not an absence
# --------------------------------------------------------------------------- #

def _monorepo_with_a_real_boundary(icons: int) -> dict[str, str]:
    files = dict(ROUTED_NEXT)
    for i in range(icons):
        files[f"packages/icons/src/i{i:05d}.tsx"] = "export const I=()=> <svg/>"
    files["zz-last/Boundary.tsx"] = ("class B extends React.Component{"
                                     "componentDidCatch(e){}}")
    return files


def test_an_exhausted_budget_produces_no_finding(monkeypatch):
    """THE MEASURED FAILURE OF VERSION ONE, which capped at 1200 files and
    fired: a monorepo with a real componentDidCatch was told it had no error
    boundary.

    No finding, because we have no claim -- we stopped reading before we could
    have one. Not a finding with a caveat: a finding IS a claim.
    """
    monkeypatch.setattr("app.scan.error_boundary._MAX_SOURCE_FILES", 20)
    scan = scan_error_boundary(_zip(_monorepo_with_a_real_boundary(200)))

    assert scan.findings == []
    assert scan.coverage == COVERAGE_EXHAUSTED
    assert "undetermined" in scan.reason
    assert scan.files_read < scan.files_total


def test_the_byte_budget_also_stops_it(monkeypatch):
    """Two bounds, because a repository can be a few enormous files or many
    small ones and either shape can outrun the reader."""
    monkeypatch.setattr("app.scan.error_boundary._MAX_TOTAL_BYTES", 500)
    files = dict(ROUTED_NEXT)
    for i in range(40):
        files[f"src/big{i}.tsx"] = "// " + ("x" * 400)

    scan = scan_error_boundary(_zip(files))

    assert scan.findings == []
    assert scan.coverage == COVERAGE_EXHAUSTED


def test_a_boundary_found_before_the_budget_runs_out_is_still_conclusive(
        monkeypatch):
    """Silence is conclusive the moment a boundary is seen: nothing later in
    the walk could unsee it. Only ABSENCE needs the whole pass, which is the
    asymmetry `coverage` exists to record."""
    monkeypatch.setattr("app.scan.error_boundary._MAX_SOURCE_FILES", 5)
    files = {
        **ROUTED_SPA,
        "src/AAA_boundary.tsx": "class B{componentDidCatch(){}}",
    }
    for i in range(50):
        files[f"src/z{i:03d}.tsx"] = "export const Z=()=> <i/>"

    scan = scan_error_boundary(_zip(files))

    assert scan.findings == []
    assert scan.coverage == COVERAGE_COMPLETE, (
        "a positive signal does not need a complete walk to be trusted")


def test_a_complete_walk_says_so_on_a_clean_verdict():
    """The distinction has to be legible on the silent path too, or a caller
    cannot tell a clean result from an abandoned one."""
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "src/Boundary.tsx": "class B{componentDidCatch(){}}",
    }))

    assert scan.coverage == COVERAGE_COMPLETE
    assert scan.findings == []


# --------------------------------------------------------------------------- #
# mount — the denominator, which is a separate question from the finding
# --------------------------------------------------------------------------- #

def test_a_non_react_repo_is_not_in_the_denominator():
    """An incidence over "every repository somebody submitted" says nothing
    about a frontend tier. A Express server is not evidence that apps do or do
    not blank."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"express":"4"}}',
        "server.js": "require('express')()",
    }))

    assert scan.mount == MOUNT_NOT_REACT


def test_a_library_is_react_but_not_in_the_denominator_either():
    scan = scan_error_boundary(_zip({
        "package.json": LIB_PKG,
        "src/components/Button/index.tsx": "export const B=()=> <button/>",
    }))

    assert scan.mount == MOUNT_NO


def test_a_mounted_app_is_in_the_denominator_whether_or_not_it_fires():
    fires = scan_error_boundary(_zip(ROUTED_SPA))
    silent = scan_error_boundary(_zip({
        **ROUTED_NEXT,
        "app/error.tsx": "export default ()=> null",
    }))

    assert fires.mount == MOUNT_YES and fires.findings
    assert silent.mount == MOUNT_YES and not silent.findings, (
        "a router entry names the mount without reading a byte")


def test_an_early_boundary_leaves_the_mount_unknown():
    """The honest cost of the early exit. A boundary token ends the walk, so a
    render call later in it was never looked for — and a component library that
    ships an ErrorBoundary looks exactly like an app that has one. Counting
    those as apps would inflate the denominator with things never at risk, so
    they are counted separately instead of guessed."""
    scan = scan_error_boundary(_zip({
        "package.json": LIB_PKG,
        "src/AAA.tsx": "class B{componentDidCatch(){}}",
        "src/components/Button/index.tsx": "export const B=()=> <button/>",
    }))

    assert scan.findings == []
    assert scan.mount == MOUNT_UNKNOWN


def test_a_mount_seen_before_the_boundary_is_still_known():
    """The same early exit, when the walk happened to pass the mount first:
    then it IS known, and reporting it as undetermined would throw away a fact
    we hold."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
        "src/AAA_main.tsx": "createRoot(el).render(<App/>)",
        "src/BBB_boundary.tsx": "class B{componentDidCatch(){}}",
    }))

    assert scan.findings == []
    assert scan.mount == MOUNT_YES


# --------------------------------------------------------------------------- #
# the root layout is still the root layout under a group or a dynamic segment
# --------------------------------------------------------------------------- #

def test_a_locale_segment_root_layout_is_a_mount():
    """MEASURED on the 2026-09-01 corpus run. mckaywrigley/chatbot-ui and
    ixartz/Next-js-Boilerplate both put their root layout at
    `app/[locale]/layout.tsx`; the anchor required `app/layout.tsx` exactly, so
    neither was seen as an app. A Next.js app has no createRoot to fall back
    on, so a missed layout is a missed application — and the ones missed this
    way were the mature projects, which is the direction that quietly inflates
    any rate measured over what remains."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"next":"14","react":"18"}}',
        "src/app/[locale]/layout.tsx": "export default ({children})=> children",
        "src/app/[locale]/page.tsx": "export default ()=> <div/>",
    }))

    assert scan.mount == MOUNT_YES
    assert len(scan.findings) == 1


def test_a_route_group_root_layout_is_a_mount():
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"next":"14","react":"18"}}',
        "app/(marketing)/layout.tsx": "export default ({children})=> children",
    }))

    assert scan.mount == MOUNT_YES


def test_a_plain_nested_layout_is_still_not_the_root():
    """Only `(group)` and `[param]` segments pass. Admitting a plain segment
    would re-open the docs-site false positive the anchor exists to stop —
    `app/dashboard/layout.tsx` is a section, not the application's root, and
    `website/examples/app/` is not the application at all."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"react":"18"}}',
        "website/examples/app/demo/layout.tsx": "export default ()=> <div/>",
    }))

    assert scan.mount != MOUNT_YES
    assert scan.findings == []


# --------------------------------------------------------------------------- #
# workspaces — a monorepo is not "not a react app"
# --------------------------------------------------------------------------- #

def test_a_workspace_root_without_react_is_not_called_non_react():
    """MEASURED: `dubinc/dub` is a Next.js product and the run printed "not a
    react/next app" for it, after reading zero files, because its react lives
    in apps/web/package.json. That is a false statement in a report, and it
    removed one of the corpus's most mature applications from the denominator
    — silently, and in the direction that inflates the rate."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"private":true,"workspaces":["apps/*"]}',
        "apps/web/package.json": '{"dependencies":{"next":"14","react":"18"}}',
        "apps/web/app/layout.tsx": "export default ({children})=> children",
    }))

    assert scan.mount == MOUNT_WORKSPACE
    assert scan.findings == [], "not analyzed means no claim, in either direction"
    assert "not the root manifest" in scan.reason
    assert "apps/web/package.json" in scan.reason


def test_a_repository_with_no_react_anywhere_is_still_not_react():
    """The distinction has to cut both ways, or MOUNT_WORKSPACE just becomes
    the new place everything unclassifiable goes."""
    scan = scan_error_boundary(_zip({
        "package.json": '{"private":true,"workspaces":["packages/*"]}',
        "packages/cli/package.json": '{"dependencies":{"commander":"12"}}',
        "packages/cli/index.js": "console.log('hi')",
    }))

    assert scan.mount == MOUNT_NOT_REACT


def test_a_vendored_manifest_does_not_make_a_repository_a_workspace():
    scan = scan_error_boundary(_zip({
        "package.json": '{"dependencies":{"express":"4"}}',
        "node_modules/react/package.json": '{"dependencies":{"react":"18"}}',
        "server.js": "require('express')()",
    }))

    assert scan.mount == MOUNT_NOT_REACT


# --------------------------------------------------------------------------- #
# path handling
# --------------------------------------------------------------------------- #

def test_a_source_directory_whose_name_contains_build_is_still_read():
    """`"build/" in name` also excludes `src/rebuild/`, which is ordinary
    source. Excluding it silently drops files a boundary could be in — an error
    in the direction of accusing."""
    scan = scan_error_boundary(_zip({
        **ROUTED_SPA,
        "src/rebuild/Boundary.tsx": "class B{componentDidCatch(){}}",
    }))

    assert scan.findings == [], (
        "src/rebuild/ is source; only a path SEGMENT equal to build/ is output")


def test_a_single_root_archive_is_handled():
    """A GitHub zip wraps everything in <repo>-<sha>/. Stripping it wrongly is
    how service_role.py once reported every route clean."""
    wrapped = {f"myapp-abc123/{k}": v for k, v in ROUTED_NEXT.items()}

    scan = scan_error_boundary(_zip(wrapped))

    assert len(scan.findings) == 1
    assert scan.findings[0].file == "app/layout.tsx"


def test_a_wrapped_archive_still_finds_its_boundary():
    wrapped = {f"myapp-abc123/{k}": v for k, v in ROUTED_NEXT.items()}
    wrapped["myapp-abc123/app/error.tsx"] = "export default ()=> null"

    assert scan_error_boundary(_zip(wrapped)).findings == []
