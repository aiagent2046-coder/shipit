"""From a missing error boundary to a delivered app/error.tsx -- and the seam
that proves the fix: the detector that raised the finding is silent on the tree
the Pack produced.

The generator and the analyzer are tested on their own. This is where a static
finding becomes a delivered fix, and where it would quietly become decorative:
a Fix Pack that writes a file that is not the boundary, or drops the SPA case
instead of handing the customer the two-line change.
"""

from __future__ import annotations

import io
import zipfile

from app.fixpack.generate import build_fixpack_plan
from app.scan.error_boundary import RULE_ID, scan_error_boundary


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _finding(file: str) -> dict:
    return {"rule_id": RULE_ID, "file": file, "line": 0,
            "title": "No error boundary above the app's routes",
            "category": "Frontend", "severity": "high", "confidence": 0.8,
            "context": "source", "fixpack_eligible": True}


NEXT_APP = {
    "proj/package.json": '{"dependencies":{"next":"14","react":"18","react-dom":"18"}}',
    "proj/app/layout.tsx": "export default function L({children}){return children}",
    "proj/app/page.tsx": "export default function P(){return <div>hi</div>}",
}

SPA = {
    "proj/package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
    "proj/src/main.tsx": "import {createRoot} from 'react-dom/client'; createRoot(x).render(<App/>)",
    "proj/src/App.tsx": "export default function App(){return <div/>}",
}


def test_app_router_gets_an_error_file():
    plan = build_fixpack_plan(make_zip(NEXT_APP), [_finding("app/layout.tsx")])
    assert "app/error.tsx" in plan.files
    assert "app/global-error.tsx" in plan.files  # covers the root layout too
    assert "'use client'" in plan.files["app/error.tsx"]
    # global-error must render its own html/body -- it replaces the root layout
    assert "<html>" in plan.files["app/global-error.tsx"]
    assert any(cf.rule_id == RULE_ID for cf in plan.config_fixes)
    assert plan.skipped == []


def test_js_app_router_gets_a_jsx_file_without_type_annotations():
    entries = {**NEXT_APP, "proj/src/app/layout.js": "export default ()=>null"}
    del entries["proj/app/layout.tsx"]
    del entries["proj/app/page.tsx"]
    entries["proj/src/app/page.js"] = "export default ()=>null"
    plan = build_fixpack_plan(make_zip(entries), [_finding("src/app/layout.js")])
    assert "src/app/error.jsx" in plan.files
    assert "src/app/global-error.jsx" in plan.files
    assert ": {" not in plan.files["src/app/error.jsx"]  # no TS type annotation
    assert ": {" not in plan.files["src/app/global-error.jsx"]


def test_spa_is_skipped_with_the_two_line_change_not_dropped():
    """The Pack does not rewrite a mount the customer wrote. The refusal is
    recorded -- with the analyzer's own fix_hint (the <ErrorBoundary> wrap) --
    because a skipped finding the buyer never sees reads as 'there was nothing
    else', the exact defect the RLS refusals were made to avoid."""
    plan = build_fixpack_plan(make_zip(SPA), [_finding("src/main.tsx")])
    assert plan.files == {} or "error.tsx" not in "".join(plan.files)
    assert len(plan.skipped) == 1
    assert plan.skipped[0].rule_id == RULE_ID
    assert "wrapping" in plan.skipped[0].reason


def test_an_existing_boundary_is_never_overwritten():
    entries = {**NEXT_APP, "proj/app/error.tsx": "export default ()=>null"}
    plan = build_fixpack_plan(make_zip(entries), [_finding("app/layout.tsx")])
    assert "app/error.tsx" not in plan.files
    assert len(plan.skipped) == 1
    assert "already exists" in plan.skipped[0].reason


def test_the_fix_makes_the_detector_go_silent():
    """The seam that matters: the delivered file resolves the finding. Run the
    analyzer on the tree with the generated error.tsx merged in, and it no
    longer fires -- the static before/after Drydock promises, no LLM."""
    before = scan_error_boundary(io.BytesIO(make_zip(NEXT_APP)))
    assert before.findings  # the finding exists to fix

    plan = build_fixpack_plan(make_zip(NEXT_APP), [_finding("app/layout.tsx")])
    patched = dict(NEXT_APP)
    for path, content in plan.files.items():
        patched[f"proj/{path}"] = content

    after = scan_error_boundary(io.BytesIO(make_zip(patched)))
    assert after.findings == []


def test_error_boundary_only_pack_names_what_it_adds():
    """When the boundary is the only change, the title says so -- not the old
    bland 'secure repository configuration', which mislabels a reliability fix
    as security and tells the customer nothing about what the PR does."""
    from app.fixpack.generate import render_pr_title
    plan = build_fixpack_plan(make_zip(NEXT_APP), [_finding("app/layout.tsx")])
    assert render_pr_title(plan) == (
        "Drydock Fix Pack: add the error boundary your app is missing")


def test_a_secret_pack_still_leads_with_rotation_when_a_boundary_is_added():
    """A boundary must never bump rotation out of the title: rotation is the
    half the customer must still do, and the title is the one line nobody
    scrolls past. Adding the boundary changes the body, not the headline.

    Built at the plan level: the title's priority is what changed here, and it
    is tested directly rather than through the secret fixer's file-location
    machinery, which is exercised in test_fixpack_generate."""
    from app.fixpack.generate import (ConfigFix, FixpackPlan, SecretFix,
                                      render_pr_title)
    plan = FixpackPlan(
        secret_fixes=[SecretFix(rule_id="stripe-live-key",
                                title="Hardcoded Stripe key", file="lib/db.ts",
                                env_var="STRIPE_SECRET_KEY",
                                rotate_where="Stripe dashboard")],
        config_fixes=[ConfigFix(rule_id=RULE_ID,
                                title="Error boundary above your routes",
                                detail="app/error.tsx")],
    )
    title = render_pr_title(plan)
    assert "rotate" in title
    assert "error boundary" not in title


def test_the_generated_boundary_reaches_the_patched_zip_the_gate_builds():
    """The verified-build gate compiles build_patched_zip(original, plan). If
    the boundary file were not in that zip at the path Next.js expects, the
    gate would build the unpatched tree and pass vacuously. It is placed under
    the repo's wrapper folder so `next build` finds it beside the layout."""
    from app.fixpack.semantic_check import build_patched_zip

    plan = build_fixpack_plan(make_zip(NEXT_APP), [_finding("app/layout.tsx")])
    patched = build_patched_zip(make_zip(NEXT_APP), plan)

    names = set(zipfile.ZipFile(io.BytesIO(patched)).namelist())
    assert "proj/app/error.tsx" in names        # under the wrapper, beside the layout
    assert "proj/app/global-error.tsx" in names


def test_the_generated_boundary_is_a_valid_next_component_shape():
    """A regression lock on the facts a real `next build` + `tsc --noEmit`
    confirmed in the sandbox (both exit 0, error.tsx and global-error.tsx
    together): each file is a Client Component (`'use client'`) with a default
    export taking Next's {error, reset} props, and global-error renders its own
    <html>/<body> because it replaces the root layout. Cheap shape checks stand
    in for the build so CI need not install Next; the build itself was run once
    by hand and must stay reproducible."""
    from app.fixpack.generate import (_ERROR_TSX, _ERROR_JSX,
                                      _GLOBAL_ERROR_TSX, _GLOBAL_ERROR_JSX)

    for src in (_ERROR_TSX, _ERROR_JSX):
        assert src.startswith("'use client'")
        assert "export default function Error(" in src
        assert "reset" in src and "error" in src
    for src in (_GLOBAL_ERROR_TSX, _GLOBAL_ERROR_JSX):
        assert src.startswith("'use client'")
        assert "export default function GlobalError(" in src
        # replaces the root layout, so it MUST bring its own document shell
        assert "<html>" in src and "<body" in src
    # the tsx variants carry Next's error type; the jsx variants carry no
    # TS annotation (it would fail to parse in a .jsx file)
    assert "Error & { digest?: string }" in _ERROR_TSX
    assert "Error & { digest?: string }" in _GLOBAL_ERROR_TSX
    for src in (_ERROR_JSX, _GLOBAL_ERROR_JSX):
        assert ": {" not in src and "digest" not in src


def test_the_boundary_goes_beside_the_layout_it_catches_for():
    """MEASURED on the 2026-09-01 corpus: chatbot-ui and ixartz keep their root
    layout at `app/[locale]/layout.tsx`. `error.tsx` only catches for the
    layout it sits beside, so an `app/error.tsx` there is outside that layout
    and catches nothing -- the Pack would ship a file that is not the boundary
    and title the PR as if it were."""
    entries = {
        "proj/package.json": '{"dependencies":{"next":"14","react":"18"}}',
        "proj/app/[locale]/layout.tsx": "export default ({children})=> children",
        "proj/app/[locale]/page.tsx": "export default ()=> <div/>",
    }
    plan = build_fixpack_plan(make_zip(entries), [_finding("app/[locale]/layout.tsx")])

    assert "app/[locale]/error.tsx" in plan.files
    # global-error replaces the ROOT layout, and Next.js reads it only at app/.
    assert "app/global-error.tsx" in plan.files
    assert "app/error.tsx" not in plan.files


def test_a_workspace_application_keeps_its_prefix():
    """`apps/web/app/layout.tsx` is an application inside a monorepo. The first
    version dropped everything before `app/` and wrote `app/error.tsx` at the
    repository root -- a directory that was not the application, so the file
    would have sat in the PR doing nothing."""
    entries = {
        "proj/package.json": '{"private":true,"workspaces":["apps/*"]}',
        "proj/apps/web/package.json": '{"dependencies":{"next":"14","react":"18"}}',
        "proj/apps/web/app/layout.tsx": "export default ({children})=> children",
    }
    plan = build_fixpack_plan(make_zip(entries), [_finding("apps/web/app/layout.tsx")])

    assert "apps/web/app/error.tsx" in plan.files
    assert "apps/web/app/global-error.tsx" in plan.files
    assert not any(p.startswith("app/") for p in plan.files)


def test_a_framework_label_is_skipped_not_placed():
    """The analyzer names a TanStack or Remix mount by a label, not a layout
    path. There is no app-router file to write there, and guessing one would
    put a Next.js artefact into a project that is not Next.js."""
    plan = build_fixpack_plan(make_zip(NEXT_APP),
                              [_finding("src/routes/ (TanStack Start)")])

    assert plan.files == {}
    assert len(plan.skipped) == 1
    assert "wrapping" in plan.skipped[0].reason
