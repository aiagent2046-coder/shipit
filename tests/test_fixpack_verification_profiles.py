import io
import zipfile
from dataclasses import FrozenInstanceError

import pytest

from app.fixpack.verification import (
    VerificationReport,
    VerificationStage,
    detect_verification_profile,
)


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, text in entries.items():
            archive.writestr(
                f"customer-repo-deadbeef/{name}",
                text,
            )

    return buffer.getvalue()


def test_detects_nextjs_typecheck_build_and_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "next build",
                    "test": "jest"
                  },
                  "dependencies": {
                    "next": "15.0.0"
                  },
                  "devDependencies": {
                    "typescript": "5.7.0"
                  }
                }
                """,
                "package-lock.json": "{}",
                "tsconfig.json": "{}",
                "app/page.tsx": "export default function Page() { return null }",
            }
        )
    )

    assert profile is not None
    assert profile.ecosystem == "node"
    assert profile.framework == "nextjs"
    assert profile.install_command.startswith("npm ci")

    assert [step.name for step in profile.steps] == [
        "typecheck",
        "build",
        "tests",
    ]

    assert profile.steps[0].command == "npx --no-install tsc --noEmit"
    assert profile.steps[0].required is True
    assert profile.steps[1].command == "npm run build"
    assert profile.steps[1].required is True
    assert profile.steps[2].required is False


def test_prefers_explicit_node_typecheck_script():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "typecheck": "tsc --noEmit",
                    "build": "next build"
                  },
                  "dependencies": {
                    "next": "15.0.0"
                  }
                }
                """,
                "tsconfig.json": "{}",
            }
        )
    )

    assert profile is not None
    assert profile.steps[0].command == "npm run typecheck"


def test_detects_vite_build_without_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """,
                "src/main.jsx": "console.log('ok')",
            }
        )
    )

    assert profile is not None
    assert profile.framework == "vite"
    assert [step.name for step in profile.steps] == ["build"]
    assert profile.steps[0].required is True


def test_node_default_test_stub_is_not_added():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build",
                    "test": "echo \\"Error: no test specified\\" && exit 1"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """
            }
        )
    )

    assert profile is not None
    assert [step.name for step in profile.steps] == ["build"]


def test_detects_fastapi_compile_import_and_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "fastapi==0.116.0\nuvicorn==0.35.0\n",
                "app/main.py": """
from fastapi import FastAPI

app: FastAPI = FastAPI()
                """,
                "tests/test_health.py": """
def test_health():
    assert True
                """,
            }
        )
    )

    assert profile is not None
    assert profile.ecosystem == "python"
    assert profile.framework == "fastapi"

    assert [step.name for step in profile.steps] == [
        "compile",
        "import",
        "tests",
    ]

    assert "compileall" in profile.steps[0].command
    assert "from app.main import app" in profile.steps[1].command
    assert "pytest" in profile.steps[2].command

    assert profile.steps[0].required is True
    assert profile.steps[1].required is True
    assert profile.steps[2].required is False


def test_fastapi_without_detectable_app_still_gets_compile_profile():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "fastapi\n",
                "service/factory.py": """
from fastapi import FastAPI

def create_app():
    return FastAPI()
                """,
            }
        )
    )

    assert profile is not None
    assert profile.framework == "fastapi"
    assert [step.name for step in profile.steps] == ["compile"]


def test_plain_node_project_is_not_claimed_as_supported():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "test": "node --test"
                  }
                }
                """
            }
        )
    )

    assert profile is None


def test_plain_python_project_is_not_claimed_as_fastapi():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "flask\n",
                "app.py": "print('hello')\n",
            }
        )
    )

    assert profile is None


def test_report_contract_is_immutable():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """
            }
        )
    )

    assert profile is not None

    stage = VerificationStage(
        name="build",
        status="passed",
        command="npm run build",
        exit_code=0,
        duration_ms=125,
    )

    report = VerificationReport(
        profile=profile,
        original=(stage,),
        patched=(stage,),
        regression=False,
        deliverable=True,
        detail="no build regression",
    )

    assert report.deliverable is True

    with pytest.raises(FrozenInstanceError):
        report.deliverable = False


# --- workspaces / monorepos ---
#
# _node_profile read only the root package.json, so dubinc/dub produced no
# profile at all: its root manifest is a turborepo one, with no dependencies
# and `"build": "turbo build"`. Every Fix Pack for it fell back to the
# semantic check -- the weaker guarantee, on the product that is paid for.

MONOREPO_ROOT = """
{
  "name": "monorepo",
  "private": true,
  "packageManager": "pnpm@9.15.9",
  "scripts": {"build": "turbo build"},
  "devDependencies": {"eslint": "9"}
}
"""

MEMBER_NEXT = """
{
  "name": "web",
  "scripts": {"build": "next build", "test": "jest"},
  "dependencies": {"next": "15.0.0"}
}
"""


def test_a_workspace_member_supplies_the_profile():
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert profile is not None
    assert profile.framework == "nextjs"
    commands = {step.name: step.command for step in profile.steps}
    assert commands["build"] == "pnpm --filter web run build"
    assert commands["tests"] == "pnpm --filter web run test"


def test_pnpm_is_installed_through_corepack():
    """node:20-slim ships corepack with the shims uninstalled, so `pnpm` is
    not on PATH until it is enabled. Without this the install fails with
    "pnpm: not found", which reads as a broken repository."""
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert profile.install_command == (
        "corepack enable && pnpm install --frozen-lockfile"
    )


def test_a_single_app_repository_is_untouched():
    """The regression guard, asserted on the exact strings. Every repository
    that verifies today must keep running the identical commands -- including
    bare `npm test` rather than `npm run test`."""
    profile = detect_verification_profile(make_zip({
        "package.json": """
        {"scripts": {"build": "next build", "test": "jest"},
         "dependencies": {"next": "15.0.0"}}
        """,
        "package-lock.json": "{}",
        "tsconfig.json": "{}",
    }))

    assert profile.install_command == "npm ci --no-audit --no-fund"
    commands = {step.name: step.command for step in profile.steps}
    assert commands["typecheck"] == "npx --no-install tsc --noEmit"
    assert commands["build"] == "npm run build"
    assert commands["tests"] == "npm test"


def test_typecheck_runs_inside_the_member_not_from_the_root():
    """pnpm and yarn install a member's devDependencies under that member, so
    typescript sits in apps/web/node_modules/.bin and not on the root's PATH.
    `npx --no-install tsc` from the root fails with "tsc not found"."""
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
        "apps/web/tsconfig.json": "{}",
    }))

    commands = {step.name: step.command for step in profile.steps}
    assert commands["typecheck"] == "pnpm --filter web exec tsc --noEmit"


def test_a_root_app_still_wins_over_a_member():
    profile = detect_verification_profile(make_zip({
        "package.json": """
        {"scripts": {"build": "vite build"}, "dependencies": {"vite": "5"}}
        """,
        "apps/docs/package.json": MEMBER_NEXT,
    }))

    assert profile.framework == "vite"


def test_the_declared_package_manager_beats_the_lockfile():
    """A repository can carry a stale lockfile from a previous manager. Its
    own packageManager field is the answer it gives about itself."""
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,          # declares pnpm
        "package-lock.json": "{}",              # left over from npm
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert profile.install_command.startswith("corepack enable && pnpm")


def test_yarn_berry_and_yarn_classic_take_different_install_flags():
    """`--frozen-lockfile` was removed in Yarn 2; `--immutable` does not exist
    in Yarn 1. Guessing either way fails the install on half the repositories."""
    berry = detect_verification_profile(make_zip({
        "package.json": '{"name":"m","packageManager":"yarn@4.1.0"}',
        "yarn.lock": "",
        "apps/web/package.json": MEMBER_NEXT,
    }))
    classic = detect_verification_profile(make_zip({
        "package.json": '{"name":"m","packageManager":"yarn@1.22.19"}',
        "yarn.lock": "",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert berry.install_command == "corepack enable && yarn install --immutable"
    assert classic.install_command == (
        "corepack enable && yarn install --frozen-lockfile"
    )


def test_npm_workspaces_are_addressed_with_the_workspace_flag():
    profile = detect_verification_profile(make_zip({
        "package.json": '{"name":"m","workspaces":["apps/*"]}',
        "package-lock.json": "{}",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    commands = {step.name: step.command for step in profile.steps}
    assert commands["build"] == "npm run build --workspace web"
    assert profile.install_command == "npm ci --no-audit --no-fund"


def test_a_vendored_dependency_manifest_is_not_mistaken_for_the_app():
    """node_modules/next/package.json sits at exactly the depth a workspace
    member does, and building a profile for it would verify somebody else's
    package."""
    profile = detect_verification_profile(make_zip({
        "package.json": '{"name":"root"}',
        "node_modules/next/package.json": MEMBER_NEXT,
    }))

    assert profile is None


def test_a_member_without_a_name_is_refused_rather_than_run_at_the_root():
    """Nothing can address it with --filter. Falling back to the whole-repo
    commands would run the root's `turbo build`, which is not this app, and
    report the result as a verified build of the patch."""
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "",
        "apps/web/package.json": '{"dependencies": {"next": "15.0.0"}}',
    }))

    assert profile is None


def test_the_member_search_has_a_floor():
    profile = detect_verification_profile(make_zip({
        "package.json": '{"name":"root"}',
        "a/b/c/package.json": MEMBER_NEXT,
    }))

    assert profile is None
