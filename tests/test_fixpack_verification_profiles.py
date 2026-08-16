import io
import os
import subprocess
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
    assert commands["build"].endswith("pnpm --filter web run build")
    assert commands["tests"].endswith("pnpm --filter web run test")


# No quote characters in the payload, deliberately. These commands interpolate
# `name` BARE -- `pnpm --filter {workspace} run build` -- so a name carrying a
# balanced pair of quotes is one shell word and proves nothing; the first draft
# of this test used one and a mutation that dropped the quoting survived it.
# A bare `;` is what actually separates commands here.
MEMBER_HOSTILE_NAME = """
{
  "name": "web; touch pwned; x",
  "scripts": {"build": "next build", "test": "jest"},
  "dependencies": {"next": "15.0.0"},
  "devDependencies": {"typescript": "5.7.0"}
}
"""


HOSTILE_ROOT = """
{
  "name": "monorepo",
  "private": true,
  "packageManager": "%s@1.2.3",
  "scripts": {"build": "turbo build"},
  "devDependencies": {"eslint": "9"}
}
"""


@pytest.mark.parametrize("manager", ["pnpm", "yarn", "npm"])
def test_a_workspace_name_is_a_shell_argument_not_shell_source(
        tmp_path, manager):
    """`name` is arbitrary text out of the client's package.json, and every
    command built from it is handed to `docker run ... sh -c <script>`.

    Run through a real sh with the managers stubbed out, because the question
    is what sh does with the string and only sh can answer it. The stub exits
    0, so a failure here means the smuggled command ran, not that pnpm is
    missing.

    All three managers, because each has its own way of naming a member and
    therefore its own interpolation -- with only pnpm covered, mutations that
    unquoted the yarn and npm branches both survived.
    """
    # The root's `packageManager` field, not a lockfile: _package_manager
    # reads the declared field first and MONOREPO_ROOT declares pnpm, so
    # parametrising the lockfile selected pnpm three times over and left the
    # yarn and npm branches untested -- their mutations survived.
    profile = detect_verification_profile(make_zip({
        "package.json": HOSTILE_ROOT % manager,
        "apps/web/package.json": MEMBER_HOSTILE_NAME,
        # tsconfig.json and no `typecheck` script is what routes the member
        # through _exec_command, the second family of commands the name lands
        # in. Without it only _script_command is exercised and half the sites
        # go untested -- a mutation dropping the quoting from `exec` survived
        # the first version of this test.
        "apps/web/tsconfig.json": "{}",
    }))
    assert profile is not None
    assert {step.name for step in profile.steps} >= {"typecheck", "build"}

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("pnpm", "corepack", "npm", "yarn", "npx"):
        stub = bin_dir / tool
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")

    for step in profile.steps:
        subprocess.run(["sh", "-c", step.command], cwd=tmp_path, env=env)

    assert not (tmp_path / "pwned").exists(), (
        "a workspace name ran a command of its own")


def test_an_ordinary_workspace_name_is_passed_through_unchanged():
    """Quoting must not rewrite the strings every verifying repository runs
    today: `@dub/utils` and `web` need no quotes and must not acquire any."""
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    commands = {step.name: step.command for step in profile.steps}
    assert commands["build"].endswith("pnpm --filter web run build")


def test_pnpm_is_put_on_path_before_every_command():
    """Pinned in full, because every character was established by running it
    in the sandbox's own flags rather than by reasoning.

    `corepack enable` alone dies with EROFS: its shims go to Node's global bin,
    on the read-only rootfs. `--install-directory` needs the directory to exist
    first (realpathSync). The shim dir and the download cache live in /work
    because each step is a separate container and only /work is carried over --
    the later ones have `--network none`, so nothing can be fetched there. And
    the prefix repeats per step because PATH does not survive between
    containers even though the directories do.
    """
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    prefix = (
        "mkdir -p /work/.shipit_bin"
        " && export COREPACK_HOME=/work/.shipit_corepack"
        " PATH=/work/.shipit_bin:$PATH"
        " && corepack enable --install-directory /work/.shipit_bin && "
    )

    assert profile.install_command == (
        prefix
        + "pnpm install --frozen-lockfile"
        + " --store-dir /work/.shipit_pnpm_store"
    )
    assert all(step.command.startswith(prefix) for step in profile.steps)


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
    assert commands["typecheck"].endswith("pnpm --filter web exec tsc --noEmit")


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

    assert "pnpm install --frozen-lockfile" in profile.install_command


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

    assert berry.install_command.endswith("yarn install --immutable")
    assert classic.install_command.endswith(
        "yarn install --frozen-lockfile --cache-folder /work/.shipit_yarn_cache"
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
    # npm needs no corepack, so an npm repository keeps the exact strings it
    # ran before any of this existed.
    assert "corepack" not in profile.install_command


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


def test_the_package_store_is_redirected_out_of_the_tmpfs():
    """Not a tidiness preference -- two independent failures.

    On dubinc/dub the default store (under HOME, which the sandbox points at
    the /tmp tmpfs) hit `ERR_PNPM_ENOSPC ... no space left on device` after
    about 800 of 2632 packages. And pnpm hard-links node_modules to the store,
    so a store on a tmpfs dies with its container and leaves the NEXT step --
    a separate `docker run` -- with dangling links. Install and build can only
    be two containers if the store is in the bind mount.
    """
    profile = detect_verification_profile(make_zip({
        "package.json": MONOREPO_ROOT,
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert "--store-dir /work/.shipit_pnpm_store" in profile.install_command
    # Beside node_modules, not under HOME.
    assert "/tmp" not in profile.install_command


def test_yarn_berry_needs_no_cache_redirect():
    """Berry caches in .yarn/cache inside the project, which is already in the
    bind mount. Adding --cache-folder there would be cargo-culted from Yarn 1,
    where the cache really is under HOME."""
    profile = detect_verification_profile(make_zip({
        "package.json": '{"name":"m","packageManager":"yarn@4.1.0"}',
        "yarn.lock": "",
        "apps/web/package.json": MEMBER_NEXT,
    }))

    assert "--cache-folder" not in profile.install_command
