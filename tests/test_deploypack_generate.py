"""Tests for Deploy Pack generation — deterministic, no LLM involved."""

import io
import pytest
import zipfile

import yaml

from app.deploypack.generate import (
    UnsupportedForDeployPack,
    extract_repo,
    generate_deploy_pack,
    read_all_files,
)
from app.ingest.stack_detect import Stack


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def test_read_all_files_strips_single_root_folder():
    buf = make_zip({
        "myapp/requirements.txt": b"fastapi\n",
        "myapp/app/main.py": b"x = 1\n",
    })
    files = read_all_files(buf)
    assert set(files) == {"requirements.txt", "app/main.py"}


def test_extract_repo_preserves_bytes_and_strips_root(tmp_path):
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20  # not valid text
    buf = make_zip({
        "myapp/requirements.txt": b"fastapi\n",
        "myapp/assets/logo.png": png_bytes,
    })
    extract_repo(buf, tmp_path)
    assert (tmp_path / "requirements.txt").read_bytes() == b"fastapi\n"
    assert (tmp_path / "assets/logo.png").read_bytes() == png_bytes


def test_extract_repo_skips_unsafe_paths(tmp_path):
    buf = make_zip({
        "myapp/requirements.txt": b"fastapi\n",
        "myapp/../../etc/evil": b"pwned",
    })
    extract_repo(buf, tmp_path)
    assert (tmp_path / "requirements.txt").exists()
    assert not (tmp_path.parent.parent / "etc" / "evil").exists()


# --- FastAPI ---

def test_fastapi_pack_pip_no_db():
    files = {
        "requirements.txt": "fastapi\nuvicorn\n",
        "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    }
    pack = generate_deploy_pack(Stack.FASTAPI, files)

    assert "pip install --no-cache-dir -r requirements.txt" in pack["Dockerfile"]
    assert "app.main:app" in pack["Dockerfile"]
    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert "db" not in compose["services"]
    assert compose["services"]["app"]["ports"] == ["8000:8000"]


def test_fastapi_pack_poetry_with_db():
    files = {
        "pyproject.toml": "[tool.poetry]\nname = 'x'\n\n[tool.poetry.dependencies]\nasyncpg = '*'\n",
        "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    }
    pack = generate_deploy_pack(Stack.FASTAPI, files)

    assert "poetry install" in pack["Dockerfile"]
    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert compose["services"]["db"]["image"] == "postgres:16-alpine"
    assert compose["services"]["app"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert "DATABASE_URL=" in pack[".env.example"]


def test_fastapi_entry_module_detected_from_custom_path_and_name():
    files = {
        "requirements.txt": "fastapi\n",
        "src/server.py": "server = FastAPI()\n",
    }
    pack = generate_deploy_pack(Stack.FASTAPI, files)
    assert '"src.server:server"' in pack["Dockerfile"]


def test_fastapi_ci_workflow_is_valid_yaml():
    files = {"requirements.txt": "fastapi\n", "app/main.py": "app = FastAPI()\n"}
    pack = generate_deploy_pack(Stack.FASTAPI, files)
    workflow = yaml.safe_load(pack[".github/workflows/deploy-pack-ci.yml"])
    assert workflow["jobs"]["build-and-boot"]["runs-on"] == "ubuntu-latest"


# --- Vite + React ---

def test_vite_pack_no_env_vars():
    files = {"package.json": '{"dependencies":{"react":"18","vite":"5"}}'}
    pack = generate_deploy_pack(Stack.VITE_REACT, files)

    assert "ARG VITE_" not in pack["Dockerfile"]
    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert "args" not in compose["services"]["app"]["build"]
    assert "try_files" in pack["nginx.conf"]


def test_vite_pack_detects_build_time_env_vars():
    files = {
        "package.json": '{"dependencies":{"react":"18","vite":"5"}}',
        "src/utils/supabase.ts": (
            "const url = import.meta.env.VITE_SUPABASE_URL\n"
            "const key = import.meta.env.VITE_SUPABASE_ANON_KEY\n"
        ),
    }
    pack = generate_deploy_pack(Stack.VITE_REACT, files)

    assert "ARG VITE_SUPABASE_URL" in pack["Dockerfile"]
    assert "ARG VITE_SUPABASE_ANON_KEY" in pack["Dockerfile"]
    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert compose["services"]["app"]["build"]["args"] == {
        "VITE_SUPABASE_ANON_KEY": "${VITE_SUPABASE_ANON_KEY}",
        "VITE_SUPABASE_URL": "${VITE_SUPABASE_URL}",
    }
    assert "VITE_SUPABASE_URL=" in pack[".env.example"]


def test_env_example_merge_keeps_existing_and_adds_new_keys_only():
    files = {
        "package.json": '{"dependencies":{"react":"18","vite":"5"}}',
        ".env.example": "VITE_SUPABASE_URL=https://already-there.example\n",
        "src/x.ts": "import.meta.env.VITE_SUPABASE_URL\nimport.meta.env.VITE_NEW_KEY\n",
    }
    pack = generate_deploy_pack(Stack.VITE_REACT, files)
    env = pack[".env.example"]
    assert "VITE_SUPABASE_URL=https://already-there.example" in env
    assert env.count("VITE_SUPABASE_URL") == 1
    assert "VITE_NEW_KEY=" in env


# --- Next.js ---

def _next_files(extra: dict[str, str] | None = None) -> dict[str, str]:
    files = {
        "package.json": '{"dependencies":{"next":"14.2.5","react":"18"}}',
        "next.config.js": 'module.exports = { output: "standalone" }\n',
        "pages/index.js": "export default function Home(){ return <div>ok</div> }\n",
    }
    files.update(extra or {})
    return files


def test_nextjs_pack_standalone_npm_no_lockfile():
    pack = generate_deploy_pack(Stack.NEXTJS, _next_files())
    df = pack["Dockerfile"]
    assert "RUN npm install" in df          # no lockfile -> install, not ci
    assert "npm run build" in df
    assert "COPY --from=build --chown=node:node /app/.next/standalone ./" in df
    assert "ENV HOSTNAME=0.0.0.0" in df     # the Docker-bind gotcha, fixed here
    assert "EXPOSE 3000" in df
    assert 'CMD ["node", "server.js"]' in df

    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert compose["services"]["app"]["ports"] == ["3000:3000"]
    assert "args" not in compose["services"]["app"]["build"]

    workflow = yaml.safe_load(pack[".github/workflows/deploy-pack-ci.yml"])
    assert workflow["jobs"]["build-and-boot"]["runs-on"] == "ubuntu-latest"


def test_nextjs_pack_detects_package_manager_from_lockfile():
    npm = generate_deploy_pack(Stack.NEXTJS, _next_files({"package-lock.json": "{}"}))
    assert "RUN npm ci" in npm["Dockerfile"]

    pnpm = generate_deploy_pack(Stack.NEXTJS, _next_files({"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"}))
    assert "corepack enable && pnpm install --frozen-lockfile" in pnpm["Dockerfile"]
    assert "pnpm run build" in pnpm["Dockerfile"]

    yarn = generate_deploy_pack(Stack.NEXTJS, _next_files({"yarn.lock": "# yarn lockfile v1\n"}))
    assert "corepack enable && yarn install --frozen-lockfile" in yarn["Dockerfile"]
    assert "yarn build" in yarn["Dockerfile"]


def test_nextjs_pack_wires_next_public_env_as_build_args():
    files = _next_files({
        "pages/index.js": (
            "const url = process.env.NEXT_PUBLIC_API_URL\n"
            "const key = process.env.NEXT_PUBLIC_ANON_KEY\n"
            "export default function Home(){ return <div>{url}{key}</div> }\n"
        ),
    })
    pack = generate_deploy_pack(Stack.NEXTJS, files)

    assert "ARG NEXT_PUBLIC_API_URL" in pack["Dockerfile"]
    assert "ARG NEXT_PUBLIC_ANON_KEY" in pack["Dockerfile"]
    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert compose["services"]["app"]["build"]["args"] == {
        "NEXT_PUBLIC_ANON_KEY": "${NEXT_PUBLIC_ANON_KEY}",
        "NEXT_PUBLIC_API_URL": "${NEXT_PUBLIC_API_URL}",
    }
    assert "NEXT_PUBLIC_API_URL=" in pack[".env.example"]


def test_nextjs_pack_refuses_without_output_standalone():
    # next.config present but standalone not set -> refuse (would build
    # green then fail to boot). Message must name the required setting.
    files = _next_files({"next.config.js": "module.exports = {}\n"})
    try:
        generate_deploy_pack(Stack.NEXTJS, files)
        assert False, "expected UnsupportedForDeployPack"
    except UnsupportedForDeployPack as exc:
        assert "standalone" in str(exc)

    # no next.config at all -> also refuse
    try:
        generate_deploy_pack(Stack.NEXTJS, {"package.json": '{"dependencies":{"next":"14"}}'})
        assert False, "expected UnsupportedForDeployPack"
    except UnsupportedForDeployPack:
        pass


# --- non-root preview containers ---
#
# SCOPE, stated plainly so these are not mistaken for more than they are: every
# test below reads the TEXT of a generated Dockerfile. None of them builds an
# image or starts a container, so none of them proves the app actually boots as a
# non-root uid -- only that the template asks for it. Real proof needs a
# `docker build` + `docker run` + `id -u`, which no pytest run here has a docker
# daemon for; that belongs in .github/workflows/e2e-sandbox-runner.yml.


def _last_start_directive_index(dockerfile: str) -> int:
    """Line index of the final CMD/ENTRYPOINT -- the process that runs untrusted
    client code, and therefore the line every USER must precede."""
    starts = [
        i for i, line in enumerate(dockerfile.splitlines())
        if line.startswith(("CMD ", "ENTRYPOINT "))
    ]
    assert starts, f"template has no CMD/ENTRYPOINT:\n{dockerfile}"
    return starts[-1]


def _user_line_indexes(dockerfile: str) -> list[int]:
    return [
        i for i, line in enumerate(dockerfile.splitlines())
        if line.startswith("USER ")
    ]


def test_nextjs_template_runs_as_node_not_root():
    """Template text only (see scope note above)."""
    df = generate_deploy_pack(Stack.NEXTJS, _next_files())["Dockerfile"]

    users = _user_line_indexes(df)
    assert users, f"no USER directive -- runtime stage would run as root:\n{df}"
    # `node` is built into node:20-slim (uid 1000), so no useradd step is needed.
    assert df.splitlines()[users[-1]] == "USER node"
    assert users[-1] < _last_start_directive_index(df)

    # Every runtime-stage COPY lands owned by node, or the unprivileged process
    # would be reading files it doesn't own.
    runtime = df.split("FROM node:20-slim AS run\n", 1)[1]
    copies = [ln for ln in runtime.splitlines() if ln.startswith("COPY ")]
    assert copies, "expected COPY lines in the runtime stage"
    assert all("--chown=node:node" in ln for ln in copies), copies


def test_fastapi_template_runs_as_numeric_nonroot_uid_after_install():
    """Template text only (see scope note above)."""
    df = generate_deploy_pack(Stack.FASTAPI, {
        "requirements.txt": "fastapi\nuvicorn\n",
        "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    })["Dockerfile"]

    users = _user_line_indexes(df)
    assert users, f"no USER directive -- container would run as root:\n{df}"
    # Numeric on purpose: python:3.12-slim ships no non-root account, and a
    # `useradd` step would depend on tooling a slim image needn't have.
    assert df.splitlines()[users[-1]] == "USER 1000:1000"
    assert users[-1] < _last_start_directive_index(df)
    assert "COPY --chown=1000:1000 . ." in df

    # pip must still install as root, into system paths: USER comes after every
    # install RUN, not before. Regression guard on the ordering specifically,
    # since a USER placed too early breaks the build rather than the runtime.
    lines = df.splitlines()
    install_runs = [i for i, ln in enumerate(lines) if ln.startswith("RUN pip ")]
    assert install_runs, f"expected a pip install step:\n{df}"
    assert max(install_runs) < users[-1]


def test_fastapi_poetry_variant_also_installs_as_root_then_drops():
    """Template text only. The poetry branch emits a different install block,
    so the USER-after-install ordering is asserted for it separately."""
    df = generate_deploy_pack(Stack.FASTAPI, {
        "pyproject.toml": "[tool.poetry]\nname = 'x'\n",
        "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    })["Dockerfile"]

    lines = df.splitlines()
    user_index = _user_line_indexes(df)[-1]
    poetry_runs = [i for i, ln in enumerate(lines) if "poetry install" in ln]
    assert poetry_runs, f"expected a poetry install step:\n{df}"
    assert max(poetry_runs) < user_index < _last_start_directive_index(df)


def test_vite_template_is_left_alone_and_still_unprivileged():
    """Regression guard: the Vite pack was ALREADY non-root before this change
    and must stay byte-identical in the ways that matter. It gets there through
    the base image (nginx-unprivileged runs as uid 101 and needs no USER line of
    its own), so adding one here would be wrong -- a USER 1000 would run nginx
    as a uid that owns none of its config or temp dirs.

    Template text only (see scope note above)."""
    df = generate_deploy_pack(
        Stack.VITE_REACT,
        {"package.json": '{"dependencies":{"react":"18","vite":"5"}}'},
    )["Dockerfile"]

    assert "FROM nginxinc/nginx-unprivileged:alpine" in df
    assert _user_line_indexes(df) == []
    assert "--chown" not in df
    # No CMD either: the unprivileged nginx image's own entrypoint serves.
    assert "CMD " not in df and "ENTRYPOINT " not in df


def test_no_generated_template_exposes_a_privileged_port():
    """The reason the old sandbox.py comment ("a generated app may bind a low
    port") is obsolete, pinned as a test: if a future template ever EXPOSEs
    below 1024 it would need root again, and this fails instead of silently
    reintroducing the conflict. Template text only."""
    packs = {
        "vite": generate_deploy_pack(
            Stack.VITE_REACT,
            {"package.json": '{"dependencies":{"react":"18","vite":"5"}}'},
        ),
        "nextjs": generate_deploy_pack(Stack.NEXTJS, _next_files()),
        "fastapi": generate_deploy_pack(Stack.FASTAPI, {
            "requirements.txt": "fastapi\n",
            "app/main.py": "app = FastAPI()\n",
        }),
    }
    for stack, pack in packs.items():
        ports = [
            int(ln.split()[1])
            for ln in pack["Dockerfile"].splitlines() if ln.startswith("EXPOSE ")
        ]
        assert ports, f"{stack} template EXPOSEs nothing"
        assert all(p >= 1024 for p in ports), (stack, ports)


# --- unsupported ---

def test_unsupported_stack_raises():
    try:
        generate_deploy_pack(Stack.UNSUPPORTED, {})
        assert False, "expected UnsupportedForDeployPack for UNSUPPORTED"
    except UnsupportedForDeployPack:
        pass


# --- .dockerignore (every stack) ---

@pytest.mark.parametrize("stack,files", [
    (Stack.FASTAPI, {"requirements.txt": "fastapi\n", "app/main.py": "app = 1\n"}),
    (Stack.VITE_REACT, {"package.json": '{"name":"x"}\n', "vite.config.js": "\n"}),
    (Stack.NEXTJS, _next_files()),
])
def test_pack_excludes_env_and_git_from_the_image(stack, files):
    """Every Dockerfile we hand out does COPY . ., so the build context is the
    image. A customer with an .env next to it would ship their credentials in
    a layer -- the exact thing the audit that preceded the pack warns about."""
    pack = generate_deploy_pack(stack, files)

    assert ".dockerignore" in pack, f"{stack} pack has no .dockerignore"
    lines = [ln.strip() for ln in pack[".dockerignore"].splitlines()]
    assert ".env" in lines
    assert ".env.*" in lines
    assert "!.env.example" in lines, "the example is documentation, not a secret"
    assert ".git" in lines, "history keeps deleted secrets alive in old objects"
    assert "node_modules" in lines


def test_dockerignore_does_not_starve_compose_of_its_env():
    """Excluding .env from the image is only safe because compose reads it from
    the host at run time. If that ever stops being true, this test should be
    the thing that notices."""
    files = {"requirements.txt": "fastapi\n", "app/main.py": "app = 1\n"}
    pack = generate_deploy_pack(Stack.FASTAPI, files)
    assert "env_file: [.env]" in pack["docker-compose.yml"]


# --- workspaces / monorepos ---
#
# detect_stack now names a monorepo's framework instead of calling it
# unsupported, which is truthful and moves the refusal here. Every template
# copies package.json from the archive root and builds in /app; a turborepo
# root manifest declares no framework and has no build for the application, so
# a Pack generated from it installs the wrong tree and produces an image that
# cannot boot. The module's own rule: worse than no Dockerfile, because it
# looks done.


def test_a_nextjs_monorepo_is_refused_rather_than_built_wrong():
    files = {
        "package.json": '{"name":"monorepo","workspaces":["apps/*"]}',
        "apps/web/package.json": '{"dependencies":{"next":"14"}}',
        "apps/web/next.config.js": 'module.exports = {output: "standalone"}',
    }

    with pytest.raises(UnsupportedForDeployPack) as caught:
        generate_deploy_pack(Stack.NEXTJS, files)

    assert "monorepo" in str(caught.value)


def test_the_monorepo_refusal_does_not_masquerade_as_a_standalone_problem():
    """The member app HAS output: "standalone". Blaming the config would send
    the user to add a line that is already there, and they would re-run and be
    refused again for a reason nobody named."""
    files = {
        "package.json": '{"name":"monorepo"}',
        "apps/web/next.config.js": 'module.exports = {output: "standalone"}',
    }

    with pytest.raises(UnsupportedForDeployPack) as caught:
        generate_deploy_pack(Stack.NEXTJS, files)

    assert "standalone" not in str(caught.value)


def test_a_vite_monorepo_is_refused():
    files = {
        "package.json": '{"name":"monorepo","workspaces":["apps/*"]}',
        "apps/site/package.json": '{"dependencies":{"react":"18","vite":"5"}}',
        "apps/site/vite.config.ts": "export default {}",
    }

    with pytest.raises(UnsupportedForDeployPack) as caught:
        generate_deploy_pack(Stack.VITE_REACT, files)

    assert "monorepo" in str(caught.value)


def test_a_root_app_is_still_built():
    """The refusal must key on where the app is, not on the word workspaces
    appearing somewhere. A single-app repository is unaffected."""
    files = {
        "package.json": '{"dependencies":{"next":"14"}}',
        "next.config.js": 'module.exports = {output: "standalone"}',
    }

    assert "Dockerfile" in generate_deploy_pack(Stack.NEXTJS, files)
