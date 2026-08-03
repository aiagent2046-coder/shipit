"""Deploy Pack — minimal scope (see shipit-go-to-market-plan.md, section 2).

Generates Dockerfile / docker-compose.yml / .dockerignore / .env.example
and a CI workflow
for a detected stack. Deterministic and template-based — no agents, no
LLM call. Three stacks:

  - fastapi:    WhiskyToad/fastapi-starter, kumarsonu676's starter
  - vite-react: what Lovable/Bolt actually export (4 of 6 test repos)
  - nextjs:     output:"standalone" builds (see _nextjs_pack)

Next.js support is gated on the app having `output: "standalone"` set in
its next.config — that mode produces the self-contained `server.js` the
generated image runs. Without it there is nothing to boot, so rather
than emit a Dockerfile that builds green and then fails to serve (worse
than none, see below), we refuse and tell the user exactly what to add.

Output correctness matters more than output existence: a generated
Dockerfile that builds but doesn't actually boot the app is worse than
no Dockerfile, because it looks done. Callers MUST run
app.deploypack.sandbox.verify_deploy_pack before treating a Pack as
complete.
"""

from __future__ import annotations

import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from app.ingest.stack_detect import Stack

_DB_MARKERS = re.compile(r"asyncpg|psycopg2|psycopg\b", re.I)
_VITE_ENV_VAR = re.compile(r"import\.meta\.env\.(VITE_[A-Z0-9_]+)")
_NEXT_PUBLIC_ENV_VAR = re.compile(r"process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)")
# output: "standalone" — the only next.config shape we can containerize
# into a minimal self-contained runtime. Tolerates single/double quotes
# and arbitrary spacing; deliberately not a full JS parser.
_NEXT_STANDALONE = re.compile(r"""output\s*:\s*['"]standalone['"]""")
_NEXT_CONFIG_NAMES = ("next.config.js", "next.config.mjs",
                      "next.config.cjs", "next.config.ts")


class UnsupportedForDeployPack(Exception):
    """Stack has no Deploy Pack template yet."""


def read_all_files(fileobj: BinaryIO) -> dict[str, str]:
    """All non-directory, non-symlink, non-binary entries, root-stripped.

    Broader than app.scan.llm_scan._iter_code_files: Deploy Pack also
    needs to read package.json / requirements.txt / pyproject.toml /
    any existing Dockerfile, not just source code.
    """
    with zipfile.ZipFile(fileobj) as zf:
        names = zf.namelist()
        tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
        prefix = ""
        if len(tops) == 1 and any("/" in n for n in names):
            prefix = next(iter(tops)) + "/"

        out: dict[str, str] = {}
        for info in zf.infolist():
            n = info.filename
            if info.is_dir() or not n.startswith(prefix) or n == prefix:
                continue
            data = zf.read(info)
            if b"\x00" in data[:4096]:
                continue
            out[n[len(prefix):]] = data.decode("utf-8", errors="ignore")
    return out


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def _is_unsafe_path(name: str) -> bool:
    """Mirrors app.ingest.validators._is_unsafe_path. Re-checked here,
    not just trusted from the earlier validate_zip call, because this
    is the one place that actually writes bytes to disk."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute():
        return True
    if len(name) >= 2 and name[1] == ":":
        return True
    return ".." in path.parts


def extract_repo(fileobj: BinaryIO, dest: Path) -> None:
    """Write the archive's real bytes to `dest`, root-stripped.

    Deliberately byte-for-byte, unlike read_all_files (which decodes to
    text for analysis) — lockfiles, images, and fonts must survive
    intact for `docker build` to actually work. Symlinks are skipped,
    never extracted, same rule as app.ingest.validators.
    """
    with zipfile.ZipFile(fileobj) as zf:
        names = zf.namelist()
        tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
        prefix = ""
        if len(tops) == 1 and any("/" in n for n in names):
            prefix = next(iter(tops)) + "/"

        for info in zf.infolist():
            n = info.filename
            if info.is_dir() or not n.startswith(prefix) or n == prefix:
                continue
            if _is_symlink(info) or _is_unsafe_path(n):
                continue
            rel = n[len(prefix):]
            out_path = dest / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(zf.read(info))


def _uses_postgres(files: dict[str, str]) -> bool:
    manifest = files.get("requirements.txt", "") + files.get("pyproject.toml", "")
    return bool(_DB_MARKERS.search(manifest))


def _fastapi_entry_module(files: dict[str, str]) -> str:
    """Best-effort `module.path:app` for uvicorn. Falls back to the
    convention both real test repos happened to use."""
    for path, text in files.items():
        if not path.endswith(".py"):
            continue
        m = re.search(r"^(\w+)\s*=\s*FastAPI\(", text, re.M)
        if m:
            module = path[:-3].replace("/", ".").removesuffix(".__init__")
            return f"{module}:{m.group(1)}"
    return "app.main:app"


def _fastapi_pack(files: dict[str, str]) -> dict[str, str]:
    uses_poetry = "[tool.poetry]" in files.get("pyproject.toml", "")
    entry = _fastapi_entry_module(files)
    needs_db = _uses_postgres(files)

    if uses_poetry:
        install = (
            "RUN pip install --no-cache-dir poetry==1.8.3 \\\n"
            "    && poetry config virtualenvs.create false\n"
            "COPY pyproject.toml poetry.lock* ./\n"
            "RUN poetry install --no-interaction --no-ansi --no-root"
        )
    else:
        install = (
            "COPY requirements.txt ./\n"
            "RUN pip install --no-cache-dir -r requirements.txt"
        )

    # Runs as a non-root uid, like the Vite pack (nginx-unprivileged, uid 101)
    # and the Fix Pack runner's forced --user: this image runs untrusted client
    # code. Two details are deliberate. The uid is NUMERIC (1000:1000) rather
    # than a named user, because python:3.12-slim ships no non-root account and
    # no guarantee of the shell tooling a `useradd` step would need. And USER
    # comes AFTER the install steps, so pip still writes to system paths as
    # root; only the finished app runs unprivileged. Safe on the exposed port:
    # 8000 is above 1024, so no privileged bind is needed.
    #
    # This lives in the Dockerfile, not in sandbox.py's --user flag, because the
    # Dockerfile is what the client takes with them when they `docker compose
    # up` on their own host; the runner flag stays behind.
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        f"{install}\n"
        "COPY --chown=1000:1000 . .\n"
        "EXPOSE 8000\n"
        "USER 1000:1000\n"
        f'CMD ["uvicorn", "{entry}", "--host", "0.0.0.0", "--port", "8000"]\n'
    )

    if needs_db:
        compose = (
            "services:\n"
            "  app:\n"
            "    build: .\n"
            '    ports: ["8000:8000"]\n'
            "    env_file: [.env]\n"
            "    depends_on:\n"
            "      db:\n"
            "        condition: service_healthy\n"
            "  db:\n"
            "    image: postgres:16-alpine\n"
            "    environment:\n"
            "      POSTGRES_USER: ${POSTGRES_USER}\n"
            "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n"
            "      POSTGRES_DB: ${POSTGRES_DB}\n"
            "    healthcheck:\n"
            '      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]\n'
            "      interval: 5s\n"
            "      timeout: 5s\n"
            "      retries: 10\n"
        )
        env_extra = (
            "POSTGRES_USER=app\nPOSTGRES_PASSWORD=change_me\nPOSTGRES_DB=app\n"
            "DATABASE_URL=postgresql+asyncpg://app:change_me@db:5432/app\n"
        )
    else:
        compose = (
            "services:\n"
            "  app:\n"
            "    build: .\n"
            '    ports: ["8000:8000"]\n'
            "    env_file: [.env]\n"
        )
        env_extra = ""

    ci = _boot_check_ci_workflow(port=8000)
    return {
        "Dockerfile": dockerfile,
        "docker-compose.yml": compose,
        ".dockerignore": DOCKERIGNORE,
        ".env.example": _merge_env_example(files, env_extra),
        ".github/workflows/deploy-pack-ci.yml": ci,
    }


def _vite_react_pack(files: dict[str, str]) -> dict[str, str]:
    env_vars = sorted({
        m for text in files.values() for m in _VITE_ENV_VAR.findall(text)
    })

    build_args_block = "".join(f"ARG {v}\nENV {v}=${{{v}}}\n" for v in env_vars)
    # Serve via nginx-unprivileged (runs as uid 101, listens on 8080), NOT the
    # stock nginx:alpine. The stock image's master runs as root and chowns its
    # temp dirs (/var/cache/nginx/*) to the worker uid on boot; under the
    # sandbox's --cap-drop=ALL + --read-only that chown fails
    # ("chown(...client_temp, 101) failed (1: Operation not permitted)") and
    # nginx aborts before it can serve. The unprivileged image never runs as
    # root, so it skips the chown/setuid entirely and boots cleanly under the
    # hardened run. See app/deploypack/sandbox.py.
    dockerfile = (
        "FROM node:20-slim AS build\n"
        "WORKDIR /app\n"
        "COPY package*.json ./\n"
        "RUN npm ci\n"
        "COPY . .\n"
        f"{build_args_block}"
        "RUN npm run build\n"
        "\n"
        "FROM nginxinc/nginx-unprivileged:alpine\n"
        "COPY --from=build /app/dist /usr/share/nginx/html\n"
        "COPY nginx.conf /etc/nginx/conf.d/default.conf\n"
        "EXPOSE 8080\n"
    )

    build_args_yaml = "".join(f"        {v}: ${{{v}}}\n" for v in env_vars)
    compose = (
        "services:\n"
        "  app:\n"
        "    build:\n"
        "      context: .\n"
        + ("      args:\n" + build_args_yaml if env_vars else "")
        + '    ports: ["8080:8080"]\n'
    )

    nginx_conf = (
        "server {\n"
        "    listen 8080;\n"
        "    server_name _;\n"
        "    root /usr/share/nginx/html;\n"
        "    index index.html;\n"
        "\n"
        "    location / {\n"
        "        try_files $uri $uri/ /index.html;\n"
        "    }\n"
        "}\n"
    )

    env_extra = "".join(f"{v}=\n" for v in env_vars)
    ci = _boot_check_ci_workflow(port=8080, container_port=8080)
    return {
        "Dockerfile": dockerfile,
        "docker-compose.yml": compose,
        ".dockerignore": DOCKERIGNORE,
        "nginx.conf": nginx_conf,
        ".env.example": _merge_env_example(files, env_extra),
        ".github/workflows/deploy-pack-ci.yml": ci,
    }


def _node_install(files: dict[str, str]) -> tuple[str, str, str]:
    """(copy_manifest, install_cmd, build_cmd) keyed off which lockfile
    the repo ships — real Lovable/Bolt/v0 Next.js exports pin npm, yarn,
    or pnpm and the wrong installer errors on a foreign lockfile. Falls
    back to `npm install` when no lockfile is present (nothing to be
    `ci`-strict against). corepack ships with the node image and pins
    the yarn/pnpm version the lockfile was written by."""
    if "pnpm-lock.yaml" in files:
        return ("COPY package.json pnpm-lock.yaml ./",
                "RUN corepack enable && pnpm install --frozen-lockfile",
                "pnpm run build")
    if "yarn.lock" in files:
        return ("COPY package.json yarn.lock ./",
                "RUN corepack enable && yarn install --frozen-lockfile",
                "yarn build")
    if "package-lock.json" in files:
        return ("COPY package.json package-lock.json ./",
                "RUN npm ci",
                "npm run build")
    return ("COPY package.json ./",
            "RUN npm install",
            "npm run build")


def _next_is_standalone(files: dict[str, str]) -> bool:
    return any(
        _NEXT_STANDALONE.search(files[name])
        for name in _NEXT_CONFIG_NAMES if name in files
    )


def _nextjs_pack(files: dict[str, str]) -> dict[str, str]:
    if not _next_is_standalone(files):
        raise UnsupportedForDeployPack(
            'Next.js Deploy Pack needs output: "standalone" in your '
            "next.config (js/mjs/cjs/ts) — add it and re-run. Without it "
            "the build produces no self-contained server.js for the image "
            "to run, so a Pack generated now would build but never boot."
        )

    copy_manifest, install_cmd, build_cmd = _node_install(files)

    # NEXT_PUBLIC_* is inlined into the client bundle at build time (same
    # class as Vite's VITE_*), so it must be a Docker build arg, not a
    # runtime env var — mirrors _vite_react_pack.
    env_vars = sorted({
        m for text in files.values() for m in _NEXT_PUBLIC_ENV_VAR.findall(text)
    })
    build_args_block = "".join(f"ARG {v}\nENV {v}=${{{v}}}\n" for v in env_vars)

    dockerfile = (
        "FROM node:20-slim AS build\n"
        "WORKDIR /app\n"
        f"{copy_manifest}\n"
        f"{install_cmd}\n"
        "COPY . .\n"
        f"{build_args_block}"
        f"RUN {build_cmd}\n"
        # public/ is optional in a Next.js app; guarantee it exists so the
        # run stage's COPY can't fail on a repo that doesn't ship one.
        "RUN mkdir -p public\n"
        "\n"
        "FROM node:20-slim AS run\n"
        "WORKDIR /app\n"
        "ENV NODE_ENV=production\n"
        # server.js binds to HOSTNAME (defaults to localhost inside the
        # container -> unreachable from the host). Force 0.0.0.0 here, in
        # the generated image, not in sandbox.py: it's how this image must
        # run, and it must ship in the Pack the user gets.
        "ENV HOSTNAME=0.0.0.0\n"
        "ENV PORT=3000\n"
        # Owned by and run as `node` (uid 1000, built into node:20-slim), not
        # root. Same reason the Vite pack serves via nginx-unprivileged and the
        # Fix Pack runner forces a non-root --user: this image runs untrusted
        # client code. It belongs in the Dockerfile rather than in sandbox.py's
        # --user flag, because the client takes the Dockerfile with them when
        # they `docker compose up` on their own host -- the runner flag stays
        # behind. Safe on the exposed port: 3000 is above 1024, so no
        # privileged bind is needed.
        "COPY --from=build --chown=node:node /app/.next/standalone ./\n"
        "COPY --from=build --chown=node:node /app/.next/static ./.next/static\n"
        "COPY --from=build --chown=node:node /app/public ./public\n"
        "EXPOSE 3000\n"
        "USER node\n"
        'CMD ["node", "server.js"]\n'
    )

    build_args_yaml = "".join(f"        {v}: ${{{v}}}\n" for v in env_vars)
    compose = (
        "services:\n"
        "  app:\n"
        "    build:\n"
        "      context: .\n"
        + ("      args:\n" + build_args_yaml if env_vars else "")
        + '    ports: ["3000:3000"]\n'
    )

    env_extra = "".join(f"{v}=\n" for v in env_vars)
    ci = _boot_check_ci_workflow(port=3000)
    return {
        "Dockerfile": dockerfile,
        "docker-compose.yml": compose,
        ".dockerignore": DOCKERIGNORE,
        ".env.example": _merge_env_example(files, env_extra),
        ".github/workflows/deploy-pack-ci.yml": ci,
    }


# docker build copies the whole build context into the image. Without this
# file, an .env sitting next to the Dockerfile becomes a layer that travels
# with the image to every registry and every host it is pulled onto -- and
# leaked credentials are the single most common finding Drydock reports, so
# shipping a build that bakes them in would undo the audit that preceded it.
#
# Excluding .env does not starve the container: docker-compose.yml declares
# env_file: [.env], which compose reads from the host at run time, and the
# generated CI boot check runs the image with no env file at all.
#
# .git goes too. A repository's history keeps deleted secrets alive in old
# objects, and a runtime image has no use for it.
DOCKERIGNORE = """\
.env
.env.*
!.env.example

node_modules
.venv
__pycache__

.git
"""

def _merge_env_example(files: dict[str, str], extra: str) -> str:
    """Keep whatever the repo already documents; append only new keys."""
    existing = files.get(".env.example", "").rstrip()
    existing_keys = {
        line.split("=", 1)[0] for line in existing.splitlines() if "=" in line
    }
    new_lines = [
        line for line in extra.splitlines()
        if line.split("=", 1)[0] not in existing_keys
    ]
    parts = [p for p in (existing, "\n".join(new_lines)) if p]
    return "\n".join(parts) + "\n"


def _boot_check_ci_workflow(port: int, container_port: int | None = None) -> str:
    container_port = container_port or port
    return (
        "name: deploy-pack-ci\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  pull_request: {}\n"
        "jobs:\n"
        "  build-and-boot:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - name: Build image\n"
        "        run: docker build -t app-image .\n"
        "      - name: Boot and healthcheck\n"
        "        run: |\n"
        f"          docker run -d --rm -p {port}:{container_port} --name app-ci app-image\n"
        "          for i in $(seq 1 20); do\n"
        f'            curl -sf http://localhost:{port}/ && exit 0\n'
        "            sleep 2\n"
        "          done\n"
        "          echo \"app did not become healthy\" >&2\n"
        "          docker logs app-ci\n"
        "          exit 1\n"
    )


def generate_deploy_pack(stack: Stack, files: dict[str, str]) -> dict[str, str]:
    """Returns {relative_path: content} for every file the Pack adds.

    Raises UnsupportedForDeployPack for a stack with no template, or for
    a Next.js app missing output:"standalone" (see _nextjs_pack).
    """
    if stack is Stack.FASTAPI:
        return _fastapi_pack(files)
    if stack is Stack.VITE_REACT:
        return _vite_react_pack(files)
    if stack is Stack.NEXTJS:
        return _nextjs_pack(files)
    raise UnsupportedForDeployPack(
        f"no Deploy Pack template for stack={stack.value!r} yet"
    )

