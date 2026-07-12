"""Tests for Deploy Pack generation — deterministic, no LLM involved."""

import io
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


# --- unsupported ---

def test_nextjs_and_unsupported_raise():
    for stack in (Stack.NEXTJS, Stack.UNSUPPORTED):
        try:
            generate_deploy_pack(stack, {})
            assert False, f"expected UnsupportedForDeployPack for {stack}"
        except UnsupportedForDeployPack:
            pass
