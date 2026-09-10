"""Audit the generated credential's lifecycle without Docker or external calls.

These tests distinguish a shipped example from an automatically enabled
runtime password. They deliberately do not assert that copying the example
unchanged is secure, or that the customer's database actually boots.
"""

import subprocess
from urllib.parse import urlsplit

import yaml

from app.deploypack.generate import generate_deploy_pack
from app.deploypack import sandbox
from app.ingest.stack_detect import Stack


def postgres_pack():
    return generate_deploy_pack(Stack.FASTAPI, {
        "requirements.txt": "fastapi\nuvicorn\nasyncpg\n",
        "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    })


def test_password_is_a_shipped_example_with_no_automatic_runtime_env():
    pack = postgres_pack()
    assert ".env.example" in pack
    assert ".env" not in pack
    env = dict(line.split("=", 1) for line in pack[".env.example"].splitlines())
    dsn = urlsplit(env["DATABASE_URL"])
    assert dsn.password == env["POSTGRES_PASSWORD"] == "change_me"
    assert dsn.hostname == "db"

    compose = yaml.safe_load(pack["docker-compose.yml"])
    assert compose["services"]["app"]["env_file"] == [".env"]
    assert compose["services"]["db"]["environment"]["POSTGRES_PASSWORD"] == "${POSTGRES_PASSWORD}"
    assert "ports" not in compose["services"]["db"]
    # The defaults become live only if the operator copies these example
    # values into the required .env (or supplies equivalent external config).
    assert "change_me" not in pack["Dockerfile"]
    assert "change_me" not in pack["docker-compose.yml"]


def test_sandbox_boot_does_not_load_the_example_or_launch_postgres(tmp_path, monkeypatch):
    pack = postgres_pack()
    for relative, content in pack.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="200", stderr="")

    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    result = sandbox.verify_deploy_pack(tmp_path, 18009, 8000, run=fake_run)
    assert result.ok
    runs = [args for args in calls if args[:2] == ["docker", "run"]]
    assert len(runs) == 1
    assert "--env-file" not in runs[0]
    assert "-e" not in runs[0] and "--env" not in runs[0]
    assert not any("postgres:16-alpine" in args for args in calls)
    assert not (tmp_path / ".env").exists()
