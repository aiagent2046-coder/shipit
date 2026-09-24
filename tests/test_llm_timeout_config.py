"""Reject unusable completion timeouts before accepting audit work."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def _import_client(timeout: str | None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("LLM_READ_TIMEOUT", None)
    if timeout is not None:
        env["LLM_READ_TIMEOUT"] = timeout
    # A fresh process exercises the actual import-time configuration without
    # replacing LLMError/Provider classes used by other tests in this process.
    return subprocess.run(
        [
            sys.executable, "-c",
            "import json; from app.llm.client import TIMEOUT; "
            "print(json.dumps({'read': TIMEOUT.read, 'connect': TIMEOUT.connect}))",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "1e309", "", "bad"])
def test_invalid_timeout_fails_at_startup(value):
    result = _import_client(value)
    assert result.returncode != 0
    assert "LLM_READ_TIMEOUT must be a finite positive number" in result.stderr


@pytest.mark.parametrize("value, expected", [(None, 120.0), ("300.5", 300.5)])
def test_valid_timeout_preserves_connect_deadline(value, expected):
    result = _import_client(value)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"read": expected, "connect": 10.0}
