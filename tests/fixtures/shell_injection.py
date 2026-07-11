"""Mirrors a real pattern: a tool-version helper that shells out with
shell=True on a command string built from user-controlled input.
"""
import subprocess


def get_tool_version(tool_name: str, user_input: str) -> str:
    cmd = f"{tool_name} --version {user_input}"
    out = subprocess.check_output(cmd, shell=True, timeout=2)
    return out.strip()
