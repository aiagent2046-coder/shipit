"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned with its premise asserted -- shipit runs
    docker through subprocess in the sandbox and proof runners, so the silence
    below is silence over code that invokes subprocess, not silence over an empty
    archive.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.command_injection import RULE_ID, scan_command_injection
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''from fastapi import APIRouter, Depends
import os

router = APIRouter()


@router.get("/ping")
async def ping(host: str):
    os.system("ping -c 1 " + host)
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/ping.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_command_built_from_caller_input_is_a_high_severity_signal():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "os.system(" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.7
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "traced only inside this function" in f["explanation"]


@pytest.mark.parametrize("source", [
    # subprocess WITHOUT shell=True is not shell-interpreted: a fixed program name
    POSITIVE.replace("os.system(\"ping -c 1 \" + host)",
                     "subprocess.run(\"ping -c 1 \" + host)"),
    # an argument list without shell=True is a safe argv, not a command line
    POSITIVE.replace("os.system(\"ping -c 1 \" + host)",
                     "subprocess.run([\"ping\", \"-c\", \"1\", host])"),
    # a fixed literal command, with the caller's value used for something else
    POSITIVE.replace("os.system(\"ping -c 1 \" + host)",
                     "os.system(\"ping -c 1 localhost\")"),
    # the command is injected configuration, not a request input
    POSITIVE.replace("async def ping(host: str):",
                     "async def ping(host: str = Depends(get_cmd)):"),
    # built by a call the trace does not follow
    POSITIVE.replace("os.system(\"ping -c 1 \" + host)",
                     "os.system(build_command(host))"),
    # shell passed as a variable is not a literal True and is not read
    POSITIVE.replace("os.system(\"ping -c 1 \" + host)",
                     "subprocess.run(\"ping -c 1 \" + host, shell=do_shell)"),
    # the value crosses a definition boundary into a local helper
    "import os\n\n\ndef job():\n    def run_it(cmd):\n        os.system(cmd)\n    run_it(\"ls -la\")\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_command_injection(archive(source)) == []


def test_an_import_alias_is_the_same_sink():
    """`from os import system` binds the name system to os.system."""
    source = '''from fastapi import APIRouter
from os import system

router = APIRouter()


@router.get("/run")
async def run(name: str):
    system("echo " + name)
'''
    findings = scan_command_injection(archive(source))
    assert len(findings) == 1


def test_subprocess_keyword_args_form_is_the_same_sink():
    source = '''from fastapi import APIRouter
import subprocess

router = APIRouter()


@router.get("/run")
async def run(name: str):
    subprocess.run(args="echo " + name, shell=True)
'''
    findings = scan_command_injection(archive(source))
    assert len(findings) == 1


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "subprocess-no-shell-list": ("app/list_files.py",
                                 'subprocess.run(["ls", "-la", name])',
                                 'subprocess.run(["ls", "-la", name], shell=True)'),
    "subprocess-no-shell-string": ("app/program.py",
                                   'subprocess.run("run-" + name)',
                                   'subprocess.run("run-" + name, shell=True)'),
    "fixed-literal-command": ("app/cron.py",
                              'os.system("systemctl restart app")',
                              'os.system("systemctl restart " + name)'),
    "shell-variable": ("app/variable.py", "shell=shell", "shell=True"),
    "helper-builds-the-command": ("app/build.py",
                                  "os.system(build_command(name))",
                                  'os.system("gen-report " + name)'),
    "command-injected-by-dependency": ("app/configured.py",
                                       "cmd: str = Depends(get_command)", "cmd: str"),
    "sink-inside-local-helper": ("app/helper.py",
                                 "    def execute(cmd):\n        os.system(cmd)\n    execute(\"ls -la\")",
                                 "    os.system(\"ls -la \" + name)"),
    "shell-c-fixed-command": ("app/reload.py",
                              '["bash", "-c", "ls -la"]',
                              '["bash", "-c", "ls -la " + name]'),
    "list-variable-shell-true": ("app/variable_list.py",
                                 "    args = [\"rm\", \"-rf\", name]\n    subprocess.run(args, shell=True)",
                                 "    subprocess.run([\"rm\", \"-rf\", name], shell=True)"),
}


def test_every_corpus_negative_has_a_mutation():
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_command_injection(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_command_injection(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard whose premise is asserted.

    shipit runs docker through subprocess in the sandbox runner, the preview
    stage and the proof probes, so a rule that fired on our own routes would be
    unusable. If this ever fails, read the reported line before touching the rule.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    text = "\n".join(sources.values())
    subprocess_calls = len(re.findall(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\(", text)) \
        + len(re.findall(r"\bos\.(?:system|popen)", text))
    assert subprocess_calls > 10, f"expected the product to invoke subprocess; found {subprocess_calls}"
    assert scan_command_injection(archive(sources)) == []
