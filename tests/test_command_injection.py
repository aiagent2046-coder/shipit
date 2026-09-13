"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product baseline is scanned and a known eligible route is then added
    to prove that discovery still reaches supported code in the same archive;
  * POSIX shell semantics are checked independently using harmless printf calls.
"""
import io
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from app.scan.command_injection import RULE_ID, scan_command_injection
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''from fastapi import APIRouter, Depends
import os
import subprocess

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
                                 'subprocess.run(["ls -la " + name], shell=True)'),
    "shell-c-positional-data": ("app/command.py",
                                "[\"bash\", \"-c\", 'printf \"%s\" \"$1\"', \"_\", name]",
                                '["bash", "-c", "printf " + name]'),
    "shell-true-positional-data": ("app/command.py",
                                   "['printf \"%s\" \"$1\"', \"_\", name]",
                                   '["printf " + name]'),
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
                                 "    args = [\"rm -rf \" + name]\n    subprocess.run(args, shell=True)",
                                 "    subprocess.run([\"rm -rf \" + name], shell=True)"),
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

    Preserve the current self-scan baseline, then add a known eligible handler
    to prove discovery reaches supported code within this same archive. A future
    finding in the baseline must be investigated, not automatically suppressed.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_command_injection(archive(sources)) == []
    # A real candidate inside the same archive must still be visited, avoiding
    # a vacuous green result when discovery/filtering stops seeing handlers.
    sources["app/aaa_command_regression.py"] = POSITIVE
    findings = scan_command_injection(archive(sources))
    assert [(f.rule_id, f.file) for f in findings] == [(RULE_ID, "app/aaa_command_regression.py")]


@pytest.mark.skipif(os.name != "posix", reason="The scanner's argument-list model is POSIX")
@pytest.mark.parametrize("explicit_shell", [False, True])
@pytest.mark.parametrize("keyword_args", [False, True])
@pytest.mark.parametrize("in_command", [False, True])
def test_posix_command_positions_match_harmless_shell_execution(explicit_shell, keyword_args, in_command):
    """Independent oracle: only synthetic printf commands run, never archive code.

    The same metacharacters are printed literally as positional data, but are
    interpreted when deliberately inserted into command source. This prevents
    golden expectations from defining their own incorrect subprocess semantics.
    """
    value = "; printf SIDE_EFFECT"
    if in_command:
        expression = '["printf DATA" + host]'
        argv = ["printf DATA" + value]
    else:
        expression = '[\'printf "%s" "$1"\', "_", host]'
        argv = ['printf "%s" "$1"', "_", value]
    if explicit_shell:
        expression = '["sh", "-c", ' + expression[1:]
        argv = ["sh", "-c", *argv]
    options = {"shell": not explicit_shell}
    result = subprocess.run(args=argv, capture_output=True, text=True, check=True, timeout=5, **options)
    assert result.stdout == ("DATASIDE_EFFECT" if in_command else value)
    call = f'subprocess.run({"args=" if keyword_args else ""}{expression}, shell={not explicit_shell})'
    source = POSITIVE.replace('os.system("ping -c 1 " + host)', call)
    findings = scan_command_injection(archive(source))
    assert len(findings) == int(in_command)


@pytest.mark.parametrize("arguments", [
    '["echo " + host]',
    '("echo " + host,)',
    '["bash", "-c", "echo " + host]',
    '("bash", "-c", "echo " + host)',
])
def test_unknown_shell_option_does_not_establish_command_position(arguments):
    source = POSITIVE.replace('os.system("ping -c 1 " + host)',
                              f'subprocess.run(args={arguments}, shell=unknown_shell)')
    assert scan_command_injection(archive(source)) == []
