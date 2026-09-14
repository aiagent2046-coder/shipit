"""Project inventory must distinguish public configuration from secret exposure."""
import io
import shutil
import subprocess
import zipfile

import pytest

from app.scan.checks import env_file_is_public_configuration, gitignore_covers_env, run_checks
from app.scan.gitignore import ArchiveGitIgnore


def scan(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for path, content in files.items():
            archive.writestr("repo/" + path, content)
    data.seek(0)
    return run_checks(data)


@pytest.mark.parametrize(("rules", "path", "expected"), [
    ({".gitignore": "/.env\n"}, ".env", True),
    ({".gitignore": "/.env\n"}, "backend/.env", False),
    ({".gitignore": ".env.*\n"}, ".env", False),
    ({".gitignore": ".env.*\n"}, "backend/.env.local", True),
    ({".gitignore": "**/.env\n"}, ".env", True),
    ({".gitignore": "**/.env\n"}, "a/b/.env", True),
    ({".gitignore": "a/**/.env\n"}, "a/.env", True),
    ({".gitignore": "a/**/.env\n"}, "a/b/c/.env", True),
    ({".gitignore": ".env\n!.env\n"}, ".env", False),
    ({".gitignore": "!.env\n.env\n"}, ".env", True),
    ({"backend/.gitignore": ".env\n"}, "backend/.env", True),
    ({"backend/.gitignore": ".env\n"}, ".env", False),
    ({".gitignore": ".env\n", "backend/.gitignore": "!.env\n"}, "backend/.env", False),
    ({".gitignore": "backend/\n!backend/.env\n"}, "backend/.env", True),
    ({".gitignore": "backend/\n", "backend/.gitignore": "!.env\n"}, "backend/.env", True),
    ({".gitignore": "backend/*\n!backend/config/\n"}, "backend/config/.env", False),
    ({".gitignore": "backend\n"}, "backend/.env", True),
    ({".gitignore": ".env/\n"}, ".env", False),
    ({".gitignore": r"\#private" + "\n"}, "#private", True),
    ({".gitignore": r"\!private" + "\n"}, "!private", True),
    ({".gitignore": r"private\*" + "\n"}, "private*", True),
    ({".gitignore": ".env   \n"}, ".env", True),
    ({".gitignore": " .env\n"}, ".env", False),
    ({".gitignore": r".env\ " + "\n"}, ".env ", True),
    ({".gitignore": ".env.[ab]\n"}, ".env.a", True),
    ({".gitignore": ".env.[!ab]\n"}, ".env.c", True),
    ({".gitignore": "frontend/.env.local\nbackend/.env\n"}, "backend/.env", True),
])
def test_ignore_semantics_match_git(tmp_path, rules, path, expected):
    assert ArchiveGitIgnore(rules).ignores(path) is expected
    if shutil.which("git") is None:
        pytest.skip("Git is used only as an independent test oracle")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, body in rules.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index", "-q", "--", path],
        cwd=tmp_path, check=False,
    )
    assert (result.returncode == 0) is expected


def test_root_helper_does_not_accept_variant_or_negated_patterns():
    assert gitignore_covers_env("/.env\n")
    assert not gitignore_covers_env(".env.*\n")
    assert not gitignore_covers_env(".env\n!.env\n")


def test_mathmodel_inventory_reports_root_gap_without_denying_nested_protection():
    findings = scan({
        ".gitignore": "backend/.env\nfrontend/.env.local\n",
        "backend/.gitignore": ".env\n",
        "frontend/.gitignore": "*.local\n.env\n",
        "frontend/.env.development": "VITE_API_BASE_URL=http://localhost:8000\nVITE_WS_URL=ws://localhost:8000\n",
        "frontend/package.json": "{}",
    })
    env = next(f for f in findings if f.rule_id == "env-file-committed")
    assert env.severity == "low" and env.context == "public_configuration"
    assert "git rm" not in env.fix_hint
    ignore = next(f for f in findings if f.rule_id == "gitignore-missing-secrets")
    assert ignore.severity == "medium"
    assert "candidate paths: .env." in ignore.explanation
    assert "backend/.env" not in ignore.explanation
    assert "frontend/.env" not in ignore.explanation
    assert "does not establish" in ignore.explanation


def test_mixed_env_files_keep_credential_evidence_at_its_actual_path():
    findings = scan({
        "frontend/.env.development": "VITE_API_BASE_URL=http://localhost:8000\n",
        "backend/.env": "DB_PASSWORD=" + "live" + "-credential-99\n",
        ".gitignore": ".env\n",
    })
    env = {f.file: f for f in findings if f.rule_id == "env-file-committed"}
    assert env["frontend/.env.development"].severity == "low"
    assert env["backend/.env"].severity == "critical"
    assert "git rm --cached -- backend/.env" in env["backend/.env"].fix_hint
    assert "/backend/.env" in env["backend/.env"].fix_hint
    assert "Static matching does not establish" in env["backend/.env"].explanation


@pytest.mark.parametrize("body", [
    "VITE_API_KEY=" + "live-credential-99",
    "VITE_SECRET=1234",
    "VITE_API_URL=https://user:credential@host.invalid",
    "VITE_API_URL=https://host.invalid/?token=abc",
    "VITE_RANDOM_BLOB=q9xnEr6",
    "VITE_API_URL=http://localhost:8000\nMALFORMED",
    "VITE_API_URL=http://localhost:8000\nDB_PASSWORD=" + "private-99",
    "NODE_PATH=../../build/packages",
])
def test_public_prefix_alone_never_downgrades_unknown_or_secret_values(body):
    assert not env_file_is_public_configuration(body)


@pytest.mark.parametrize("config", [
    ".github/workflows/build.yaml", ".gitlab-ci.yml", ".circleci/config.yml",
    "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml",
    ".travis.yml", ".drone.yml", ".buildkite/pipeline.yml",
])
def test_ci_inventory_recognizes_alternatives(config):
    assert not any(f.rule_id == "no-ci" for f in scan({config: "", "app.py": ""}))


def test_ci_readme_is_not_a_workflow_and_absence_does_not_claim_no_automation():
    finding = next(f for f in scan({".github/workflows/README.md": "instructions", "app.py": ""})
                   if f.rule_id == "no-ci")
    assert "External automation" in finding.explanation
    assert "Nothing runs automatically" not in finding.explanation


def test_hostile_wildcard_pattern_is_bounded_without_backtracking():
    pattern = "*a" * 200 + "b"
    matcher = ArchiveGitIgnore({".gitignore": pattern})
    assert not matcher.ignores("a" * 500)


def test_oversized_rules_cannot_hide_a_late_negation():
    matcher = ArchiveGitIgnore({".gitignore": ".env\n" + "x\n" * 2048 + "!.env\n"})
    assert not matcher.complete
    assert not matcher.ignores(".env")
    finding = next(f for f in scan({".gitignore": ".env\n" + "x\n" * 2048,
                                   "app.py": ""})
                   if f.rule_id == "gitignore-missing-secrets")
    assert "budget" in finding.explanation and "unresolved" in finding.explanation


def test_match_work_budget_stays_unresolved():
    matcher = ArchiveGitIgnore({".gitignore": "*a" * 200 + "b"})
    for _ in range(20):
        assert not matcher.ignores("a" * 500)
    assert not matcher.complete
