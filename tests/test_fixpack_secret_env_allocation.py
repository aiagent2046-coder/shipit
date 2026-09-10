"""A generated fix must not merge unrelated credentials into one setting."""

from dataclasses import asdict
import io
import json
import zipfile

import pytest

from app.fixpack.generate import build_fixpack_plan, _validate_syntax, render_pr_body
from app.scan.collapse import collapse_repeats
from app.scan.secrets import scan_secrets


def _zip(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for path, source in entries.items():
            archive.writestr("repo/" + path, source)
    return output.getvalue()


def _plan(entries, *, grouped=False):
    data = _zip(entries)
    findings = [asdict(f) for f in scan_secrets(io.BytesIO(data))]
    if grouped:
        findings = collapse_repeats(findings)
    return build_fixpack_plan(data, findings), findings


def _assert_no_values(plan, values):
    output = json.dumps(asdict(plan)) + render_pr_body(plan)
    for value in values:
        assert value not in output


def test_distinct_database_jwt_and_api_credentials_keep_independent_runtime_values(monkeypatch):
    names = ("PG_PASSWORD", "JWT_SECRET", "TOKEN")
    values = ["synTheticValue314159" + str(index) for index in range(3)]
    source = "".join(f'{name} = "{value}"\n' for name, value in zip(names, values))
    plan, _ = _plan({"config.py": source})
    assert not plan.skipped
    assert {fix.env_var for fix in plan.secret_fixes} == set(names)
    for index, name in enumerate(names):
        monkeypatch.setenv(name, "rotated-credential-" + str(index))
    namespace = {}
    exec(compile(plan.files["config.py"], "synthetic-config.py", "exec"), namespace)
    assert [namespace[name] for name in names] == ["rotated-credential-" + str(i) for i in range(3)]
    assert set(plan.files[".env.example"].splitlines()) == {name + "=changeme" for name in names}
    _assert_no_values(plan, values)


def test_same_mask_and_assignment_name_do_not_merge_distinct_literals(monkeypatch):
    values = ["synTheticTokenValue314159", "difFerentTokenValue271828"]
    entries = {f"src/{index}.py": f'API_TOKEN = "{value}"\n' for index, value in enumerate(values)}
    plan, findings = _plan(entries)
    assert len(findings) == 2
    assert findings[0]["masked"] == findings[1]["masked"]
    assert {fix.env_var for fix in plan.secret_fixes} == {"API_TOKEN", "API_TOKEN_2"}
    monkeypatch.setenv("API_TOKEN", "rotated-first")
    monkeypatch.setenv("API_TOKEN_2", "rotated-second")
    results = []
    for path in entries:
        namespace = {}
        exec(compile(plan.files[path], "synthetic-config.py", "exec"), namespace)
        results.append(namespace["API_TOKEN"])
    assert results == ["rotated-first", "rotated-second"]
    _assert_no_values(plan, values)
    # Zip traversal and report ordering must not choose different bindings.
    reversed_data = _zip(dict(reversed(list(entries.items()))))
    reversed_plan = build_fixpack_plan(reversed_data, list(reversed(findings)))
    assert reversed_plan.files == plan.files


def test_grouped_identical_literal_uses_one_setting_in_all_recorded_files():
    value = "synTheticTokenValue314159"
    plan, findings = _plan({
        "src/a.py": f'API_TOKEN = "{value}"\n',
        "src/b.py": f'API_TOKEN = "{value}"\n',
    }, grouped=True)
    assert len(findings) == 1
    assert findings[0]["occurrence_count"] == 2
    assert len(plan.secret_fixes) == 2
    assert {fix.env_var for fix in plan.secret_fixes} == {"API_TOKEN"}
    assert all('os.environ["API_TOKEN"]' in plan.files[path] for path in ("src/a.py", "src/b.py"))
    _assert_no_values(plan, [value])


def test_distinct_provider_keys_get_separate_names():
    values = ["ghp_" + char * 36 for char in "ab"]
    plan, _ = _plan({f"src/{i}.py": f'key = "{value}"\n' for i, value in enumerate(values)})
    assert not plan.skipped
    assert {fix.env_var for fix in plan.secret_fixes} == {"GITHUB_TOKEN", "GITHUB_TOKEN_2"}
    _assert_no_values(plan, values)


@pytest.mark.parametrize("reference", [
    'os.getenv("API_TOKEN", "development")',
    'os.environ.get("API_TOKEN", "development")',
    'os.environ["API_TOKEN"]',
    'getenv("API_TOKEN")',
    'environ.get("API_TOKEN")',
    'process.env.API_TOKEN',
    'process.env["API_TOKEN"]',
    'process . env . API_TOKEN',
    'os . environ . get("API_TOKEN")',
])
def test_existing_environment_references_are_reserved_and_preserved(reference):
    value = "synTheticTokenValue314159"
    existing = "existing = " + reference + "\n"
    plan, _ = _plan({"config.py": f'API_TOKEN = "{value}"\n', "existing.py": existing})
    assert {fix.env_var for fix in plan.secret_fixes} == {"API_TOKEN_2"}
    assert "existing.py" not in plan.files
    _assert_no_values(plan, [value])


def test_dotenv_names_and_existing_defaults_are_not_repurposed(monkeypatch):
    value = "synTheticTokenValue314159"
    default = 'existing = os.getenv("API_TOKEN", "development")\n'
    plan, _ = _plan({
        "config.py": 'import os\n' + default + f'API_TOKEN = "{value}"\n',
        ".env.example": "API_TOKEN_2=changeme\n",
        ".env.local": "API_TOKEN_3=changeme\n",
    })
    assert {fix.env_var for fix in plan.secret_fixes} == {"API_TOKEN_4"}
    assert default in plan.files["config.py"]
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.setenv("API_TOKEN_4", "rotated-new")
    namespace = {}
    exec(compile(plan.files["config.py"], "synthetic-config.py", "exec"), namespace)
    assert namespace["existing"] == "development"
    assert namespace["API_TOKEN"] == "rotated-new"
    _assert_no_values(plan, [value])


@pytest.mark.parametrize("extension", ["js", "ts"])
def test_javascript_and_typescript_keep_separate_normalized_names(extension):
    values = ["synTheticTokenValue314159", "difFerentTokenValue271828"]
    source = (f'export const config = {{\nadminToken: "{values[0]}",\n'
              f'"api_key": "{values[1]}"\n}};\n')
    path = "src/config." + extension
    plan, _ = _plan({path: source})
    assert not plan.skipped
    assert {fix.env_var for fix in plan.secret_fixes} == {"ADMIN_TOKEN", "API_KEY"}
    assert _validate_syntax(path, source, plan.files[path])
    suffix = "!" if extension == "ts" else ""
    assert f"adminToken: process.env.ADMIN_TOKEN{suffix}" in plan.files[path]
    assert f'"api_key": process.env.API_KEY{suffix}' in plan.files[path]
    _assert_no_values(plan, values)


def test_multiple_private_keys_are_not_combined_by_a_whole_file_rewrite():
    border = "-" * 5
    begin = border + "BEGIN PRIVATE KEY" + border
    end = border + "END PRIVATE KEY" + border
    values = [begin + "\n" + char * 80 + "\n" + end for char in "AB"]
    source = "".join(f'key_{index} = """{value}"""\n' for index, value in enumerate(values))
    plan, findings = _plan({"config.py": source})
    assert sum(f["rule_id"] == "private-key-block" for f in findings) == 2
    assert not plan.files
    assert not plan.secret_fixes
    assert all("multiple or incomplete private keys" in item.reason for item in plan.skipped)
    _assert_no_values(plan, values)
