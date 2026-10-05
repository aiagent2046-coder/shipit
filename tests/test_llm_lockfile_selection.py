"""Lockfile policy frees model context without deleting dependency evidence."""
import hashlib
import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient, LLMError, LLMUsage
from app.report.evidence import manifest_rows
from app.sca.lockfiles import collect_dependencies
from app.scan import llm_scan
from app.scan.manifest import scan_manifest


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    buf.seek(0)
    return buf


class RecordedClient(LLMClient):
    def __init__(self, fail=False):
        super().__init__(providers=[])
        self.sent = []
        self.fail = fail

    def complete(self, system, prompt, **kwargs):
        self.sent.append(prompt)
        if self.fail:
            raise LLMError("provider unavailable")
        return "[]", LLMUsage(model="fake", input_tokens=1, output_tokens=1)


def test_dependency_lockfiles_do_not_displace_working_code():
    production = [(f"src/auth{i}.ts", "const token = 1;\n".ljust(150)) for i in range(6)]
    files = [("package-lock.json", "token " * 1000), *production]
    # The old ranking spends part of the fixed budget on a lockfile and loses code.
    old_names = {name for name, _ in llm_scan._select_ranked_files(files, "auth", 1000)}
    assert len(old_names & {name for name, _ in production}) < len(production)
    selected = llm_scan.select_files(files, "auth", 1000)
    assert {name for name, _ in selected} == {name for name, _ in production}
    assert sum(len(text) for _, text in selected) <= 1000


def test_exact_lockfile_names_are_excluded_at_any_depth_but_inputs_are_preserved():
    locks = {f"repo/apps/web/{name}": 'token: "dependency metadata"'
             for name in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "packages.lock.json")}
    kept = {f"repo/{name}": 'token: "application configuration"'
            for name in ("package.json", "pyproject.toml", "lock-policy.json", "auth.yaml", "src/auth.ts")}
    files = {**locks, **kept}
    source_hashes = {}
    with zipfile.ZipFile(archive(files)) as zf:
        candidates = llm_scan._iter_code_files(zf, source_hashes=source_hashes)
    assert dict(candidates) == files
    assert source_hashes == {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}
    assert {name for name, _ in llm_scan.select_files(candidates, "auth")} == set(kept)


def test_lockfile_does_not_turn_test_only_repository_into_application_source():
    files = {"package-lock.json": '{"token": "dependency"}', "package.json": '{"name": "sample"}',
             "tests/auth.test.ts": "const token = 'fixture';\n"}
    client = RecordedClient()
    buf = archive(files)
    _, stats = llm_scan.run_llm_scan(buf, client, rubrics=("auth",))
    assert not llm_scan.has_application_source(list(files.items()))
    assert stats.selection_scope == "nonproduction_only"
    assert stats.submitted_files == ("tests/auth.test.ts",)
    assert len(client.sent) == 1


@pytest.mark.parametrize("fail", [False, True])
def test_lockfile_exclusion_is_unique_across_passes_rubrics_and_provider_failure(fail):
    files = {"package-lock.json": '{"token": "webhook"}', "nested/pnpm-lock.yaml": "plain: metadata\n",
             "src/auth.ts": "const token = 1;", "src/billing.ts": "const webhook = 1;"}
    buf = archive(files)
    client = RecordedClient(fail=fail)
    _, stats = llm_scan.run_llm_scan(buf, client, rubrics=("auth", "money"), passes=2)
    assert stats.candidate_files == 4
    assert stats.selection_exclusions["dependency_lockfile"] == 2
    assert sum(stats.selection_exclusions.values()) == stats.candidate_files - len(stats.submitted_files)
    assert all("package-lock.json" not in prompt and "pnpm-lock.yaml" not in prompt for prompt in client.sent)
    if fail:
        assert len(client.sent) == 1
        assert stats.selection_exclusions["rubric_not_reached"] == 1
    else:
        assert len(client.sent) == 4
        assert sum(stats.selection_exclusions.values()) == 2
    manifest = scan_manifest(buf.getvalue(), "test", {}, vars(stats), None)
    rows = dict(manifest_rows({"scan_manifest": manifest}))
    assert rows["Files not submitted: Dependency lockfiles excluded from model context"] == "2"


def test_zero_lockfile_exclusions_are_explicit():
    _, stats = llm_scan.run_llm_scan(archive({"auth.ts": "const token = 1;"}),
                                   RecordedClient(), rubrics=("auth",))
    assert stats.selection_exclusions["dependency_lockfile"] == 0


def test_dependency_inventory_still_reads_lockfile_from_same_archive():
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "application", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.4"},
    }})
    buf = archive({"package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
                   "package-lock.json": lock, "src/auth.ts": "const token = 1;"})
    original = buf.getvalue()
    client = RecordedClient()
    llm_scan.run_llm_scan(buf, client, rubrics=("auth",))
    dependencies, manifests, _ = collect_dependencies(buf.getvalue())
    assert buf.getvalue() == original
    assert manifests == ["package-lock.json"]
    assert [(item.name, item.version) for item in dependencies] == [("lodash", "4.17.4")]
    assert all("package-lock.json" not in prompt for prompt in client.sent)


def test_unused_support_reserve_returns_to_application_code():
    production = [("src/auth.ts", "const token = 1;\n".ljust(140)),
                  *[(f"src/auth{i}.ts", "const token = 1;\n".ljust(140)) for i in range(6)]]
    support = ("tests/auth.test.ts", "token=1;\n")
    selected = llm_scan.select_files([*production, support], "auth", 1000)
    # A fixed 10% reservation only fits six of these seven complete source files.
    assert len(llm_scan._select_ranked_files(production, "auth", 900)) == 6
    assert {name for name, _ in selected} == {name for name, _ in [*production, support]}
    assert dict(selected)[support[0]] == support[1]
    assert sum(len(text) for _, text in selected) <= 1000
