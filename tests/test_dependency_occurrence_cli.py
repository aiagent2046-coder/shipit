"""CLI location changes remain visible without multiplying advisory matches."""
from copy import deepcopy
import json

from app import local_cli as cli
from app.scan.cve_match import match_archive
from tests.test_cve_match import archive, catalog
from tests.test_local_report_display import report_with, terminal_rows


def report():
    files = {}
    for prefix, dev, direct in (("", False, False), ("worker/", True, True)):
        declarations = {"devDependencies": {"widget": "1.2.3"}} if direct else {}
        files[prefix + "package.json"] = json.dumps(declarations)
        files[prefix + "package-lock.json"] = json.dumps({"lockfileVersion": 3, "packages": {
            "": declarations,
            "node_modules/widget": {"version": "1.2.3", "dev": dev},
        }})
    result = match_archive(archive(files), catalog())
    return {**report_with(result["findings"]), "dependency_cve": result["coverage"]}


def test_cli_shows_each_manifest_scope_and_directness_without_duplicate_tasks(capsys):
    result = report()
    before = deepcopy(result)
    cli.display(result, False)
    tasks = terminal_rows(capsys.readouterr().out)
    assert len(tasks) == 1
    assert tasks[0]["advisory_findings"] == 1
    assert tasks[0]["dependency_scope"] == "unknown"  # mixed scopes remain per location
    assert tasks[0]["direct"] is None
    locations = {item["manifest"]: item for item in tasks[0]["occurrences"]}
    assert set(locations) == {"package-lock.json", "worker/package-lock.json"}
    assert (locations["package-lock.json"]["dependency_scope"], locations["package-lock.json"]["direct"]) == (
        "runtime", False)
    assert (locations["worker/package-lock.json"]["dependency_scope"],
            locations["worker/package-lock.json"]["direct"]) == ("development", True)
    assert tasks[0]["occurrences_recorded"] is True
    assert result == before
    cli.display(result, True)
    assert json.loads(capsys.readouterr().out) == before


def test_history_identity_notices_location_changes_but_ignores_list_order():
    finding, = report()["findings"]
    reordered = deepcopy(finding)
    reordered["claim_evidence"]["occurrences"].reverse()
    assert cli._identity(reordered) == cli._identity(finding)
    single = deepcopy(finding)
    single["claim_evidence"]["occurrences"] = [single["claim_evidence"]["occurrences"][0]]
    assert cli._identity(single) != cli._identity(finding)
    changed_scope = deepcopy(finding)
    changed_scope["claim_evidence"]["occurrences"][1]["dependency_scope"] = "runtime"
    assert cli._identity(changed_scope) != cli._identity(finding)
