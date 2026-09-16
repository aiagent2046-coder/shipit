"""Generated Next.js manifests must not replace the project's dependency graph."""
import io
import json
import zipfile

from app.sca.lockfiles import (
    MAX_EXCLUDED_MANIFESTS,
    MAX_LOCKFILES,
    collect_dependency_inventory,
    unusable_lockfiles,
)
from app.scan.cve_match import match_archive


def _archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


def _lock(version):
    return json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/widget": {"version": version},
    }})


def _catalog():
    return {"schema_version": 1, "source": {
        "repository": "https://github.com/CVEProject/cvelistV5",
        "commit": "a" * 40, "generated_at": "2026-09-14T12:00:00Z",
    }, "stats": {}, "packages": {"npm:widget": [{
        "id": "CVE-2025-12345", "title": "Example advisory",
        "default_status": "unaffected", "versions": [{
            "version": "1.0.0", "lessThan": "2.0.0",
            "status": "affected", "versionType": "semver",
        }],
    }]}}


def test_generated_pins_and_manifest_only_outputs_are_reported_as_exclusions():
    data = _archive({
        "web/package-lock.json": _lock("2.0.0"),
        "web/.next/package-lock.json": _lock("1.2.3"),
        "web/.next/package.json": "{}",
        "web/.next/build/package.json": "{}",
    })
    result = match_archive(data, _catalog())
    assert result["findings"] == []
    coverage = result["coverage"]
    assert coverage["status_counts"]["unaffected"] == 1
    assert coverage["status"] == "checked"
    assert coverage["incomplete_manifests"] == {}
    assert coverage["excluded_manifests"] == {
        "web/.next/package-lock.json": "generated_next_build",
        "web/.next/package.json": "generated_next_build",
        "web/.next/build/package.json": "generated_next_build",
    }


def test_generated_lockfiles_do_not_spend_the_selection_budget():
    files = {f".next/{index}/package-lock.json": "broken"
             for index in range(MAX_LOCKFILES + 1)}
    files["apps/frontend/package-lock.json"] = _lock("1.2.3")
    inventory = collect_dependency_inventory(_archive(files))
    assert inventory.manifests == ["apps/frontend/package-lock.json"]
    assert [(dep.name, dep.version) for dep in inventory.dependencies] == [
        ("widget", "1.2.3"),
    ]
    assert inventory.incomplete_manifests == {}
    assert len(inventory.excluded_manifests) == MAX_LOCKFILES + 1


def test_exclusion_requires_exact_directory_component_and_preserves_other_builds():
    paths = ["dist", "build", "my.next", ".next-backup", "next"]
    inventory = collect_dependency_inventory(_archive({
        f"{directory}/requirements.txt": f"package{index}==1.0.0\n"
        for index, directory in enumerate(paths)
    }))
    assert inventory.found == len(paths)
    assert inventory.excluded_manifests == {}
    # An ordinary source manifest under build remains an honest coverage gap.
    result = match_archive(_archive({"build/package.json": "{}"}), _catalog())
    assert result["coverage"]["incomplete_manifests"] == {
        "build/package.json": "unresolved",
    }


def test_unsupported_generated_manifests_are_excluded_consistently():
    data = _archive({"web/.next/go.mod": "module example\n",
                     "web/.next/yarn.lock": "ignored",
                     "go.mod": "module project\n"})
    assert unusable_lockfiles(data) == ["go.mod"]
    result = match_archive(data, _catalog())
    assert result["coverage"]["incomplete_manifests"] == {"go.mod": "unsupported"}
    assert set(result["coverage"]["excluded_manifests"]) == {
        "web/.next/go.mod", "web/.next/yarn.lock",
    }


def test_exclusion_metadata_is_bounded_without_selecting_overflow_manifests():
    files = {f".next/{index}/package.json": "{}"
             for index in range(MAX_EXCLUDED_MANIFESTS + 3)}
    files[".next/chunks/app.js"] = "// not a manifest"
    inventory = collect_dependency_inventory(_archive(files))
    assert len(inventory.excluded_manifests) == MAX_EXCLUDED_MANIFESTS
    assert inventory.excluded_manifests_truncated == 3
    assert inventory.found == 0
    assert inventory.incomplete_manifests == {}
