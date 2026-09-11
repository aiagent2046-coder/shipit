"""Bundled dependencies must neither produce own-code findings nor hide them.

Keep the archive order explicit: over 400 harmless dependency files before a
real own-code signal reproduced the missed findings that this regression pins.
"""

import io
import zipfile

import pytest

from app.scan.outbound_url import scan_outbound_url
from app.scan.path_traversal import scan_path_traversal
from app.scan.tls_verification import scan_tls_verification
from app.scan.unsafe_deserialization import scan_unsafe_deserialization

CASES = [
    pytest.param(
        scan_tls_verification, "tls-verification-disabled", "client.py",
        'import requests\nrequests.get("https://example.com", verify=False)\n',
        id="tls-python",
    ),
    pytest.param(
        scan_tls_verification, "tls-verification-disabled", "client.ts",
        'import https from "node:https";\nnew https.Agent({rejectUnauthorized: false});\n',
        id="tls-typescript",
    ),
    pytest.param(
        scan_unsafe_deserialization, "unsafe-deserialization", "restore.py",
        "import pickle\ndef restore(payload):\n    return pickle.loads(payload)\n",
        id="deserialization",
    ),
    pytest.param(
        scan_outbound_url, "python-outbound-request-unvalidated-url", "proxy.py",
        'from fastapi import FastAPI\nimport httpx\napp = FastAPI()\n'
        '@app.get("/proxy")\ndef proxy(url: str):\n    return httpx.get(url)\n',
        id="outbound-url",
    ),
    pytest.param(
        scan_path_traversal, "path-traversal-file-sink", "files.py",
        'from fastapi import FastAPI\napp = FastAPI()\n'
        '@app.get("/download")\ndef download(path: str):\n    return open(path).read()\n',
        id="path-traversal",
    ),
]


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, source in files:
            zf.writestr(path, source)
    buf.seek(0)
    return buf


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("wrapper", ["", "project/"])
@pytest.mark.parametrize("dependency", [
    "node_modules", "vendor", ".venv", "venv", "site-packages", "bower_components", ".tox", ".nox",
])
def test_own_code_fires_but_identical_dependency_code_is_excluded(
    scanner, rule_id, filename, source, wrapper, dependency,
):
    own_path = f"{wrapper}app/{filename}"
    own_findings = scanner(archive([(own_path, source)]))
    assert len(own_findings) == 1
    assert own_findings[0].rule_id == rule_id
    assert own_findings[0].file == own_path

    dependency_path = f"{wrapper}{dependency}/library/{filename}"
    assert scanner(archive([(dependency_path, source)])) == []
    # An own-code migration remains eligible, but migration names inside a
    # dependency must not bypass the independent dependency exclusion.
    assert scanner(archive([(f"{wrapper}{dependency}/library/migrations/{filename}", source)])) == []
    assert scanner(archive([(dependency_path, source), (own_path, source)])) == own_findings


@pytest.mark.parametrize("scanner,rule_id,filename,source", CASES)
@pytest.mark.parametrize("wrapper", ["", "project/"])
@pytest.mark.parametrize("dependency", [".venv", "node_modules", "vendor"])
def test_over_400_dependencies_before_own_code_do_not_consume_its_file_budget(
    scanner, rule_id, filename, source, wrapper, dependency,
):
    own_file = (f"{wrapper}app/{filename}", source)
    suffix = filename.rsplit(".", 1)[-1]
    harmless = "pass\n" if suffix == "py" else "export const present = true;\n"
    dependencies = [
        (f"{wrapper}{dependency}/library/module_{number}.{suffix}", harmless)
        for number in range(401)
    ]
    expected = scanner(archive([own_file]))
    assert len(expected) == 1
    assert expected[0].rule_id == rule_id
    assert scanner(archive([*dependencies, own_file])) == expected
    assert scanner(archive([own_file, *dependencies])) == expected
