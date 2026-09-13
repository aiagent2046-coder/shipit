"""Rebuild pinned native wheels in a configured Pyodide cross-build environment.

Run with Python 3.14.2 and pyodide-build 0.39.0 after sourcing emsdk_env.sh.
Downloads are build-time only. Output is separate from the reviewed vendored
wheels; run parser and corpus parity before updating the manifest's hashes.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
from urllib.request import urlopen


def download(source):
    with urlopen(source["url"], timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError(f"Source integrity mismatch: {source['url']}")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new scratch directory for sources and wheels")
    args = parser.parse_args()
    manifest = json.loads((Path(__file__).resolve().parents[1] / "native/manifest.json").read_text())
    if platform.python_version() != manifest["python"]:
        raise SystemExit(f"Requires host Python {manifest['python']}")
    from importlib.metadata import version
    if version("pyodide-build") != manifest["pyodide_build"]:
        raise SystemExit("pyodide-build version differs from the manifest")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(manifest["source_date_epoch"]))
    built = []
    for pkg in manifest["packages"]:
        source = output / pkg["name"]
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(download(pkg["source"]))) as archive:
            archive.extractall(source, filter="data")
        roots = list(source.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("Expected one source root")
        root = roots[0]
        if supplement := pkg.get("supplement"):
            # The TypeScript PyPI sdist omits these seven headers. Copy only
            # the manifest allowlist from the official npm release, same version.
            with tarfile.open(fileobj=io.BytesIO(download(supplement))) as archive:
                for name in supplement["files"]:
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.extractfile(f"package/{name}").read())
        with (output / f"{pkg['name']}.log").open("w") as log:
            subprocess.run(["pyodide", "build", "-o", str(output / "wheels")],
                           cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        wheel = output / "wheels" / pkg["file_name"]
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        built.append({"file_name": wheel.name, "sha256": digest,
                      "matches_vendored": digest == pkg["sha256"]})
    (output / "rebuilt.json").write_text(json.dumps(built, indent=2) + "\n")
    print(json.dumps(built, indent=2))


if __name__ == "__main__":
    main()
