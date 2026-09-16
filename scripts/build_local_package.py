"""Build an isolated offline distribution from the shared, reviewed engine.

No imports from app are executed while collecting or relocating source files.
The generated source project also builds independently of the Shipit checkout.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = {"pyyaml", "tree-sitter", "tree-sitter-typescript", "pglast"}
EXTERNAL = {"yaml", "tree_sitter", "tree_sitter_typescript", "pglast"}
ALLOWED = {
    "app", "app.local_cli", "app.local_store", "app.logging_config", "app.log_context", "app.capabilities",
    "app.ingest", "app.ingest.validators", "app.report", "app.report.sarif", "app.report.plain_language",
    "app.sca", "app.sca.lockfiles", "app.sca.resolved_locks",
}


def module_path(root: Path, name: str) -> Path | None:
    path = root.joinpath(*name.split("."))
    for candidate in (path.with_suffix(".py"), path / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def imports(tree: ast.AST, root: Path, module: str = "") -> set[str]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "importlib":
                    raise ValueError("New dynamic application import needs an explicit relocation review")
                if alias.name == "app" or alias.name.startswith("app."):
                    raise ValueError("Use from-imports for relocatable application modules")
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise ValueError("Relative imports need an explicit relocation review")
            name = node.module or ""
            if name.split(".")[0] == "importlib" and not (
                    module == "app.scan.check_loading" and name == "importlib"
                    and all(a.name == "import_module" and a.asname is None for a in node.names)):
                raise ValueError("New dynamic application import needs an explicit relocation review")
            if name == "builtins" and any(a.name == "__import__" for a in node.names):
                raise ValueError("New dynamic application import needs an explicit relocation review")
            found.add(name)
            if name == "app" or name.startswith("app."):
                for alias in node.names:
                    child = name + "." + alias.name
                    if module_path(root, child):
                        found.add(child)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "optional_native_function":
                if (not node.args or not isinstance(node.args[0], ast.Constant)
                        or not isinstance(node.args[0].value, str)):
                    raise ValueError("Native check module must be a literal")
                found.add(node.args[0].value)
            elif node.func.id in {"import_module", "__import__"}:
                if not (module == "app.scan.check_loading" and node.func.id == "import_module"
                        and len(node.args) == 1 and isinstance(node.args[0], ast.Name)
                        and node.args[0].id == "module" and not node.keywords):
                    raise ValueError("New dynamic application import needs an explicit relocation review")
    return found


def source_files(root: Path) -> list[Path]:
    pending = ["app.local_cli"]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if name not in ALLOWED and not (name.startswith("app.scan.") or name == "app.scan"):
            raise ValueError(f"Module outside the offline boundary: {name}")
        if name in {"app.scan.pipeline", "app.scan.llm_scan"}:
            raise ValueError(f"Server orchestration cannot enter the local package: {name}")
        path = module_path(root, name)
        if path is None:
            raise ValueError(f"Missing application module: {name}")
        seen.add(name)
        # Importing a child executes every parent's __init__, so inspect those too.
        if "." in name:
            pending.append(name.rsplit(".", 1)[0])
        for imported in imports(ast.parse(path.read_text()), root, name):
            if imported == "app" or imported.startswith("app."):
                pending.append(imported)
            elif imported.split(".")[0] not in sys.stdlib_module_names | EXTERNAL:
                raise ValueError(f"Unexpected external dependency in {name}: {imported}")
    return sorted(module_path(root, name) for name in seen)


def relocate(source: str) -> str:
    """Change import sites only; preserve source lines, evidence and update URLs."""
    tree = ast.parse(source)
    lines = source.encode().splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    edits = []
    for node in ast.walk(tree):
        target = node
        replacement = None
        if isinstance(node, ast.ImportFrom) and (node.module == "app" or (node.module or "").startswith("app.")):
            original = ast.get_source_segment(source, node)
            replacement = re.sub(r"^(from(?:\s|\\\r?\n)+)app(?=[.\s])", r"\1drydock_local", original, count=1)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "optional_native_function"):
            target = node.args[0]
            if isinstance(target, ast.Constant) and isinstance(target.value, str) and target.value.startswith("app."):
                replacement = json.dumps("drydock_local" + target.value[3:])
        if replacement is not None:
            edits.append((offsets[target.lineno - 1] + target.col_offset,
                          offsets[target.end_lineno - 1] + target.end_col_offset, replacement.encode()))
    raw = source.encode()
    for start, end, replacement in sorted(edits, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    result = raw.decode()
    if any(isinstance(n, ast.ImportFrom) and (n.module == "app" or (n.module or "").startswith("app."))
           for n in ast.walk(ast.parse(result))):
        raise ValueError("Unrelocated application import")
    return result


def locked_requirements(root: Path, names: set[str]) -> tuple[str, list[str]]:
    text = (root / "requirements.txt").read_text()
    selected, pins = [], []
    for name in sorted(names):
        match = re.search(r"^" + re.escape(name) + r"==([^\s\\]+)[^\n]*\n(?:[ \t]+[^\n]*\n)*", text, re.M | re.I)
        if not match:
            raise ValueError(f"Missing runtime lock: {name}")
        pin = f"{name}=={match[1]}"
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match[0])
        if not hashes:
            raise ValueError(f"Missing runtime hashes: {name}")
        pins.append(pin)
        selected.append(pin + " \\\n" + " \\\n".join("    --hash=sha256:" + digest for digest in hashes))
    return "\n".join(selected) + "\n", pins


def stage(root: Path, destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=False)
    package = destination / "drydock_local"
    hashes = {}
    for path in source_files(root):
        relative = path.relative_to(root)
        output = destination / "drydock_local" / path.relative_to(root / "app")
        output.parent.mkdir(parents=True, exist_ok=True)
        source = path.read_text()
        output.write_text(relocate(source))
        hashes[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (package / "data").mkdir()
    for name in ("cve-catalog.json", "cve-catalog.json.sha256"):
        shutil.copyfile(root / "app/data" / name, package / "data" / name)
    raw = (package / "data/cve-catalog.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != (package / "data/cve-catalog.json.sha256").read_text().split()[0]:
        raise ValueError("Bundled catalog checksum mismatch")
    for source, name in (("local/pyproject.toml.in", "pyproject.toml"), ("LICENSE", "LICENSE"),
                         ("docs/local-drydock.md", "README.md")):
        shutil.copyfile(root / source, destination / name)
    lock, pins = locked_requirements(root, DEPENDENCIES)
    (destination / "requirements.txt").write_text(lock)
    (destination / "dependencies.txt").write_text("\n".join(pins) + "\n")
    config = tomllib.loads((destination / "pyproject.toml").read_text())
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root))
    version_tree = ast.parse((root / "app/scan/version.py").read_text())
    engine = next(ast.literal_eval(n.value) for n in version_tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "AUDIT_ENGINE_VERSION" for t in n.targets))
    info = {"package_version": config["project"]["version"], "engine_version": engine,
            "source_revision": revision, "source_dirty": dirty,
            "source_url": f"https://github.com/aiagent2046-coder/shipit/tree/{revision}",
            "source_sha256": hashes, "catalog_sha256": digest, "dependencies": pins}
    (package / "build-info.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    return info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--wheelhouse", action="store_true", help="download locked wheels for this OS/Python")
    parser.add_argument("--stage-only", action="store_true", help="prepare source without invoking the build backend")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    info = stage(ROOT, out / "source")
    (out / "build-requirements.txt").write_text(locked_requirements(ROOT, {"setuptools"})[0])
    if args.stage_only:
        print(json.dumps({"output": str(out), "modules": len(info["source_sha256"])}))
        return
    wheels = out / "wheelhouse"
    wheels.mkdir()
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--no-index",
                    "--wheel-dir", str(wheels), str(out / "source")], check=True)
    wheel = next(wheels.glob("drydock_local-*.whl"))
    lock = (out / "source/requirements.txt").read_text()
    if args.wheelhouse:
        subprocess.run([sys.executable, "-m", "pip", "download", "--require-hashes", "--only-binary=:all:",
                        "--dest", str(wheels), "-r", str(out / "source/requirements.txt")], check=True)
    checksum = hashlib.sha256(wheel.read_bytes()).hexdigest()
    lock += f"drydock-local=={info['package_version']} --hash=sha256:{checksum}\n"
    (out / "install.txt").write_text(lock)
    shutil.copyfile(ROOT / "local/install.sh", out / "install.sh")
    shutil.copyfile(ROOT / "docs/local-drydock.md", out / "README.md")
    (out / "build-info.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    # A source archive keeps the distribution rebuildable without a Git checkout.
    with tempfile.TemporaryDirectory() as temporary:
        subprocess.run([sys.executable, "-c", "import setuptools.build_meta as b; b.build_sdist(" +
                        repr(temporary) + ")"], cwd=out / "source", check=True)
        shutil.copyfile(next(Path(temporary).glob("*.tar.gz")), out / "drydock-local-source.tar.gz")
    print(json.dumps({"output": str(out), "wheel": wheel.name, "wheel_bytes": wheel.stat().st_size,
                      "modules": len(info["source_sha256"]), "dependencies": info["dependencies"]}))


if __name__ == "__main__":
    main()
