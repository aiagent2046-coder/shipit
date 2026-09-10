"""Bytes turned back into objects through a format that can run code.

WHY THIS EXISTS. `pickle` is not a data format, it is a small virtual machine: a
pickle payload names classes and calls them, and `pickle.loads` on bytes somebody
else chose is remote code execution with extra steps. `yaml.load` without a safe
loader had the same power in PyYAML before 5.1, and still does when it is handed
`Loader=yaml.Loader`. The static stage read none of this -- no rule in app/scan
matched `pickle`, `yaml.load`, `dill`, `marshal`, `jsonpickle` or `torch.load`
(measured with the gap probe before writing).

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. A call that deserialises through a
format with code-execution primitives: pickle/cPickle/dill/marshal, pandas'
read_pickle, jsonpickle.decode, `yaml.load`/`load_all` without a safe loader,
`yaml.unsafe_load`, and `torch.load(..., weights_only=False)`. That is a fact about
the call. It is NOT a claim that the bytes are attacker-controlled: a pickle written
by the same process and read back is ordinary code, and this rule cannot tell the
two apart. The finding says what the call does and states that the provenance was
not read. Silence is not a certificate either -- a loader reached through a variable
(`loader = pickle.loads`) is not resolved, and JS/TS deserialisation is out of scope
entirely.

WHY AST, NOT A GREP. The rule turns on which ARGUMENT is present:

    yaml.load(data)                                  arbitrary objects
    yaml.load(data, Loader=yaml.SafeLoader)           a subset of YAML values
    yaml.safe_load(data)                              the same thing, spelled once
    torch.load(path, weights_only=True)               tensors, not objects
    torch.load(path)                                  version-dependent, see below

A regex that matched `yaml.load(` would report the first two, and one that matched
the function name would miss `load_all`. The tree shows the keyword that decides.

TORCH IS VERSION-DEPENDENT, AND THE RULE ONLY REPORTS THE EXPLICIT CASE. Since 2.6
`torch.load` defaults to `weights_only=True`; before that it did not. Reading
versions is not something this rule does, so it reports `weights_only=False` (a
deliberate switch back to arbitrary-object loading) and leaves a bare `torch.load`
alone, with that gap named here rather than papered over.

NEVER EXECUTES THE UPLOADED CODE. ast.parse builds a tree; nothing is imported,
run, unpickled or fetched.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "unsafe-deserialization"

# Modules whose loaders execute code, mapped to whether every member counts. A
# module listed here is not a name match: the call is looked up by (module, member)
# so `yaml.load` can be judged on its Loader while `yaml.safe_load` never is.
_ALWAYS_UNSAFE = {
    "pickle": {"load", "loads", "Unpickler"},
    "cPickle": {"load", "loads", "Unpickler"},
    "_pickle": {"load", "loads", "Unpickler"},
    "dill": {"load", "loads", "Unpickler"},
    "marshal": {"load", "loads"},
    "jsonpickle": {"decode"},
    "pandas": {"read_pickle"},
}

# YAML loaders that do NOT execute arbitrary objects. Anything else -- including no
# Loader at all, which is the pre-5.1 default -- is reported.
_SAFE_YAML_LOADERS = frozenset({
    "CSafeLoader", "CFullLoader", "FullLoader", "SafeLoader", "safe_load", "full_load",
})
_YAML_LOADERS = frozenset({"load", "load_all"})
_YAML_UNSAFE_HELPERS = frozenset({"unsafe_load", "unsafe_load_all"})

# torch.load defends itself with an argument rather than a loader class.
_TORCH_FLAG = "weights_only"

# Mirrors the sibling scanners.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


@dataclass(frozen=True)
class _Evidence:
    line: int
    what: str


def _imports(tree: ast.Module) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """(local name -> module for `import X as Y`, local name -> (module, member)).

    The rule has to read the code the way the reader does: `import pandas as pd`
    makes `pd.read_pickle` the same call as `pandas.read_pickle`, and
    `from pickle import loads` makes a bare `loads(...)` a pickle load. The smoke
    test caught the first of those -- an alias map keyed on the real module name
    silently missed `pd.read_pickle`, which is how the call appears in real code.
    Only module-level imports of THIS file are read; a loader imported in another
    module and passed in is out of scope, and the finding's text says the trace is
    local.
    """
    modules: dict[str, str] = {}
    members: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                # `import pandas` -> pandas; `import pandas as pd` -> pd; `import a.b`
                # binds the root name `a`, which is what the code then calls through.
                modules[alias.asname or root] = root if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            root = node.module.split(".")[0]
            for alias in node.names:
                members[alias.asname or alias.name] = (root, alias.name)
    return modules, members


def _dotted(node: ast.AST) -> tuple[str, str]:
    """(prefix, member) for a call target, or ("", "").

    `pickle.loads` -> ("pickle", "loads"); `pd.read_pickle` -> ("pd", "read_pickle").
    A deeper chain keeps its last two names, which is what a reader recognises.
    """
    if isinstance(node, ast.Attribute):
        prefix = node.value
        if isinstance(prefix, ast.Attribute):
            return prefix.attr, node.attr
        if isinstance(prefix, ast.Name):
            return prefix.id, node.attr
        return "", node.attr
    return "", ""


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _safe_loader_name(node: ast.AST) -> str:
    """The Loader argument's name, however it was spelled (`yaml.SafeLoader`)."""
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _loader_argument(call: ast.Call) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            return keyword.value
    # `yaml.load(stream, Loader)` also accepts it positionally, second.
    return call.args[1] if len(call.args) > 1 else None


def _evidence(tree: ast.Module) -> list[_Evidence]:
    found: list[_Evidence] = []
    modules, members = _imports(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        prefix, member = _dotted(node.func)
        if not member and isinstance(node.func, ast.Name):
            # `from pickle import loads` -> the bare call IS a pickle load.
            imported = members.get(node.func.id)
            if imported:
                prefix, member = imported
        if not member:
            continue
        # Resolve the alias the way Python does before judging the name.
        module = modules.get(prefix, prefix)
        if member in _ALWAYS_UNSAFE.get(module, frozenset()):
            found.append(_Evidence(node.lineno, f"calls {module}.{member}()"))
            continue
        if module == "torch" and member == "load":
            for keyword in node.keywords:
                if keyword.arg == _TORCH_FLAG and _is_false(keyword.value):
                    found.append(_Evidence(node.lineno, "calls torch.load() with weights_only=False"))
            continue
        if module != "yaml":
            continue
        if member in _YAML_UNSAFE_HELPERS:
            found.append(_Evidence(node.lineno, f"calls yaml.{member}()"))
            continue
        if member not in _YAML_LOADERS:
            continue
        loader = _loader_argument(node)
        if loader is None:
            found.append(_Evidence(node.lineno, f"calls yaml.{member}() with no Loader argument"))
            continue
        if _safe_loader_name(loader) not in _SAFE_YAML_LOADERS:
            found.append(_Evidence(
                node.lineno, f"calls yaml.{member}() with Loader={_safe_loader_name(loader) or '?'}"))
    return found


def scan_unsafe_deserialization(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [info for info in archive.infolist()
                 if not info.is_dir() and info.filename.endswith(".py")
                 and info.file_size <= _MAX_FILE_BYTES
                 and not is_non_production_path(info.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                tree = ast.parse(archive.read(info).decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                # Unparseable is "not read", not "clean"; the coverage text says so.
                continue
            for item in _evidence(tree):
                if len(findings) >= _MAX_FINDINGS:
                    break
                findings.append(_finding(info.filename, item))
    return findings


def _finding(path: str, item: _Evidence) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="Data is turned back into objects through a format that can run code",
        severity="high",
        # The call is certain -- ast read it, and the format's power is not in
        # doubt. What is not verified is where the bytes came from: the same call
        # reading a file this process wrote a minute ago is ordinary code.
        confidence=0.8,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} {item.what}. This format can name classes and call them while "
            "it loads, so bytes chosen by somebody else are executed with this process's "
            "privileges -- the classic route from an uploaded file or a message payload to "
            "running code on the server. Where the bytes come from has NOT been verified: a "
            "payload written by the same process and read back is ordinary code, and this "
            "call looks the same either way."
        ),
        fix_hint=(
            "Use a format that carries values rather than objects when the data crosses a "
            "trust boundary: json (or msgpack/cbor) with an explicit schema. Where a pickle-"
            "based format is unavoidable, verify a signature or checksum over the payload "
            "before loading it, and never load data that arrived in a request, an upload, or "
            "a message from another system."
        ),
    )
