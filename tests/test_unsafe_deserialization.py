"""Synthetic source fixtures: no uploaded code is executed, imported or unpickled.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned with its premise asserted. shipit reads YAML
    in its own secrets scanner -- `yaml.compose(text, Loader=yaml.SafeLoader)` --
    and parses JSON in dozens of places, so the silence below is silence over code
    that deserialises, not silence over an empty archive.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.static import run_static_scan
from app.scan.unsafe_deserialization import RULE_ID, scan_unsafe_deserialization

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''import pickle


def restore(payload):
    return pickle.loads(payload)
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/restore.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_deserialising_through_a_code_capable_format_is_a_high_severity_signal():
    source = POSITIVE
    findings = [f for f in run_static_scan(archive(source))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "pickle.loads(" in source.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.8
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "Where the bytes come from has NOT been verified" in f["explanation"]


@pytest.mark.parametrize("source", [
    # a value format
    "import json\nobj = json.loads(text)\n",
    # literals without calls
    "import ast\nobj = ast.literal_eval(text)\n",
    # the safe YAML spellings, including the loader passed positionally
    "import yaml\ndoc = yaml.safe_load(text)\n",
    "import yaml\ndoc = yaml.load(text, Loader=yaml.SafeLoader)\n",
    "import yaml\ndoc = yaml.load(text, yaml.FullLoader)\n",
    # serialising, not deserialising
    "import pickle\nblob = pickle.dumps(obj)\n",
    # the hardened torch call, and the version-dependent bare one
    "import torch\nm = torch.load(path, weights_only=True)\n",
    "import torch\nm = torch.load(path)\n",
    # name shadowing: a local function called loads is not a pickle load
    "def loads(x):\n    return x\n\nobj = loads(payload)\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_unsafe_deserialization(archive(source)) == []


def test_the_import_map_resolves_aliases_the_way_python_does():
    """`import pandas as pd`, `from pickle import loads`, and a deeper path.

    The smoke test found the first of these slipping past a rule keyed on the real
    module name -- `pd.read_pickle` is how the call appears in real code.
    """
    cases = [
        "import pandas as pd\ndf = pd.read_pickle(path)\n",
        "from pickle import loads as pl\nobj = pl(blob)\n",
        "import dill\nobj = dill.loads(blob)\n",
        "import pickle as p\nobj = p.loads(blob)\n",
    ]
    for source in cases:
        assert scan_unsafe_deserialization(archive(source)), source
    # an alias of a SAFE module is not a finding, however short the name
    assert scan_unsafe_deserialization(archive("import json as p\nobj = p.loads(text)\n")) == []


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "shadowed-loader-parameter": ("app/restore.py", "restore(codec, data)", "restore(data)"),
    "safe-yaml-import-alias": ("app/restore.py", "SafeLoader as SL", "UnsafeLoader as SL"),
    "yaml-safe-loaders": ("app/config_safe.py", "yaml.load(text, Loader=yaml.SafeLoader)",
                          "yaml.load(text)"),
    "json-and-literal-eval": ("app/data_in.py", "import json", "import pickle as json"),
    "pickle-dumps-is-the-safe-direction": ("app/write_cache.py", "pickle.dump(obj, handle)",
                                           "pickle.load(handle)"),
    "torch-load-weights-only-true": ("app/models_safe.py", "weights_only=True", "weights_only=False"),
    "torch-load-without-the-flag": ("app/models_bare.py", "torch.load(path)",
                                    "torch.load(path, weights_only=False)"),
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
    assert scan_unsafe_deserialization(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_unsafe_deserialization(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard whose premise is asserted.

    If it fires, read the reported line first: either the product really does load
    objects through one of these formats, or the rule grew a false positive.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    text = "\n".join(sources.values())
    # Premise: the product deserialises, and it does it safely where it matters.
    assert re.search(r"Loader=yaml\.SafeLoader", text), "our own safe YAML read should still be there"
    assert len(re.findall(r"json\.loads\(", text)) > 10, "and JSON parsing is everywhere"
    assert scan_unsafe_deserialization(archive(sources)) == []


@pytest.mark.parametrize("source", [
    "def restore(pickle, data):\n    return pickle.loads(data)\n",
    "import pickle\ndef restore(pickle, data):\n    return pickle.loads(data)\n",
    "import pickle\nimport json\npickle = json\npickle.loads(data)\n",
    "from pickle import loads\ndef restore(loads, data):\n    return loads(data)\n",
    "from pickle import loads\ndef loads(data):\n    return data\nloads(data)\n",
    "def restore(service, data):\n    return service.pickle.loads(data)\n",
    "from . import pickle\npickle.loads(data)\n",
    "import json as codec\ndef unrelated():\n    import pickle as codec\n"
    "def restore(data):\n    return codec.loads(data)\n",
    "import pickle as codec\ndef restore(data):\n    return codec.loads(data)\n"
    "import json as codec\n",
    "import pickle\ndef restore(data):\n    result = pickle.loads(data)\n"
    "    pickle = None\n    return result\n",
    "import pickle\n(lambda pickle: pickle.loads(data))(decoder)\n",
    "import pickle\n[pickle.loads(data) for pickle in decoders]\n",
    "class Local:\n    import pickle\n    def restore(self, data):\n"
    "        return pickle.loads(data)\n",
    "import pickle\ndef overwrite():\n    global pickle\n    pickle = None\n"
    "def restore(data):\n    return pickle.loads(data)\n",
    "import pickle\nfrom extension import *\npickle.loads(data)\n",
    "import pickle\nimport pickle as p\np.loads = custom_loader\npickle.loads(data)\n",
    "from pickle import loads\nimport pickle\npickle.loads = custom_loader\nloads(data)\n",
    "import yaml\ndef restore(SafeLoader, data):\n"
    "    return yaml.load(data, Loader=SafeLoader)\n",
    "import yaml\nyaml.load(data, **options)\n",
])
def test_unknown_or_shadowed_objects_are_not_claimed_to_be_library_loaders(source):
    assert scan_unsafe_deserialization(archive(source)) == []


@pytest.mark.parametrize("source", [
    "import pickle as codec\ndef unrelated():\n    import json as codec\n"
    "def restore(data):\n    return codec.loads(data)\n",
    "def restore(data):\n    from pickle import loads as decode\n    return decode(data)\n",
    "import pickle\nclass Local:\n    import json as pickle\n"
    "    def restore(self, data):\n        return pickle.loads(data)\n",
    "import pickle\ndef outer():\n    def inner(data):\n        return pickle.loads(data)\n",
    "import pickle\npickle = pickle.loads(data)\n",
    "import pickle\nresult = pickle.loads(data)\nimport json as pickle\n",
    "import yaml\nfrom yaml import UnsafeLoader as SafeLoader\n"
    "yaml.load(data, Loader=SafeLoader)\n",
    "from yaml.loader import UnsafeLoader as SL\nfrom yaml import load\nload(data, SL)\n",
])
def test_stable_imports_survive_unrelated_scopes_and_import_aliases(source):
    findings = scan_unsafe_deserialization(archive(source))
    assert len(findings) == 1
    assert findings[0].severity == "high"


@pytest.mark.parametrize("name", ["BaseLoader", "CBaseLoader", "SafeLoader", "CSafeLoader",
                                 "FullLoader", "CFullLoader"])
def test_yaml_value_loaders_are_silent_under_import_aliases(name):
    source = f"import yaml\nfrom yaml import {name} as SL\nyaml.load(data, Loader=SL)\n"
    assert scan_unsafe_deserialization(archive(source)) == []
    unsafe = source.replace(f"import {name} as SL", "import UnsafeLoader as SL")
    assert len(scan_unsafe_deserialization(archive(unsafe))) == 1


def test_unpickler_constructor_does_not_claim_to_deserialize():
    source = "import pickle\nprepared = pickle.Unpickler(stream)\n"
    assert scan_unsafe_deserialization(archive(source)) == []
    loaded = source.replace("Unpickler(stream)", "Unpickler(stream).load()")
    findings = scan_unsafe_deserialization(archive(loaded))
    assert len(findings) == 1
    assert "Unpickler.load" in findings[0].explanation


def test_marshal_warning_distinguishes_returning_code_from_executing_it():
    findings = scan_unsafe_deserialization(archive("import marshal\nmarshal.loads(data)\n"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "medium"
    assert "does not execute it" in finding.explanation
    assert "does not establish arbitrary code execution" in finding.explanation


def test_missing_yaml_loader_is_an_unresolved_version_warning():
    finding, = scan_unsafe_deserialization(archive("import yaml\nyaml.load(data)\n"))
    assert finding.severity == "medium"
    assert "Modern PyYAML requires Loader and raises TypeError" in finding.explanation
    assert "installed version was not resolved" in finding.explanation


def test_untrusted_checksum_is_not_suggested_as_authentication():
    finding, = scan_unsafe_deserialization(archive(POSITIVE))
    assert "HMAC or digital signature" in finding.fix_hint
    assert "checksum supplied alongside untrusted bytes does not authenticate" in finding.fix_hint


def test_deep_or_large_ast_is_outside_the_bounded_trace():
    # Both inputs parse but would exceed the detector's declared traversal budget.
    assert scan_unsafe_deserialization(archive("x = " + "a." * 110 + "load(data)\n")) == []
    large = "x = 1\n" * 6000 + POSITIVE
    assert scan_unsafe_deserialization(archive(large)) == []
