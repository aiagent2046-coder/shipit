import base64
import hashlib

from app.scan.supply import binary_evidence as binary
from app.scan.supply.obfuscation_delta import analyze_python_obfuscation
from tests.supply.binary_forensics.test_binary_evidence import elf, with_report


def test_clean_python_code_has_zero_obfuscation_delta():
    clean = b"""
import subprocess

def version() -> str:
    res = subprocess.run(["git", "--version"], check=True, capture_output=True, text=True)
    return res.stdout.strip()
"""
    result = analyze_python_obfuscation(clean, file_path="app/git_info.py")
    assert result["status"] == "completed"
    assert result["delta_score"] == 0
    assert result["signals"] == []
    assert result["ffi_targets"] == []


def test_llm_evasion_patterns_and_ffi_bridge_are_measured_deterministically():
    b64_cmd = base64.b64encode(b"/bin/sh -c id").decode("ascii")
    evasive = f"""
import base64
import ctypes
import subprocess as sp

if False:
    decoy = "harmless"

def trigger(payload: bytes):
    try:
        lib = ctypes.CDLL("./native/" + "bridge.so")
        cmd = base64.b64decode("{b64_cmd}")
        runner = sp.Popen
        dyn = getattr(__import__("o" + "s"), "sys" + "tem")
        runner(cmd, shell=True)
        dyn("id")
    except Exception:
        pass
""".encode("utf-8")

    result = analyze_python_obfuscation(evasive, file_path="pkg/loader.py")
    assert result["status"] == "completed"
    kinds = {sig["kind"] for sig in result["signals"]}
    assert {
        "constant_branch_guard",
        "encoded_sensitive_constant",
        "dangerous_callable_alias",
        "dynamic_import_sink",
        "dynamic_getattr_sink",
        "silent_exception_swallow",
    } <= kinds
    assert result["delta_score"] >= 14
    assert result["ffi_targets"] == [{
        "library_arg": "./native/bridge.so",
        "dynamic_path": False,
        "split_ops": 1,
        "span": result["ffi_targets"][0]["span"],
    }]


def _v2_report(body=None):
    body = elf() if body is None else body
    digest = hashlib.sha256(body).hexdigest()
    return {
        "version": 1,
        "scope": "binary_static",
        "profile": binary.PROFILE,
        "status": "completed",
        "reason": "static_export_completed",
        "artifact": {"sha256": digest, "bytes": len(body), "format": "ELF64LE", "machine": 62},
        "provider": {
            "name": "ghidra",
            "version": binary.GHIDRA_VERSION,
            "java_major": 25,
            "java_version": "25.0.1",
            "distribution_sha256": binary.DISTRIBUTION_SHA256,
            "exporter_sha256": binary.EXPORTER_SHA256,
        },
        "facts": {
            "version": 2,
            "ghidra_version": binary.GHIDRA_VERSION,
            "executable_sha256": digest,
            "executable_format": "Executable and Linking Format (ELF)",
            "language_id": "x86:LE:64:default",
            "compiler_spec_id": "gcc",
            "image_base": "ram:00400000",
            "analysis_timed_out": False,
            "truncated": False,
            "functions": [
                {
                    "entry": "ram:00401000",
                    "name": "run_plugin",
                    "body_addresses": 48,
                    "basic_blocks": 3,
                    "cfg_edges": 3,
                    "indirect_calls": 0,
                    "is_thunk": False,
                },
                {
                    "entry": "ram:00401040",
                    "name": "internal_dispatch",
                    "body_addresses": 24,
                    "basic_blocks": 1,
                    "cfg_edges": 0,
                    "indirect_calls": 1,
                    "is_thunk": False,
                },
            ],
            "imports": [
                {"library": "libc.so.6", "name": "system", "external_location": "EXTERNAL:00000001"},
            ],
            "exports": [
                {"entry": "ram:00401000", "name": "run_plugin"},
            ],
            "call_edges": [
                {"caller": "ram:00401000", "target": "ram:00401040", "target_kind": "internal"},
                {"caller": "ram:00401040", "target": "EXTERNAL:00000001", "target_kind": "import"},
            ],
        },
        "runtime_verified": False,
        "automatic_patch": False,
        "limitations": list(binary.PRODUCER_LIMITATIONS),
    }


def test_ghidra_v2_call_graph_is_validated_and_traces_export_to_system_import():
    raw = with_report(_v2_report())
    collected = binary.collect_binary_evidence(raw)
    assert collected["status"] == "completed"
    facts = collected["artifacts"][0]["facts"]
    summary = binary.summarize_binary_reachability(facts)
    assert summary is not None
    assert summary["export_count"] == 1
    assert summary["call_edge_count"] == 2
    assert summary["reachable_sensitive_imports"] == [{
        "export_entry": "ram:00401000",
        "export_name": "run_plugin",
        "import_library": "libc.so.6",
        "import_name": "system",
        "external_location": "EXTERNAL:00000001",
        "hop_count": 2,
        "call_chain": ["ram:00401000", "ram:00401040"],
    }]
    assert len(summary["indirect_call_stubs"]) == 1


def test_ghidra_v2_rejects_dangling_call_edge_targets():
    broken = _v2_report()
    broken["facts"]["call_edges"][0]["target"] = "ram:00409999"
    collected = binary.collect_binary_evidence(with_report(broken))
    assert collected["status"] == "unavailable"
    assert collected["artifacts"][0]["reason"] == "invalid_report"


def test_python_indirect_const_propagation_join_reverse_and_importlib():
    indirect = b"""
import ctypes
import importlib

def stealth():
    try:
        p1 = "./native/"
        p2 = "hook.so"
        lib = ctypes.CDLL(p1 + p2)
        mod_name = "".join(["s", "u", "b", "p", "r", "o", "c", "e", "s", "s"])
        m = importlib.import_module(mod_name)
        attr = "nepoP"[::-1]
        fn = getattr(m, attr)
        return lib, fn
    except Exception:
        pass
"""
    res = analyze_python_obfuscation(indirect, file_path="pkg/stealth.py")
    assert res["status"] == "completed"
    kinds = {s["kind"] for s in res["signals"]}
    assert {
        "split_sensitive_literal",
        "dynamic_import_sink",
        "dynamic_getattr_sink",
        "silent_exception_swallow",
    } <= kinds
    assert res["delta_score"] >= 11
    assert res["ffi_targets"][0]["library_arg"] == "./native/hook.so"


def test_broken_llm_splice_hallucination_and_split_ffi_path_are_caught():
    """Pinned from a real qwen2.5-coder:7b escape sample:
    model mis-spliced 'os'+'system' into getattr(__import__('sys'), 'tem')."""
    sample = b"""
import base64
import ctypes

def boot():
    try:
        lib = ctypes.CDLL('./native/' + 'hook.so')
        fn = getattr(__import__('sys'), 'tem')
        return lib, fn
    except Exception:
        pass
"""
    res = analyze_python_obfuscation(sample, file_path="variant_00_loader.py")
    kinds = {s["kind"] for s in res["signals"]}
    assert "split_ffi_library_path" in kinds
    assert "hallucinated_stdlib_getattr" in kinds
    assert "silent_exception_swallow" in kinds
    assert res["delta_score"] >= 9
