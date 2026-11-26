"""Verify 2-pass cross-file constant & re-export unrolling across Python and TypeScript."""
import hashlib
import json

from app.scan import binary_evidence as binary
from app.scan.forensic_chain import run_forensic_investigation
from app.scan.obfuscation_delta import analyze_archive_code_dna
from tests.test_binary_evidence import archive, elf


def test_three_file_split_python_payload_and_ffi_bridge_are_reconstructed_to_ghidra_execve():
    elf_bytes = elf(b"\x90" * 24)
    digest = hashlib.sha256(elf_bytes).hexdigest()

    # File 1: looks completely innocent (delta_score == 0 in isolation)
    constants_py = b'PART_A = "sub"\nPART_B = "process"\nNATIVE_DIR = "./native/"\n'
    # File 2: intermediate re-assembler
    reexport_py = (
        b"from pkg.constants import NATIVE_DIR, PART_A, PART_B\n"
        b"TARGET_MOD = PART_A + PART_B\n"
        b'TARGET_SO = NATIVE_DIR + "hook.so"\n'
    )
    # File 3: consumer using only neutral identifiers imported from File 2!
    runner_py = (
        b"import ctypes\n"
        b"from pkg.reexport import TARGET_MOD, TARGET_SO\n\n"
        b"def fire():\n"
        b"    try:\n"
        b"        lib = ctypes.CDLL(TARGET_SO)\n"
        b'        fn = getattr(__import__(TARGET_MOD), "Po" + "pen")\n'
        b"        return lib, fn\n"
        b"    except Exception:\n"
        b"        pass\n"
    )

    ghidra_rep = {
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
            "image_base": "ram:00100000",
            "analysis_timed_out": False,
            "truncated": False,
            "functions": [
                {"entry": "ram:00101000", "name": "entry_fn", "body_addresses": 20, "basic_blocks": 1, "cfg_edges": 0, "indirect_calls": 0, "is_thunk": False},
            ],
            "imports": [
                {"library": "libc.so.6", "name": "execve", "external_location": "EXTERNAL:00000001"},
            ],
            "exports": [{"entry": "ram:00101000", "name": "entry_fn"}],
            "call_edges": [
                {"caller": "ram:00101000", "target": "EXTERNAL:00000001", "target_kind": "import"},
            ],
        },
        "runtime_verified": False,
        "automatic_patch": False,
        "limitations": list(binary.PRODUCER_LIMITATIONS),
    }

    raw = archive({
        "pkg/__init__.py": b"",
        "pkg/constants.py": constants_py,
        "pkg/reexport.py": reexport_py,
        "pkg/runner.py": runner_py,
        "native/libhook.so": elf_bytes,
    })
    bound = binary.attach_binary_reports(
        raw, [("native/libhook.so", json.dumps(ghidra_rep, sort_keys=True).encode("utf-8"))]
    )

    bundle = run_forensic_investigation(bound, engine_version="test-cross-file-v1")
    assert bundle["status"] == "completed"
    # Even though TARGET_SO was split across 3 files, FFI bridge resolved to ./native/hook.so -> native/libhook.so!
    assert len(bundle["cross_boundary_chains"]) == 1
    assert bundle["cross_boundary_chains"][0]["binary_path"] == "native/libhook.so"
    assert bundle["cross_boundary_chains"][0]["reachable_sensitive_imports"][0]["import_name"] == "execve"

    kinds = {o["kind"] for o in bundle["forensic_observations"]}
    assert "obfuscated_ffi_to_sensitive_binary_sink" in kinds
    assert "high_obfuscation_delta_source" in kinds


def test_typescript_barrel_reexport_chain_unrolls_hidden_child_process_and_addon():
    parts_ts = b'export const A = "child_";\nexport const B = "process";\nexport const EXT = ".node";\n'
    barrel_ts = b'export { A, B, EXT } from "./parts";\n'
    entry_ts = (
        b'import { A, B, EXT } from "./barrel";\n'
        b"export function load() {\n"
        b"  try {\n"
        b'    const cp = require(A + B);\n'
        b'    const addon = require("./native/agent" + EXT);\n'
        b'    return cp["ex" + "ecSync"]("id") || addon;\n'
        b"  } catch {}\n"
        b"}\n"
    )
    dna = analyze_archive_code_dna(archive({
        "src/parts.ts": parts_ts,
        "src/barrel.ts": barrel_ts,
        "src/entry.ts": entry_ts,
    }))
    assert dna["status"] == "completed"
    entry_res = next(f for f in dna["flagged_files"] if f["file"] == "src/entry.ts")
    sig_kinds = {s["kind"] for s in entry_res["signals"]}
    assert "dynamic_import_sink" in sig_kinds
    assert "split_ffi_library_path" in sig_kinds
    assert "cross_file_const_assembly" in sig_kinds
    assert dna["ffi_bridges"][0]["library_arg"] == "./native/agent.node"
