"""Verify Weisfeiler-Lehman CFG invariance under stripping, relocation, and block permutation."""
import hashlib
import json

from app.scan import binary_evidence as binary
from app.scan.cfg_topology import (
    KNOWN_TOPOLOGY_SIGNATURES,
    compute_cfg_dna,
)
from app.scan.forensic_chain import run_forensic_investigation
from tests.test_binary_evidence import archive, elf


def test_wl_hash_is_invariant_to_block_permutation_and_relocation():
    # Original layout: entry(0) -> branch_a(1) & branch_b(2) -> loop_body(3 -> 3) -> exit(4)
    blocks_a = [
        {"is_return": False, "direct_calls": 0, "indirect_calls": 0},  # 0: entry
        {"is_return": False, "direct_calls": 1, "indirect_calls": 0},  # 1: branch A
        {"is_return": False, "direct_calls": 0, "indirect_calls": 0},  # 2: branch B
        {"is_return": False, "direct_calls": 0, "indirect_calls": 1},  # 3: loop body with indirect call
        {"is_return": True, "direct_calls": 0, "indirect_calls": 0},   # 4: return
    ]
    edges_a = [(0, 1), (0, 2), (1, 3), (2, 3), (3, 3), (3, 4)]
    dna_a = compute_cfg_dna(blocks_a, edges_a, entry_index=0)

    # Permute block indices completely (simulating different linker layout / address ordering):
    # New indices: old 4->0, old 2->1, old 0(entry)->2, old 3->3, old 1->4
    perm = {0: 2, 1: 4, 2: 1, 3: 3, 4: 0}
    inv = {v: k for k, v in perm.items()}
    blocks_b = [blocks_a[inv[i]] for i in range(5)]
    edges_b = [(perm[u], perm[v]) for u, v in edges_a]
    dna_b = compute_cfg_dna(blocks_b, edges_b, entry_index=2)

    assert dna_a == dna_b
    assert dna_a["basic_blocks"] == 5
    assert dna_a["cfg_edges"] == 6
    assert dna_a["back_edges"] == 1
    assert dna_a["branch_blocks"] == 2
    assert dna_a["cyclomatic"] == 3


def test_wl_hash_discriminates_non_isomorphic_control_flow():
    # Graph 1: Diamond if/else without loop (4 blocks, 4 edges)
    diamond = compute_cfg_dna(
        blocks=[
            {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
            {"is_return": False, "direct_calls": 1, "indirect_calls": 0},
            {"is_return": False, "direct_calls": 1, "indirect_calls": 0},
            {"is_return": True, "direct_calls": 0, "indirect_calls": 0},
        ],
        edges=[(0, 1), (0, 2), (1, 3), (2, 3)],
    )
    # Graph 2: While-loop with 4 blocks and 4 edges (same V and E counts, different topology!)
    loop_graph = compute_cfg_dna(
        blocks=[
            {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
            {"is_return": False, "direct_calls": 1, "indirect_calls": 0},
            {"is_return": False, "direct_calls": 1, "indirect_calls": 0},
            {"is_return": True, "direct_calls": 0, "indirect_calls": 0},
        ],
        edges=[(0, 1), (1, 2), (2, 1), (1, 3)],
    )
    assert diamond["basic_blocks"] == loop_graph["basic_blocks"] == 4
    assert diamond["cfg_edges"] == loop_graph["cfg_edges"] == 4
    assert diamond["back_edges"] == 0 and loop_graph["back_edges"] == 1
    assert diamond["wl_hash"] != loop_graph["wl_hash"]


def test_stripped_decoder_stub_is_caught_purely_by_cfg_topology_and_wl_signature():
    elf_bytes = elf(b"\xcc" * 48)
    digest = hashlib.sha256(elf_bytes).hexdigest()
    decoder_dna = compute_cfg_dna(
        blocks=[
            {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
            {"is_return": False, "direct_calls": 0, "indirect_calls": 0},
            {"is_return": True, "direct_calls": 0, "indirect_calls": 1},
        ],
        edges=[(0, 1), (1, 1), (1, 2)],
    )
    assert decoder_dna["wl_hash"] in KNOWN_TOPOLOGY_SIGNATURES

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
            "image_base": "ram:00900000",  # Relocated base address!
            "analysis_timed_out": False,
            "truncated": False,
            "functions": [
                {
                    "entry": "ram:00904420",
                    "name": "FUN_00904420",  # Completely stripped symbol name!
                    "body_addresses": 52,
                    "is_thunk": False,
                    **decoder_dna,
                },
            ],
            "imports": [],  # Zero visible imports (e.g. dynamic syscall/shellcode)!
            "exports": [{"entry": "ram:00904420", "name": "FUN_00904420"}],
            "call_edges": [],
        },
        "runtime_verified": False,
        "automatic_patch": False,
        "limitations": list(binary.PRODUCER_LIMITATIONS),
    }

    bound = binary.attach_binary_reports(
        archive({"bin/stager.elf": elf_bytes}),
        [("bin/stager.elf", json.dumps(ghidra_rep, sort_keys=True).encode("utf-8"))],
    )
    bundle = run_forensic_investigation(bound, engine_version="test-wl-v1")
    assert bundle["status"] == "completed"
    obs = bundle["forensic_observations"]
    assert any(
        o["kind"] == "binary_cfg_loop_indirect_stager"
        and "cfg-loop-indirect-stager-v1" in o["signal_kinds"]
        for o in obs
    )

def test_tarjan_scc_distinguishes_goto_error_cleanup_from_flattened_state_machine():

    from app.scan.cfg_topology import analyze_function_topologies



    # 1. Cython/CPython goto-error shape: 16 blocks, 12 branches all jumping forward to cleanup block 15

    goto_blocks = [{"is_return": i == 15, "direct_calls": 0, "indirect_calls": 0} for i in range(16)]

    goto_edges = [(i, i + 1) for i in range(14)] + [(i, 15) for i in range(12)] + [(14, 15)]

    goto_dna = compute_cfg_dna(goto_blocks, goto_edges)

    assert goto_dna["max_scc_blocks"] == 0 and goto_dna["max_scc_hub_in"] == 0



    # 2. True OLLVM/CFF dispatcher: header(0) -> 12 state blocks(1..12) -> latch(13) -> header(0), plus exit(14..15)

    cff_blocks = [{"is_return": i == 15, "direct_calls": 0, "indirect_calls": 0} for i in range(16)]

    cff_edges = (

        [(0, s) for s in range(1, 11)]

        + [(s, 13) for s in range(1, 11)]

        + [(10, 11), (11, 12), (12, 13), (13, 0), (0, 14), (14, 15)]

    )

    cff_dna = compute_cfg_dna(cff_blocks, cff_edges)

    assert cff_dna["max_scc_blocks"] >= 14 and cff_dna["max_scc_hub_in"] >= 8



    topo = analyze_function_topologies([

        {"entry": "ram:00101000", "name": "cython_goto_cleanup", "is_thunk": False, **goto_dna},

        {"entry": "ram:00102000", "name": "ollvm_dispatcher", "is_thunk": False, **cff_dna},

    ])

    assert [r["name"] for r in topo["flattened_dispatchers"]] == ["ollvm_dispatcher"]
