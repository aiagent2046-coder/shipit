"""Cross-boundary deterministic forensic chain: Code DNA + Ghidra Call Graph + CVE/KEV.

Connects source-level LLM evasion/obfuscation signals (intra- and cross-file)
and FFI loaders to Ghidra v2 binary call-graph reachability, Weisfeiler-Lehman
CFG topology signatures, and known-exploited CVE records under cryptographic
SHA-256 hand-offs. Never executes code or claims runtime proof.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import PurePosixPath

from app.scan.supply.binary_evidence import collect_binary_evidence, summarize_binary_reachability
from app.scan.supply.obfuscation_delta import analyze_archive_code_dna
from app.scan.supply.threat_context import build_threat_context

FORENSIC_ROLES = ("detector", "researcher", "correlator", "verifier")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    ).hexdigest()


def _canonical_soname_stem(filename: str) -> str:
    """Normalize 'libhook.so.1', 'hook.cpython-312-x86_64-linux-gnu.so', '_hook.abi3.so' -> 'hook'."""
    name = filename.strip()
    if name.startswith("lib") and len(name) > 3 and (name[3].isalnum() or name[3] == "_"):
        name = name[3:]
    for marker in (".cpython-", ".pypy", ".abi3.", ".so", ".node", ".dylib", ".dll"):
        idx = name.find(marker)
        if idx > 0:
            name = name[:idx]
            break
    return name.lstrip("_").lower()


def _match_ffi_to_artifact(library_arg: str | None, artifact_paths: list[str]) -> list[str]:
    if not library_arg:
        return []
    cleaned = library_arg.strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    req_posix = PurePosixPath(cleaned)
    req_dir = req_posix.parent.as_posix()
    target_name = req_posix.name
    target_stem = _canonical_soname_stem(target_name)
    matches = []
    for art_path in artifact_paths:
        art_posix = PurePosixPath(art_path)
        art_name = art_posix.name
        if art_path == cleaned or art_path.endswith("/" + cleaned) or art_name == target_name:
            matches.append(art_path)
            continue
        if target_stem and len(target_stem) >= 3 and _canonical_soname_stem(art_name) == target_stem:
            if req_dir in ("", ".") or art_posix.parent.as_posix().endswith(req_dir):
                matches.append(art_path)
    return sorted(set(matches))


def run_forensic_investigation(
    archive_bytes: bytes,
    *,
    engine_version: str,
    dependency_records: list[dict] | None = None,
    threat_catalog: dict | None = None,
    threat_as_of: str | None = None,
    precomputed_binary: dict | None = None,
    precomputed_threat: dict | None = None,
) -> dict:
    """Execute the 4-stage deterministic forensic investigation over an archive."""
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    state: dict = {
        "schema": 1,
        "archive_sha256": archive_sha256,
        "engine_version": engine_version,
        "runtime_verified": False,
        "automatic_patch": False,
        "code_dna": None,
        "binary_topology": None,
        "threat_intel": None,
        "cross_boundary_chains": [],
        "forensic_observations": [],
    }
    receipts = []

    def step_detector(current: dict) -> tuple[dict, str, str]:
        current["code_dna"] = analyze_archive_code_dna(archive_bytes)
        if precomputed_binary is not None and precomputed_binary.get("archive_sha256") == archive_sha256:
            current["binary_raw"] = deepcopy(precomputed_binary)
        else:
            current["binary_raw"] = collect_binary_evidence(archive_bytes)
        return current, "completed", "surface_signals_collected"

    def step_researcher(current: dict) -> tuple[dict, str, str]:
        binary_raw = current.pop("binary_raw")
        artifacts_topology = []
        for art in binary_raw.get("artifacts", []):
            reachability = summarize_binary_reachability(art["facts"]) if art.get("facts") else None
            artifacts_topology.append({
                "path": art["path"],
                "sha256": art["sha256"],
                "status": art["status"],
                "reason": art["reason"],
                "reachability": reachability,
            })
        current["binary_topology"] = {
            "status": binary_raw["status"],
            "artifacts": artifacts_topology,
            "limitations": list(binary_raw.get("limitations", [])),
        }
        if precomputed_threat is not None and isinstance(precomputed_threat, dict):
            current["threat_intel"] = deepcopy(precomputed_threat)
        else:
            current["threat_intel"] = build_threat_context(
                dependency_records or [], catalog=threat_catalog, as_of=threat_as_of
            )
        return current, "completed", "topology_and_kev_enriched"

    def step_correlator(current: dict) -> tuple[dict, str, str]:
        dna = current["code_dna"]
        topo = current["binary_topology"]
        intel = current["threat_intel"]

        art_by_path = {a["path"]: a for a in topo["artifacts"]}
        artifact_paths = sorted(art_by_path)
        flagged_by_file = {f["file"]: f for f in dna["flagged_files"]}

        chains = []
        for bridge in dna["ffi_bridges"]:
            matched_paths = _match_ffi_to_artifact(bridge["library_arg"], artifact_paths)
            src_info = flagged_by_file.get(bridge["source_file"], {})
            src_delta = src_info.get("delta_score", 0)
            for art_path in matched_paths:
                art = art_by_path[art_path]
                reach = art.get("reachability") or {}
                sinks = reach.get("reachable_sensitive_imports", [])
                chains.append({
                    "source_file": bridge["source_file"],
                    "source_sha256": bridge["source_sha256"],
                    "source_delta_score": src_delta,
                    "ffi_library_arg": bridge["library_arg"],
                    "ffi_split_ops": bridge["split_ops"],
                    "binary_path": art_path,
                    "binary_sha256": art["sha256"],
                    "binary_status": art["status"],
                    "reachable_sensitive_imports": sinks,
                    "indirect_call_stubs": reach.get("indirect_call_stubs", []),
                })

        observations = []
        for chain in chains:
            has_delta = chain["source_delta_score"] not in (0, 1, 2) or bool(chain["ffi_split_ops"])
            if chain["reachable_sensitive_imports"] and has_delta:
                observations.append({
                    "kind": "obfuscated_ffi_to_sensitive_binary_sink",
                    "verification_status": "unverified",
                    "source_file": chain["source_file"],
                    "binary_path": chain["binary_path"],
                    "source_delta_score": chain["source_delta_score"],
                    "sink_imports": sorted({s["import_name"] for s in chain["reachable_sensitive_imports"]}),
                })
            elif chain["reachable_sensitive_imports"]:
                observations.append({
                    "kind": "ffi_bridge_to_sensitive_binary_sink",
                    "verification_status": "unverified",
                    "source_file": chain["source_file"],
                    "binary_path": chain["binary_path"],
                    "source_delta_score": chain["source_delta_score"],
                    "sink_imports": sorted({s["import_name"] for s in chain["reachable_sensitive_imports"]}),
                })

        for f in dna["flagged_files"]:
            sig_kinds = sorted({s["kind"] for s in f["signals"]})
            has_active_signal = any(k != "silent_exception_swallow" for k in sig_kinds)
            if f["delta_score"] >= 6 and has_active_signal:
                observations.append({
                    "kind": "high_obfuscation_delta_source",
                    "verification_status": "unverified",
                    "source_file": f["file"],
                    "language": f["language"],
                    "source_delta_score": f["delta_score"],
                    "signal_kinds": sig_kinds,
                })

        for art in topo["artifacts"]:
            reach = art.get("reachability") or {}
            t_info = reach.get("topology") or {}
            if t_info.get("loop_indirect_anomalies"):
                observations.append({
                    "kind": "binary_cfg_loop_indirect_stager",
                    "verification_status": "unverified",
                    "binary_path": art["path"],
                    "signal_kinds": [
                        row["signature_id"] for row in t_info.get("signature_matches", [])
                    ] or ["loop_with_computed_call"],
                })
            if t_info.get("flattened_dispatchers"):
                observations.append({
                    "kind": "binary_cfg_flattened_dispatcher",
                    "verification_status": "unverified",
                    "binary_path": art["path"],
                    "signal_kinds": ["control_flow_flattening"],
                })

        kev_matches = intel.get("matches", []) if isinstance(intel, dict) else []
        if kev_matches and dna["max_delta_score"] >= 4:
            observations.append({
                "kind": "kev_exposure_with_obfuscated_code_dna",
                "verification_status": "unverified",
                "kev_cve_ids": sorted({
                    row["cve_id"] for row in kev_matches if isinstance(row, dict) and "cve_id" in row
                }),
                "max_delta_score": dna["max_delta_score"],
            })

        current["cross_boundary_chains"] = chains
        current["forensic_observations"] = observations
        return current, "completed", "cross_boundary_correlation_completed"

    def step_verifier(current: dict) -> tuple[dict, str, str]:
        if current["archive_sha256"] != archive_sha256:
            raise ValueError("archive_binding_mismatch")
        if current["runtime_verified"] is not False or current["automatic_patch"] is not False:
            raise ValueError("truthfulness_contract_violation")
        dna_incomplete = current["code_dna"]["status"] != "completed"
        bin_status = current["binary_topology"]["status"]
        bin_incomplete = bin_status in {"partial", "unavailable", "not_run"}
        overall = "partial" if (dna_incomplete or bin_incomplete) else "completed"
        current["status"] = overall
        return current, "completed", "forensic_bundle_verified"

    workers = {
        "detector": step_detector,
        "researcher": step_researcher,
        "correlator": step_correlator,
        "verifier": step_verifier,
    }

    accepted = deepcopy(state)
    for role in FORENSIC_ROLES:
        before_hash = _digest(accepted)
        proposed, step_status, reason = workers[role](deepcopy(accepted))
        proposed = deepcopy(proposed)
        after_hash = _digest(proposed)
        receipts.append({
            "role": role,
            "depends_on": receipts[-1]["output_sha256"] if receipts else None,
            "input_sha256": before_hash,
            "output_sha256": after_hash,
            "status": step_status,
            "reason": reason,
        })
        accepted = proposed

    accepted["forensic_chain"] = {
        "version": 1,
        "roles": list(FORENSIC_ROLES),
        "receipts": receipts,
    }
    return accepted
