"""Failure contracts for the optional native provider; never execute target binaries."""
import json
import struct
import sys

import pytest

from scripts import inspect_binary_ghidra as ghidra


def elf():
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


def raw_result():
    return {"version": 1, "ghidra_version": "12.2", "executable_sha256": "a" * 64,
            "executable_format": "Executable and Linking Format (ELF)", "language_id": "x86:LE:64:default",
            "compiler_spec_id": "gcc", "image_base": "ram:00400000", "analysis_timed_out": False,
            "truncated": False, "functions": [{"name": "main", "entry": "ram:00401000", "body_addresses": 32}],
            "imports": [{"library": "libc.so.6", "name": "puts", "external_location": "EXTERNAL:00000001"}]}


def test_only_supported_elf_and_bounded_regular_files(tmp_path, monkeypatch):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf())
    assert ghidra.read_binary(binary) == elf()
    link = tmp_path / "link"
    link.symlink_to(binary)
    with pytest.raises(OSError):
        ghidra.read_binary(link)
    for body in (b"not ELF", elf()[:20], elf()[:5] + b"\x02" + elf()[6:]):
        binary.write_bytes(body)
        with pytest.raises(ghidra.Unavailable, match="unsupported_elf"):
            ghidra.read_binary(binary)
    binary.write_bytes(elf())
    monkeypatch.setattr(ghidra, "MAX_BINARY_BYTES", 32)
    with pytest.raises(ghidra.Unavailable, match="binary_limit"):
        ghidra.read_binary(binary)


def test_strict_result_preserves_partial_flags():
    value = raw_result()
    assert ghidra.parse_result(json.dumps(value).encode(), "a" * 64) == value
    value.update(analysis_timed_out=True, truncated=True)
    assert ghidra.parse_result(json.dumps(value).encode(), "a" * 64)["analysis_timed_out"] is True


@pytest.mark.parametrize("change", [
    {"version": True}, {"ghidra_version": "12.1"}, {"executable_sha256": "b" * 64},
    {"language_id": "AARCH64:LE:64:v8A"}, {"truncated": 0}, {"runtime_verified": True},
    {"image_base": "not an address"}, {"functions": [{"name": "f", "entry": "ram:1", "body_addresses": True}]},
    {"imports": [{"library": "libc", "name": "x"}]},
])
def test_mismatched_or_malformed_results_are_rejected(change):
    value = {**raw_result(), **change}
    with pytest.raises(ghidra.Unavailable, match="invalid_result"):
        ghidra.parse_result(json.dumps(value).encode(), "a" * 64)


def test_duplicate_keys_rows_nonfinite_and_oversized_results_fail(monkeypatch):
    with pytest.raises(ghidra.Unavailable):
        ghidra.parse_result(b'{"version":1,"version":1}', "a" * 64)
    with pytest.raises(ghidra.Unavailable):
        ghidra.parse_result(b'{"version":NaN}', "a" * 64)
    value = raw_result()
    value["functions"] *= 2
    with pytest.raises(ghidra.Unavailable):
        ghidra.parse_result(json.dumps(value).encode(), "a" * 64)
    monkeypatch.setattr(ghidra, "MAX_OUTPUT_BYTES", 5)
    with pytest.raises(ghidra.Unavailable, match="output_limit"):
        ghidra.parse_result(b"long output", "a" * 64)


def test_unavailable_tool_or_jdk_cannot_promote_evidence(tmp_path):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf())
    result = ghidra.inspect(binary, tmp_path / "missing.zip", tmp_path / "no-jdk")
    assert result["status"] == "unavailable"
    assert result["reason"] == "jdk_25_unavailable"
    assert result["facts"] is None
    assert result["runtime_verified"] is False
    java = tmp_path / "jdk"
    (java / "bin").mkdir(parents=True)
    (java / "bin/java").touch()
    (java / "bin/javac").touch()
    (java / "release").write_text('JAVA_VERSION="25.0.1"\n')
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"wrong toolchain")
    result = ghidra.inspect(binary, archive, java)
    assert result["reason"] == "tool_checksum_mismatch"
    assert result["status"] == "unavailable"
    assert result["automatic_patch"] is False


def test_parent_enforces_wall_and_output_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "WALL_SECONDS", 0.15)
    command = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
    with pytest.raises(ghidra.Unavailable, match="execution_timeout"):
        ghidra.run_headless(command, {}, tmp_path, tmp_path / "result", tmp_path / "log")
    monkeypatch.setattr(ghidra, "WALL_SECONDS", 10)
    monkeypatch.setattr(ghidra, "MAX_LOG_BYTES", 100)
    command = [sys.executable, "-I", "-c", "import os,time; os.write(1,b'x'*101); time.sleep(60)"]
    with pytest.raises(ghidra.Unavailable, match="output_limit"):
        ghidra.run_headless(command, {}, tmp_path, tmp_path / "result", tmp_path / "log2")


def test_nonzero_process_exit_is_not_accepted(tmp_path):
    result = tmp_path / "result"
    result.write_text(json.dumps(raw_result()))
    with pytest.raises(ghidra.Unavailable, match="execution_failed"):
        ghidra.run_headless([sys.executable, "-I", "-c", "raise SystemExit(3)"], {},
                           tmp_path, result, tmp_path / "log")
