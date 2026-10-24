"""Optional static ELF pilot. Not imported by server/browser scanners; never runs the target."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import struct
import subprocess
import tempfile
import time
import zipfile

VERSION = "12.2"
ARCHIVE_SHA256 = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
PROFILE = "elf-x86-64-static-v1"
MAX_BINARY_BYTES = 10 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_FACTS = 1000
WALL_SECONDS = 120
EXPORTER = Path(__file__).with_name("ghidra") / "ExportDrydockFacts.java"
ADDRESS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*:[0-9a-fA-F]{1,16}\Z")
LIMITATIONS = ["static_discovery_only", "function_recovery_not_proven_complete", "imports_are_not_vulnerabilities",
               "external_locations_are_not_runtime_addresses", "target_not_executed", "no_security_verdict"]


class Unavailable(ValueError):
    pass


def digest_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read_binary(path: Path) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise Unavailable("unsupported_file")
        body = handle.read(MAX_BINARY_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(body) > MAX_BINARY_BYTES:
        raise Unavailable("binary_limit")
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise Unavailable("binary_changed")
    if (len(body) < 64 or body[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<HHI", body, 16) not in ((2, 62, 1), (3, 62, 1))
            or struct.unpack_from("<H", body, 52)[0] != 64):
        raise Unavailable("unsupported_elf")
    return body


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unavailable("invalid_result")
        result[key] = value
    return result


def _nonfinite(_value):
    raise Unavailable("invalid_result")


def parse_result(data: bytes, binary_sha256: str) -> dict:
    """Strict producer contract; it does not authenticate externally supplied JSON."""
    if len(data) > MAX_OUTPUT_BYTES:
        raise Unavailable("output_limit")
    try:
        value = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
        keys = {"version", "ghidra_version", "executable_sha256", "executable_format", "language_id",
                "compiler_spec_id", "image_base", "analysis_timed_out", "truncated", "functions", "imports"}
        if (type(value) is not dict or set(value) != keys or type(value["version"]) is not int
                or value["version"] != 1 or value["ghidra_version"] != VERSION
                or value["executable_sha256"] != binary_sha256
                or value["executable_format"] != "Executable and Linking Format (ELF)"
                or value["language_id"] != "x86:LE:64:default" or value["compiler_spec_id"] != "gcc"
                or type(value["analysis_timed_out"]) is not bool or type(value["truncated"]) is not bool
                or not isinstance(value["image_base"], str) or not ADDRESS.fullmatch(value["image_base"])):
            raise Unavailable("invalid_result")
        for field, expected in (("functions", {"entry", "name", "body_addresses"}),
                                ("imports", {"library", "name", "external_location"})):
            rows = value[field]
            if type(rows) is not list or len(rows) > MAX_FACTS:
                raise Unavailable("invalid_result")
            identifiers = []
            for row in rows:
                if type(row) is not dict or set(row) != expected:
                    raise Unavailable("invalid_result")
                for name, item in row.items():
                    if name == "body_addresses":
                        if type(item) is not int or not 0 <= item <= 2**64 - 1:
                            raise Unavailable("invalid_result")
                    elif not isinstance(item, str) or not 1 <= len(item) <= 256:
                        raise Unavailable("invalid_result")
                location = row.get("entry", row.get("external_location"))
                if not ADDRESS.fullmatch(location):
                    raise Unavailable("invalid_result")
                identifiers.append(row["entry"] if field == "functions" else (
                    row["library"], row["name"], row["external_location"]))
            if identifiers != sorted(set(identifiers)):
                raise Unavailable("invalid_result")
        return value
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Unavailable("invalid_result") from error


def extract_distribution(archive: Path, target: Path) -> Path:
    if not archive.is_file():
        raise Unavailable("tool_unavailable")
    if digest_file(archive) != ARCHIVE_SHA256:
        raise Unavailable("tool_checksum_mismatch")
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        if len(names) > 100000 or len(set(names)) != len(names) or sum(e.file_size for e in entries) > 3_000_000_000:
            raise Unavailable("tool_archive_limit")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or "\\" in entry.filename or stat.S_ISLNK(mode):
                raise Unavailable("invalid_tool_archive")
        zipped.extractall(target)
        for entry in entries:
            if not entry.is_dir() and entry.external_attr >> 16 & 0o111:
                (target / entry.filename).chmod(0o700)
    roots = list(target.glob("*/support/analyzeHeadless"))
    if len(roots) != 1:
        raise Unavailable("invalid_tool_archive")
    return roots[0].parent.parent


def run_headless(command: list[str], environment: dict, cwd: Path, result: Path, log: Path) -> bytes:
    process = None
    try:
        with log.open("wb") as output:
            started = time.monotonic()
            process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
            while True:
                if log.stat().st_size > MAX_LOG_BYTES or (result.exists() and result.stat().st_size > MAX_OUTPUT_BYTES):
                    raise Unavailable("output_limit")
                remaining = WALL_SECONDS - (time.monotonic() - started)
                if remaining <= 0:
                    raise Unavailable("execution_timeout")
                try:
                    code = process.wait(timeout=min(0.05, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
        if code != 0 or not result.is_file():
            raise Unavailable("execution_failed")
        if log.stat().st_size > MAX_LOG_BYTES:
            raise Unavailable("output_limit")
        with result.open("rb") as handle:
            return handle.read(MAX_OUTPUT_BYTES + 1)
    finally:
        if process is not None:
            # launch.sh leaves a shell parent; kill/reap the entire session on every exit.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def inspect(binary: Path, archive: Path, java_home: Path, diagnostic_log: Path | None = None) -> dict:
    report = {"version": 1, "scope": "binary_static", "profile": PROFILE, "status": "unavailable",
              "reason": "not_executed", "artifact": None, "provider": None, "facts": None,
              "runtime_verified": False, "automatic_patch": False, "limitations": list(LIMITATIONS)}
    try:
        if os.name != "posix":
            raise Unavailable("unsupported_runtime")
        body = read_binary(binary)
        sha256 = hashlib.sha256(body).hexdigest()
        report["artifact"] = {"sha256": sha256, "bytes": len(body), "format": "ELF64LE", "machine": 62}
        release = java_home / "release"
        if (not (java_home / "bin/java").is_file() or not (java_home / "bin/javac").is_file()
                or not release.is_file()
                or not re.search(r'^JAVA_VERSION="25(?:[.\"]|[-+])', release.read_text(), re.M)):
            raise Unavailable("jdk_25_unavailable")
        java_version = re.search(r'^JAVA_VERSION="([^"\n]+)"', release.read_text(), re.M).group(1)
        with tempfile.TemporaryDirectory(prefix="drydock-ghidra-") as directory:
            work = Path(directory)
            tool = extract_distribution(archive, work / "tool")
            program = work / "input.elf"
            program.write_bytes(body)
            scripts = work / "scripts"
            scripts.mkdir()
            exporter_bytes = EXPORTER.read_bytes()
            (scripts / EXPORTER.name).write_bytes(exporter_bytes)
            projects = work / "projects"
            projects.mkdir()
            output = work / "facts.json"
            options = " ".join(f"-D{name}={work / folder}" for name, folder in (
                ("user.home", "home"), ("application.settingsdir", "settings"),
                ("application.cachedir", "cache"), ("application.tempdir", "temp"), ("java.io.tmpdir", "temp")))
            (work / "temp").mkdir()
            environment = {"PATH": f"{java_home / 'bin'}:/usr/bin:/bin", "JAVA_HOME": str(java_home),
                           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                           "GHIDRA_HEADLESS_MAXMEM": "1G", "GHIDRA_HEADLESS_JAVA_OPTIONS": options}
            command = [str(tool / "support/analyzeHeadless"), str(projects), "Drydock",
                       "-import", str(program), "-loader", "ElfLoader", "-loader-loadLibraries", "false",
                       "-loader-linkExistingProjectLibraries", "false", "-processor", "x86:LE:64:default",
                       "-cspec", "gcc", "-scriptPath", str(scripts), "-postScript", EXPORTER.name, str(output),
                       "-analysisTimeoutPerFile", "60", "-max-cpu", "1", "-readOnly"]
            log = work / "headless.log"
            try:
                raw = run_headless(command, environment, work, output, log)
            finally:
                if diagnostic_log is not None and log.exists():
                    with diagnostic_log.open("xb") as saved, log.open("rb") as source:
                        saved.write(source.read(MAX_LOG_BYTES))
            facts = parse_result(raw, sha256)
            if program.read_bytes() != body:
                raise Unavailable("binary_changed")
            report["provider"] = {"name": "ghidra", "version": VERSION, "java_major": 25,
                                  "java_version": java_version,
                                  "distribution_sha256": ARCHIVE_SHA256,
                                  "exporter_sha256": hashlib.sha256(exporter_bytes).hexdigest()}
            report["facts"] = facts
            partial = facts["analysis_timed_out"] or facts["truncated"]
            report.update(status="partial" if partial else "completed",
                          reason="analysis_timeout" if facts["analysis_timed_out"] else (
                              "fact_limit" if facts["truncated"] else "static_export_completed"))
    except Unavailable as error:
        report["reason"] = str(error)
    except (OSError, ValueError, zipfile.BadZipFile):
        report["reason"] = "execution_unavailable"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--ghidra-archive", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--diagnostic-log", type=Path, help="optional new file for bounded Ghidra diagnostics")
    args = parser.parse_args()
    if args.diagnostic_log is not None and args.diagnostic_log.exists():
        parser.error("diagnostic log must be a new file")
    # Refuse overwrites before spending resources or launching anything.
    with args.output.open("x", encoding="utf-8") as output:
        report = inspect(args.binary.absolute(), args.ghidra_archive.absolute(), args.java_home.absolute(),
                         args.diagnostic_log.absolute() if args.diagnostic_log else None)
        text = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        output.write(text + "\n")
    print(f"Ghidra static evidence: {report['status']} ({report['reason']}); no security verdict")
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
