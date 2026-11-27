#!/usr/bin/env python3
import hashlib
import pathlib
import shutil
import stat
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
expected = "dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d"
actual = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
if actual != expected:
    raise SystemExit("Archive SHA256 mismatch; extraction refused")
with zipfile.ZipFile(archive) as z:
    entries = z.infolist()
    if len(entries) > 50000 or sum(x.file_size for x in entries) > 1024**3:
        raise SystemExit("Archive exceeds extraction limits")
    files = []
    roots = set()
    for info in entries:
        p = pathlib.PurePosixPath(info.filename)
        if p.is_absolute() or ".." in p.parts or "\\" in info.filename:
            raise SystemExit("Unsafe archive path")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise SystemExit("Unsupported archive entry type")
        if info.is_dir():
            continue
        if len(p.parts) < 2:
            raise SystemExit("Expected single enclosing project directory")
        roots.add(p.parts[0])
        if any(x.startswith(".env") or x in (".git", "node_modules") for x in p.parts):
            continue
        files.append((info, pathlib.Path(*p.parts[1:])))
    if len(roots) != 1:
        raise SystemExit("Expected exactly one project root")
    seen = set()
    for info, relative in files:
        if relative in seen:
            raise SystemExit("Duplicate archive path")
        seen.add(relative)
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with z.open(info) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(0o644)
if not (dest / "package-lock.json").is_file():
    raise SystemExit("Missing package-lock.json")
print(f"archive_sha256={actual}")
print(f"extracted_files={len(files)}")
print("dotenv_files_excluded=true")
