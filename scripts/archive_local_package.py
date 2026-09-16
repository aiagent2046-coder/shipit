"""Archive a verified, clean offline bundle for a specific release revision."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

FILES = ('install.sh', 'install.txt', 'README.md', 'build-info.json', 'drydock-local-source.tar.gz')
DEPENDENCIES = {'pyyaml', 'tree-sitter', 'tree-sitter-typescript', 'pglast'}


def canonical(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Missing regular file or unsafe symlink: {path}')
    return path.read_bytes()


def validate_bundle(bundle: Path, revision: str) -> dict[str, bytes]:
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Expected revision must be a full lowercase Git SHA')
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError('Bundle must be a real directory')
    payload = {name: read_regular(bundle / name) for name in FILES}
    info = json.loads(payload['build-info.json'])
    if info.get('source_revision') != revision or info.get('source_dirty') is not False:
        raise ValueError('Release provenance requires the expected revision and source_dirty=false')
    # This intentionally accepts only the builder\'s pinned, hash-locked format.
    lock = payload['install.txt'].decode().replace('\\\r\n', ' ').replace('\\\n', ' ')
    locked = {}
    for line in lock.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)\s*', line)
        if not match:
            raise ValueError('Invalid hashed installation lock')
        name = canonical(match[1])
        if name in locked:
            raise ValueError(f'Duplicate installation lock: {name}')
        locked[name] = (match[2], set(re.findall(r'--hash=sha256:([0-9a-f]{64})', match[3])))
    if set(locked) != DEPENDENCIES | {'drydock-local'}:
        raise ValueError('Installation lock must include exactly the project and four dependencies')
    expected_pins = {f'{name}=={locked[name][0]}' for name in DEPENDENCIES}
    if set(info.get('dependencies', [])) != expected_pins or info.get('package_version') != locked['drydock-local'][0]:
        raise ValueError('Installation lock does not match build provenance')
    wheelhouse = bundle / 'wheelhouse'
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError('Missing wheelhouse or unsafe symlink')
    seen = set()
    for wheel in sorted(wheelhouse.iterdir()):
        # Wheel distribution/version cannot contain dashes; tags follow them.
        parts = wheel.name.split('-')
        if not wheel.name.endswith('.whl') or len(parts) not in (5, 6):
            raise ValueError(f'Unexpected wheelhouse entry: {wheel.name}')
        name = canonical(parts[0])
        if name not in locked or name in seen or parts[1] != locked[name][0]:
            raise ValueError(f'Unexpected or duplicate wheel: {wheel.name}')
        raw = read_regular(wheel)
        if hashlib.sha256(raw).hexdigest() not in locked[name][1]:
            raise ValueError(f'Wheel checksum mismatch: {wheel.name}')
        if name == 'drydock-local':
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                embedded = json.loads(archive.read('drydock_local/build-info.json'))
            if embedded != info:
                raise ValueError('Project wheel does not match build provenance')
        seen.add(name)
        payload['wheelhouse/' + wheel.name] = raw
    if seen != set(locked):
        raise ValueError('Incomplete wheelhouse')
    return payload


def archive_bundle(bundle: Path, out: Path, name: str, revision: str) -> tuple[Path, Path]:
    if not re.fullmatch(r'drydock-local-[A-Za-z0-9][A-Za-z0-9._-]{0,150}', name) or '..' in name:
        raise ValueError('Unsafe release archive name')
    payload = validate_bundle(bundle, revision)
    out.mkdir(parents=True, exist_ok=True)
    destination = out / (name + '.tar.gz')
    checksum = out / (name + '.tar.gz.sha256')
    if destination.exists() or destination.is_symlink() or checksum.exists() or checksum.is_symlink():
        raise FileExistsError('Release output already exists')
    # Exclusive opens protect existing artifacts even if another process publishes concurrently.
    with destination.open('xb') as output:
        try:
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                for relative, raw in sorted(payload.items()):
                    entry = tarfile.TarInfo(name + '/' + relative)
                    entry.size = len(raw)
                    entry.mode = 0o755 if relative == 'install.sh' else 0o644
                    archive.addfile(entry, io.BytesIO(raw))
            output.flush()
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            with checksum.open('x') as check:
                check.write(f'{digest}  {destination.name}\n')
        except BaseException:
            destination.unlink()
            raise
    return destination, checksum


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    archive, checksum = archive_bundle(args.bundle, args.out, args.name, args.revision)
    print(json.dumps({'archive': str(archive), 'checksum': str(checksum)}))


if __name__ == '__main__':
    main()
