"""Attach explicit Ghidra reports to a project ZIP for browser or hosted scans."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingest.validators import ArchiveValidationError, MAX_ARCHIVE_BYTES
from app.scan.binary_evidence import MAX_REPORT_BYTES, attach_binary_reports, collect_binary_evidence


def read_regular(path: str, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('input_must_be_regular_file')
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('input_size_limit')
    return raw


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', help='Existing project ZIP')
    parser.add_argument('--binary-evidence', action='append', required=True, metavar='ZIP_PATH=REPORT_JSON')
    parser.add_argument('--output', required=True, help='New output ZIP; existing files are never overwritten')
    args = parser.parse_args(argv)
    try:
        reports = []
        for item in args.binary_evidence:
            path, separator, filename = item.partition('=')
            if not separator or not path or not filename:
                raise ValueError('expected ZIP_PATH=REPORT_JSON')
            reports.append((path, read_regular(filename, MAX_REPORT_BYTES)))
        combined = attach_binary_reports(read_regular(args.archive, MAX_ARCHIVE_BYTES), reports)
        evidence = collect_binary_evidence(combined)
        with open(args.output, 'xb') as target:
            target.write(combined)
    except (OSError, ValueError, ArchiveValidationError) as error:
        parser.exit(2, f'Cannot attach binary evidence: {error}\n')
    print(f"Binary evidence: {evidence['status']}; archive SHA-256: {evidence['archive_sha256']}")
    return 0 if evidence['status'] == 'completed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
