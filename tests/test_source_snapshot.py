"""Source facts are bound to immutable bytes and one unambiguous AST sink."""
import hashlib
import io
import zipfile

import pytest

from app.scan import source_snapshot as snapshots
from app.scan.evidence_acquisition import EvidenceBudget, EvidenceLimit
from app.scan.source_snapshot import SourceSnapshot, SourceUnavailable


def snapshot(source='cur.execute(query)\n', **files):
    files = {'src/query.py': source, **files}
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        for path, value in files.items():
            archive.writestr(path, value)
    digest = hashlib.sha256(data.getvalue()).hexdigest()
    data.seek(3)
    result = SourceSnapshot.from_archive(data, archive_sha256=digest)
    assert data.tell() == 3
    trace = {'file': 'src/query.py', 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
             'sink_line': 1, 'sink_method': 'execute'}
    return result, trace


def test_exact_source_identity_and_cached_ast():
    source, trace = snapshot()
    try:
        budget = EvidenceBudget()
        document, sink = source.locate(trace, spend=budget.spend)
        remaining = budget.remaining
        assert snapshots.source_span(sink) == [1, 0, 1, 18]
        assert source.locate(trace, spend=budget.spend) == (document, sink)
        assert remaining - budget.remaining == 1
        with pytest.raises(SourceUnavailable, match='source_changed'):
            source.locate({**trace, 'source_sha256': '0' * 64}, spend=budget.spend)
    finally:
        source.close()


@pytest.mark.parametrize(('body', 'reason'), [
    ('cur.execute(a); cur.execute(b)\n', 'ambiguous_sink'),
    ('cur.executemany(query)\n', 'sink_not_found'),
    ('cur.execute(\n', 'source_parse_error'),
])
def test_ambiguous_missing_and_unparseable_source_never_resolve(body, reason):
    source, trace = snapshot(body)
    try:
        with pytest.raises(SourceUnavailable, match=reason):
            source.locate(trace, spend=EvidenceBudget().spend)
    finally:
        source.close()


def test_archive_identity_is_checked_before_opening():
    with pytest.raises(SourceUnavailable, match='source_changed'):
        SourceSnapshot(b'not the original archive', '0' * 64)


def test_source_and_cumulative_limits(monkeypatch):
    source, trace = snapshot(**{'src/other.py': 'cur.execute(other)\n'})
    try:
        monkeypatch.setattr(snapshots, 'MAX_SNAPSHOT_BYTES', 20)
        source.locate(trace, spend=EvidenceBudget().spend)
        with pytest.raises(SourceUnavailable, match='source_limit'):
            source.locate({**trace, 'file': 'src/other.py'}, spend=EvidenceBudget().spend)
    finally:
        source.close()
    source, trace = snapshot()
    try:
        monkeypatch.setattr(snapshots, 'MAX_SOURCE_BYTES', 5)
        with pytest.raises(SourceUnavailable, match='source_limit'):
            source.locate(trace, spend=EvidenceBudget().spend)
    finally:
        source.close()


def test_node_limit_and_shared_work_budget(monkeypatch):
    source, trace = snapshot()
    try:
        with pytest.raises(EvidenceLimit):
            source.locate(trace, spend=EvidenceBudget(max_work=0).spend)
        monkeypatch.setattr(snapshots, 'MAX_SOURCE_NODES', 2)
        with pytest.raises(SourceUnavailable, match='source_limit'):
            source.locate(trace, spend=EvidenceBudget().spend)
    finally:
        source.close()


def test_archive_paths_are_read_without_extraction(tmp_path):
    source, trace = snapshot(**{'../../escaped.py': 'raise RuntimeError("must not execute")'})
    try:
        source.locate(trace, spend=EvidenceBudget().spend)
        assert not list(tmp_path.iterdir())
    finally:
        source.close()
