"""Record actual selection stages without changing prompts or making network calls."""
import io
import zipfile

from app.llm.client import LLMClient, LLMError, LLMUsage
from app.scan import llm_scan
from app.scan.manifest import scan_manifest


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


class Empty(LLMClient):
    def __init__(self, fail=False):
        super().__init__(providers=[])
        self.sent = []
        self.fail = fail

    def complete(self, system, prompt, **kwargs):
        self.sent.append(prompt)
        if self.fail:
            raise LLMError('provider unavailable')
        return '[]', LLMUsage(model='fake', input_tokens=1, output_tokens=1)


def check_partition(stats):
    assert sum(stats.selection_exclusions.values()) == stats.candidate_files - len(stats.submitted_files)


def test_nonmatching_and_budget_exclusions_are_unique_across_passes(monkeypatch):
    monkeypatch.setattr(llm_scan, 'content_budget', lambda client: 100)
    client = Empty()
    files = {'auth.py': 'token = 1', 'large.py': 'token = 1\n' * 100, 'plain.py': 'x = 1'}
    buf = archive(files)
    _, stats = llm_scan.run_llm_scan(buf, client, rubrics=('auth',), passes=2)
    assert stats.calls == 2
    assert client.sent[0] == client.sent[1]
    assert stats.submitted_files == ('auth.py',)
    assert stats.selection_exclusions == dict(no_rubric_match=1, rubric_not_reached=0,
                                              selection_budget=1, request_window=0)
    check_partition(stats)
    m = scan_manifest(buf.getvalue(), 'test', {}, vars(stats), None)
    assert m['llm_selection_exclusions'] == stats.selection_exclusions
    assert 'token' not in str(m['llm_selection_exclusions'])


def test_request_window_removal_and_other_rubric_submission(monkeypatch):
    original = llm_scan.fit_to_window

    def fit(selected, rubric, limit, context=''):
        # Force the real window fitting function to remove auth files.
        return original(selected, rubric, 1 if rubric == 'auth' else limit, context)

    monkeypatch.setattr(llm_scan, 'fit_to_window', fit)
    files = {'auth.py': 'token = 1', 'shared.py': 'token = payment = 1'}
    _, stats = llm_scan.run_llm_scan(archive(files), Empty(), rubrics=('auth',))
    assert stats.selection_exclusions['request_window'] == 2
    check_partition(stats)
    _, stats = llm_scan.run_llm_scan(archive(files), Empty(), rubrics=('auth', 'money'))
    assert 'shared.py' in stats.submitted_files
    assert stats.selection_exclusions['request_window'] == 1
    check_partition(stats)


def test_stop_reasons_do_not_call_never_reached_files_budget_exclusions():
    files = {'auth.py': 'token = 1', 'billing.py': 'payment = 1'}
    for client, cap in [(Empty(fail=True), None), (Empty(), 0)]:
        _, stats = llm_scan.run_llm_scan(archive(files), client, rubrics=('auth', 'money'), cost_cap_usd=cap)
        assert len(client.sent) == 1
        assert stats.selection_exclusions['rubric_not_reached'] == 1
        assert stats.selection_exclusions['selection_budget'] == 0
        check_partition(stats)
