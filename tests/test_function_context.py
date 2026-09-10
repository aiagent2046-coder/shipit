"""Source-driven observations and conservative cross-file navigation."""
import io
import json
from pathlib import Path
import stat
import zipfile

from app.scan import function_context as context
from app.scan.source_facts import collect_source_facts, facts_prompt
from app.report.evidence import manifest_rows
from tests.test_operation_context import archive


def test_method_beyond_model_prefix_is_attached_as_candidate():
    db = '# padding\n' * 6000 + '''class Repo:
    async def complete(self, conn):
        await conn.execute("UPDATE payments SET status='completed' WHERE id=%s", (identifier,))
'''
    record = context.collect_function_context(archive({
        'app/db.py': db,
        'app/protocol.py': 'class Protocol:\n    async def complete(self): ...\n',
        'app/billing.py': 'async def grant(repo):\n    return await repo.complete()\n',
    }))
    grant = next(r for r in record['records'] if r['scope'] == 'grant')
    target, = grant['candidates']
    assert target['line'] > 6000
    assert target['indexed_name_matches'] == 2
    assert target['binding'] == 'name_candidate_not_resolved'
    assert target['checks'][0]['queries'][0]['tokens'] == ['UPDATE', 'WHERE']
    assert 'completed' not in json.dumps(target)  # SQL values aren't copied.


def test_check_runs_without_any_model_title_and_reaches_report():
    source = '''async def report(row):
    if row['status'] == 'completed':
        return None
    await notify_operator(row)
'''
    record = collect_source_facts(archive({'payment.py': source}))
    fact, = record['functions']['records']
    assert fact['checks'][0]['kind'] == 'completed_status_return'
    assert fact['checks'][0]['result'] == 'observed'
    assert 'completed_status_return' in facts_prompt(record)
    assert 'completed_status_return' in dict(manifest_rows({'scan_manifest': {'source_facts': record}}))[
        'Function evidence 1']


def test_sql_comments_values_and_dynamic_arguments_are_not_lock_observations(tmp_path):
    marker = tmp_path / 'must-not-execute'
    source = f'''def run(conn):
    conn.execute("SELECT 'pg_advisory_lock secret-value' /* UPDATE WHERE */")
    conn.execute(dynamic_sql)
    open({str(marker)!r}, 'w').write('executed')
'''
    fact, = context.collect_function_context(archive({'db.py': source}))['records']
    assert fact['checks'][0]['queries'] == [{'line': 2, 'tokens': ['SELECT']}]
    assert 'secret-value' not in json.dumps(fact)
    assert not marker.exists()


def test_multiple_implementations_stay_candidates():
    record = context.collect_function_context(archive({
        'a.py': 'def lookup(c):\n    c.execute("SELECT 1")\n',
        'b.py': 'def lookup(c):\n    c.execute("SELECT 2")\n',
        'caller.py': 'def run(repo):\n    repo.lookup()\n',
    }))
    caller = next(r for r in record['records'] if r['scope'] == 'run')
    assert len(caller['candidates']) == 2
    assert all(r['indexed_name_matches'] == 2 for r in caller['candidates'])


def test_invalid_duplicate_symlink_and_test_inputs_are_excluded():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('broken.py', 'def (')
        z.writestr('tests/a.py', 'def run(c):\n c.execute("SELECT 1")')
        info = zipfile.ZipInfo('link.py')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, 'target.py')
    r = context.collect_function_context(buf)
    assert not r['records'] and r['excluded_files'] == 2
    assert r['limitations'] == ['unparseable_python']


def test_budgets_and_prompt_do_not_mutate_inventory(monkeypatch):
    monkeypatch.setattr(context, 'MAX_FUNCTIONS', 1)
    r = collect_source_facts(archive({'db.py': 'def a(c):\n c.execute("SELECT 1")\ndef b(): pass'}))
    assert r['functions']['limitations'] == ['function_limit_reached']
    original = json.dumps(r, sort_keys=True)
    assert facts_prompt(r, max_chars=20) == ''
    assert json.dumps(r, sort_keys=True) == original


def test_actual_payment_helpers_survive_function_prompt_budget():
    paths = ['app/db.py', 'app/billing/__init__.py', 'app/billing/bank_transfer.py',
             'app/main.py', 'app/worker/main.py']
    r = collect_source_facts(archive({p: Path(p).read_text() for p in paths}))
    prompt = facts_prompt(r)
    assert len(prompt) <= 16000
    data = json.loads(prompt[prompt.index('{'):])
    functions = data['functions']['records']
    assert any(f['scope'] == '_anon_daily_cap_exceeded' for f in functions)
    grant = next(f for f in functions if f['scope'] == 'grant_fixpack')
    assert any(c['scope'] == 'PaymentRepository.mark_completed_fixpack' for c in grant['candidates'])
    assert any(f['checks'] and f['checks'][0]['kind'] == 'completed_status_return' for f in functions)


def test_common_method_names_are_not_attached_as_arbitrary_repository_methods():
    files = {f'm{i}.py': 'def get(c):\n c.execute("SELECT 1")\n' for i in range(4)}
    files['caller.py'] = 'def enabled(env):\n return env.get("flag") == "1"\n'
    r = context.collect_function_context(archive(files))
    fn = next(f for f in r['records'] if f['scope'] == 'enabled')
    assert not fn['candidates']
    assert 'ambiguous_name_matches' in r['limitations']
