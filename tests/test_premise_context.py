import ast
import json
from pathlib import Path

from app.scan.premise_context import finding_context, transaction_templates, update_predicates
from app.scan.function_context import collect_function_context
from app.scan.source_facts import collect_source_facts, facts_prompt
from tests.test_operation_context import archive


def test_update_keeps_retry_predicate_and_redacts_unrelated_values():
    sql = """UPDATE payments SET token='private-value' WHERE id=%s AND
        (status='pending' OR (status='completed' AND external_ref=%s))"""
    record, = update_predicates(sql)
    text = json.dumps(record)
    assert 'AND_EXPR' in text and 'OR_EXPR' in text
    assert 'pending' in text and 'completed' in text and 'external_ref' in text
    assert 'private-value' not in text
    assert record['where']['args'][0]['right'] == {'parameter': 1}
    assert 'redacted' in json.dumps(update_predicates("UPDATE t SET x=1 WHERE secret='private-value'"))


def test_update_subquery_where_does_not_protect_outer_update():
    record, = update_predicates('UPDATE t SET x=(SELECT x FROM other WHERE id=1)')
    assert record['where'] == {'absent': True}
    assert update_predicates('UPDATE t SET') == []
    assert update_predicates("SELECT 'UPDATE t SET x=%s'") == []


def test_bare_builtin_set_not_linked_to_repository_method():
    record = collect_function_context(archive({
        'db.py': 'class Repo:\n def set(self,c): c.execute("UPDATE t SET x=1")',
        'caller.py': 'def main():\n found=set()\n return found == other'}))
    fn = next(r for r in record['records'] if r['scope'] == 'main')
    assert not fn['candidates']


def test_numeric_context_checks_only_supported_location_and_public_examples():
    facts = collect_source_facts(archive({'pay.py': 'def price(amount):\n return f"{float(amount):.2f}"'}))
    finding = {'file': 'pay.py', 'line_start': 2, 'line_end': 2,
               'title': 'Float formatting loses cents', 'explanation': 'Examples 990.07, 333.33, 99.99'}
    check, = finding_context(finding, facts)
    assert len(check['cases']) == 3
    assert all(c['difference'] == '0.00' and not c['amount_changed'] for c in check['cases'])
    assert finding_context({**finding, 'file': 'other.py'}, facts) == []
    assert finding_context({**finding, 'line_start': 1, 'line_end': 1}, facts) == []
    assert finding_context({**finding, 'explanation': 'Unknown 1234.56'}, facts) == []


def test_transaction_template_observed_without_claiming_runner_execution():
    source = Path('scripts/migration_manager.py').read_text()
    fn = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'apply_one')
    check, = transaction_templates(fn)
    assert check['kind'] == 'transaction_template'
    assert 'execution not verified' in check['detail']
    changed = ast.parse('def run(path):\n sql=f"SELECT 1; {path}"').body[0]
    assert transaction_templates(changed) == []
    facts = collect_source_facts(archive({'scripts/migration_manager.py': source}))
    attached, = finding_context({'title': 'Migration UPDATE runs outside a transaction',
        'file': 'scripts/migration_manager.py', 'line_start': fn.lineno, 'line_end': fn.end_lineno}, facts)
    assert attached['scope'] == 'apply_one'
    assert 'transaction_template' in facts_prompt(facts)


def test_expanded_actual_repository_prompt_retains_payment_predicates():
    paths = ['app/db.py', 'app/billing/__init__.py', 'app/main.py', 'app/billing/bank_transfer.py',
             'scripts/migration_manager.py']
    facts = collect_source_facts(archive({p: Path(p).read_text() for p in paths}))
    prompt = facts_prompt(facts)
    assert len(prompt) <= 16000
    assert 'mark_completed_fixpack' in prompt and 'status_literal' in prompt
    assert 'transaction_template' in prompt and '_anon_daily_cap_exceeded' in prompt


def test_payment_claim_does_not_inherit_unrelated_migration_transaction():
    source = Path('scripts/migration_manager.py').read_text()
    facts = collect_source_facts(archive({'scripts/migration_manager.py': source}))
    claim = {'title': 'Migration 0025 permits retry but grant lacks a transaction',
             'file': 'app/billing/__init__.py', 'line_start': 253, 'line_end': 320}
    assert finding_context(claim, facts) == []
    assert finding_context({'title': claim['title']}, facts) == []
