"""Source-role regressions from audit d736a550; synthetic inputs only."""
import io
import json
import zipfile
from dataclasses import asdict

from app.report.evidence import claim_evidence_rows, finding_counts, source_severity_counts
from app.report.html import render_report
from app.report.plain_language import plain_fields
from app.scan.checks import run_checks
from app.scan.claim_evidence import static_claim_evidence
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.secrets import scan_secrets


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for path, source in files.items():
            z.writestr(path, source)
    buf.seek(0)
    return buf


def uri(scheme='postgres', password='password', host='host'):
    return scheme + '://' + 'user:' + password + '@' + host + '/app'


def scan(path, source):
    findings = [f for f in scan_secrets(archive({path: source}))
                if f.rule_id.startswith('connection-string')]
    assert len(findings) == 1
    return findings[0]


def test_default_password_does_not_skip_comment_test_or_ci_classification():
    cases = [
        ('app/source.py', '# ' + uri(), 'comment'),
        ('tests/source.py', 'url = ' + repr(uri()), 'test_file'),
        ('.github/workflows/smoke.yml', 'DATABASE_URL: ' + uri(host='localhost'), 'ci_service'),
        ('scripts/proof.py', 'invalid_url = ' + repr(uri(scheme='https', host='example.com')), 'doc_example'),
    ]
    for path, source, expected in cases:
        f = scan(path, source)
        assert f.context == expected
        assert f.severity == 'low'
        assert 'almost certainly' not in plain_fields(asdict(f))[1]
    assert scan('app/config.py', 'url = ' + repr(uri(host='live.customer.org'))).context is None


def test_docstrings_and_configuration_text_have_separate_roles():
    f = scan('scripts/verify.py', '"""Usage:\n export DATABASE_URL=' + uri() + '\n"""')
    assert f.context == 'doc_example'
    assert f.source_context['kind'] == 'docstring'
    body = 'def generate():\n    env = ("POSTGRES_PASSWORD=change_me\\n"\n           "DATABASE_URL=' + uri(
        scheme='postgresql+asyncpg', password='change_me', host='db') + '\\n")\n    return env\n'
    f = scan('app/generate.py', body)
    assert f.source_context == dict(kind='configuration_template', uri_scheme='postgresql+asyncpg', uri_kind='database')
    assert f.context is None  # may become deployed configuration; keep in source observations
    record = asdict(f) | {'claim_evidence': static_claim_evidence() | {'source_context': f.source_context}}
    rows = dict(claim_evidence_rows(record))
    assert rows['Source context'] == 'Configuration text containing change_me'
    assert 'not verified' in rows['URI protocol']


def test_web_uri_is_not_described_as_a_database_and_metadata_has_no_credentials():
    f = scan('scripts/proof.py', 'url = ' + repr(uri('https', host='example.com')))
    assert f.source_context['uri_kind'] == 'web'
    assert 'database' not in ' '.join(plain_fields(asdict(f))).lower()
    assert 'user' not in json.dumps(f.source_context)
    assert 'example.com' not in json.dumps(f.source_context)
    assert 'password' not in json.dumps(f.source_context)
    f = scan('app/config.py', 'url = ' + repr(uri('custom', host='live.customer.org')))
    assert f.source_context['uri_kind'] == 'other_or_unknown'
    assert f.context is None


def test_real_looking_value_in_ci_or_scripts_is_retained_and_not_marked_synthetic():
    for path in ('.github/workflows/build.yml', 'scripts/config.py', 'app/config.py'):
        f = scan(path, 'DATABASE_URL = ' + repr(uri(password='unique-' + 'credential-8732', host='live.customer.org')))
        assert f.severity == 'critical'
        assert f.context is None
    f = scan('migrations/001.sql', '-- ' + uri(password='unique-' + 'credential-8732', host='live.customer.org'))
    assert f.context is None
    assert f.severity == 'critical'


def test_unparseable_python_preserves_signal_without_inventing_docstring_role():
    f = scan('app/broken.py', 'def broken(:\n url = ' + repr(uri()))
    assert f.context is None
    assert f.source_context['kind'] == 'source_literal'


def test_alternative_deployment_is_visible_inventory_not_a_penalty():
    for alternative in ('deploy/app.service', 'vercel.json', 'netlify.toml', 'Procfile', 'fly.toml'):
        checks = run_checks(archive({'repo/' + alternative: 'placeholder config'}))
        f = next(f for f in checks if f.rule_id == 'no-dockerfile')
        assert f.context == 'deployment_inventory'
        scored = ScoredFinding(**asdict(f))
        assert compute_scores([scored]) == compute_scores([])
        finding = asdict(scored)
        assert finding_counts([finding]) == (0, 0)
        assert not any(source_severity_counts([finding]).values())
        html = render_report({'score': {'total': 0, 'categories': {}}, 'findings': [finding]})
        assert 'Deployment inventory' in html
        assert alternative in html
        assert 'Potential low impact' not in html
        assert 'live deployment are not checked' in html
    f = next(f for f in run_checks(archive({'app.py': 'pass'})) if f.rule_id == 'no-dockerfile')
    assert f.context is None
    assert not any(f.rule_id == 'no-dockerfile' for f in run_checks(archive({'Dockerfile': 'FROM scratch'})))


def test_source_roles_survive_the_static_pipeline_and_do_not_exclude_other_findings():
    from app.scan.static import run_static_scan
    buf = archive({'scripts/check.py': '# ' + uri(), 'deploy/app.service': '[Service]',
                   'app.py': 'url = ' + repr(uri(password='distinct-' + 'value8732', host='live.customer.org'))})
    result = run_static_scan(buf)
    comment = next(f for f in result['findings'] if f['file'] == 'scripts/check.py')
    assert comment['claim_evidence']['source_context']['kind'] == 'comment'
    assert finding_counts([comment]) == (0, 1)
    inventory = next(f for f in result['findings'] if f['rule_id'] == 'no-dockerfile')
    assert inventory['context'] == 'deployment_inventory'
    live = next(f for f in result['findings'] if f['file'] == 'app.py' and f['rule_id'].startswith('connection-string'))
    assert live['severity'] == 'critical'
    assert finding_counts([live]) == (1, 0)
