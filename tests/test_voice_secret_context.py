"""Credential context regressions derived from VoiceStudio; no live keys."""
import json

import pytest

from app.scan.secrets import scan_secrets
from tests.test_secrets import make_zip


def scan(path, source):
    return scan_secrets(make_zip({path: source.encode()}))


@pytest.mark.parametrize('label', ['API-Schlüssel', 'HuggingFace-Token', 'Knuffelgezicht-token',
                                   'โทเค็นใบหน้ากอด', 'แทรกโทเค็นการแสดงออก'])
def test_catalog_label_is_retained_as_information(label):
    findings = scan('frontend/src/i18n/locales/th.json', json.dumps({'hf_token': label}, ensure_ascii=False))
    assert len(findings) == 1
    assert findings[0].severity == 'low'
    assert findings[0].source_context == {'kind': 'translation_label'}


@pytest.mark.parametrize('path', ['src/config.json', 'locales/migrations/config.json'])
def test_label_damping_does_not_apply_to_config_or_migrations(path):
    assert scan(path, '{"api_key": "HuggingFace-Token"}')[0].severity == 'high'


def test_catalog_does_not_hide_credential_bytes():
    findings = scan('locales/de.json', '{"api_key": "real-looking-12345678", "token": "ghp_' + 'A'*36 + '"}')
    assert any(f.rule_id == 'generic-assignment' and f.severity == 'high' for f in findings)
    assert any(f.rule_id == 'github-pat' for f in findings)


def test_large_unicode_catalog_keeps_context():
    source = json.dumps({'padding': 'ก'*90000, 'api_key': 'HuggingFace-Token'}, ensure_ascii=False)
    assert scan('locales/th.json', source)[0].severity == 'low'


@pytest.mark.parametrize('prefix,expected', [('phc_', False), ('phx_', True), ('phs_', True)])
def test_posthog_public_and_private_key_types(prefix, expected):
    assert bool(scan('src/config.py', 'PROJECT_TOKEN = "' + prefix + 'aB3'*14 + 'CD"')) == expected


def test_storage_key_declaration_is_not_sql_but_embedded_sql_is_scanned():
    assert not scan('src/auth.ts', "export const LEGACY_API_KEY_STORAGE_KEY = 'ov_api_key';")
    findings = scan('src/auth.ts', '''const query = "UPDATE config SET api_key = 'synthetic-12345678'";''')
    assert any(f.rule_id == 'sql-secret-assignment' for f in findings)
    assert scan('src/auth.ts', "const api_key = 'synthetic-12345678';")


@pytest.mark.parametrize('language,quote,expected', [('bash', '"', False), ('sh', '"', False),
    ('shell', '"', False), ('python', '"', True), ('bash', "'", True), ('', '"', True)])
def test_markdown_expansion_requires_shell_fence_and_double_quotes(language, quote, expected):
    source = f'```{language}\ndocker run -e API_KEY={quote}$PROJECT_API_KEY{quote} app\n```\n'
    assert bool(scan('docs/install.md', source)) == expected


def test_shell_docs_keep_defaults_and_other_literals():
    source = '```bash\nAPI_KEY="${API_KEY:-real-default-value}"\n```\nAPI_KEY="$PROJECT_API_KEY"\n'
    assert len(scan('docs/install.md', source)) == 2
