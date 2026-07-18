"""Tests for the secrets scanner. The masking test is the critical one:
a scanner that leaks the secrets it finds is worse than no scanner.
"""

import io
import zipfile

from app.scan.secrets import scan_secrets

# Deliberately fake but format-valid samples.
FAKE_AWS = "AKIA" + "A" * 16
FAKE_GHP = "ghp_" + "a" * 36
FAKE_STRIPE = "sk_live_" + "a" * 24
FAKE_ANTHROPIC = "sk-ant-api03-" + "a" * 24
FAKE_TG = "1234567890:" + "A" * 35
FAKE_JWT = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def test_detects_known_token_formats_with_file_and_line():
    src = f"const a = '{FAKE_AWS}'\nconst b = '{FAKE_GHP}'\n".encode()
    findings = scan_secrets(make_zip({"src/config.ts": src}))
    ids = {f.rule_id for f in findings}
    assert {"aws-access-key-id", "github-pat"} <= ids
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    assert aws.file == "src/config.ts" and aws.line == 1
    assert aws.severity == "critical"


def test_detects_stripe_anthropic_telegram_privatekey():
    src = "\n".join([
        f'STRIPE = "{FAKE_STRIPE}"',
        f'client = Anthropic(api_key="{FAKE_ANTHROPIC}")',
        f'BOT = "{FAKE_TG}"',
        "-----BEGIN RSA PRIVATE KEY-----",
    ]).encode()
    ids = {f.rule_id for f in scan_secrets(make_zip({"app.py": src}))}
    assert {
        "stripe-live-key", "anthropic-api-key",
        "telegram-bot-token", "private-key-block",
    } <= ids


def test_finding_never_contains_secret_value():
    src = f"key = '{FAKE_STRIPE}'\ntoken = '{FAKE_JWT}'".encode()
    findings = scan_secrets(make_zip({"a.py": src}))
    assert findings
    for f in findings:
        dumped = repr(f)
        assert FAKE_STRIPE not in dumped
        assert FAKE_JWT not in dumped
        assert "****" in f.masked


def test_jwt_flagged_with_lower_confidence():
    findings = scan_secrets(make_zip({"a.js": f"const t='{FAKE_JWT}'".encode()}))
    jwt = next(f for f in findings if f.rule_id == "jwt-in-code")
    assert jwt.severity == "high" and jwt.confidence < 0.9


def test_generic_assignment_heuristic():
    src = b'PASSWORD = os.environ["APP_SECRET"]\n'
    ids = {f.rule_id for f in scan_secrets(make_zip({"settings.py": src}))}
    assert "generic-assignment" in ids


def test_skips_node_modules_binaries_and_lockfiles():
    entries = {
        "node_modules/pkg/index.js": f"'{FAKE_AWS}'".encode(),
        "logo.png": b"\x89PNG\x00\x00" + FAKE_AWS.encode(),
        "package-lock.json.lock": f"'{FAKE_AWS}'".encode(),
        "src/ok.ts": b"export const x = 1;",
    }
    assert scan_secrets(make_zip(entries)) == []


def test_clean_project_yields_no_findings():
    entries = {
        "src/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
        ".env.example": b"ANTHROPIC_API_KEY=\nDATABASE_URL=\n",
    }
    assert scan_secrets(make_zip(entries)) == []


def _jwt_with_role(role: str) -> str:
    import base64, json as _json
    def b64(d): return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'HS256'})}.{b64({'role': role, 'iss': 'supabase'})}." + "s" * 20


def test_supabase_anon_key_is_informational():
    src = f"const k = '{_jwt_with_role('anon')}'".encode()
    f = next(f for f in scan_secrets(make_zip({"a.ts": src}))
             if f.rule_id == "supabase-anon-key")
    assert f.severity == "low" and f.confidence <= 0.3


def test_anon_key_in_migration_not_reescalated():
    # migration context must NOT turn the public anon key into a
    # high-confidence "committed database migration" secret (that was
    # the source of a 40-row false-alarm wall in a real report).
    src = f"insert into x values ('{_jwt_with_role('anon')}');".encode()
    findings = scan_secrets(make_zip({"supabase/migrations/0001.sql": src}))
    f = next(f for f in findings if f.rule_id == "supabase-anon-key")
    assert f.severity == "low"
    assert f.confidence <= 0.3
    assert "committed database migration" not in f.title


def test_supabase_service_role_key_is_critical():
    src = f"const k = '{_jwt_with_role('service_role')}'".encode()
    f = next(f for f in scan_secrets(make_zip({"a.ts": src}))
             if f.rule_id == "jwt-in-code")
    assert f.severity == "critical"
    assert "service_role" in f.title


def test_doc_context_damps_but_keeps_finding():
    # A credential-shaped string inside a blog article: reported, but
    # capped at medium and confidence-damped (real-world case: a QA
    # tutorials site scored 0.0 from example passwords in its posts).
    zf = make_zip({
        "src/app/blog/posts/api-guide.ts":
            b'const example = os.environ["AWS_ACCESS_KEY_ID"];\n',
    })
    findings = scan_secrets(zf)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.confidence < 0.4
    assert "(documentation/example context)" in f.title


def test_same_secret_outside_doc_context_stays_critical():
    zf = make_zip({
        "src/config.ts": b'const key = os.environ["AWS_ACCESS_KEY_ID"];\n',
    })
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.9
    assert "(documentation" not in findings[0].title


def test_markdown_files_are_doc_context():
    zf = make_zip({"README.md": b'token: os.environ["AWS_ACCESS_KEY_ID"]\n'})
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_plpgsql_secret_assignment_caught():
    zf = make_zip({
        "supabase/migrations/20260509_cron.sql":
            b"DECLARE\n  v_cron_secret text := os.environ["DATABASE_SECRET"];\n",
    })
    findings = scan_secrets(zf)
    rule_ids = {f.rule_id for f in findings}
    assert "sql-secret-assignment" in rule_ids


def test_migration_context_raises_confidence_and_marks_title():
    zf = make_zip({
        "supabase/migrations/0001_seed.sql":
            b"insert into email_settings (password) values ('smtp-password-value');\n"
            b"select set_config('app.api_key', 'abcdefghijklmnop', false);\n"
            b"DECLARE v_cron_secret text := os.environ["DATABASE_SECRET"];\n",
    })
    findings = scan_secrets(zf)
    assert findings, "expected at least one finding in a migration"
    for f in findings:
        assert f.confidence >= 0.9
        assert "(committed database migration)" in f.title


def test_migration_context_wins_over_doc_context():
    # examples/migrations/ is still a migration, not a teaching example
    zf = make_zip({
        "examples/migrations/0001.sql":
            b"DECLARE v_password text := os.environ["DATABASE_SECRET"];\n",
    })
    findings = scan_secrets(zf)
    assert len(findings) >= 1
    assert all("(committed database migration)" in f.title for f in findings)
    assert all(f.confidence >= 0.9 for f in findings)


# --- Test-fixture / placeholder damping ------------------------------------
# Real-world false positives from auditing aiagent2046-coder/devtools-aggregator:
# a jest.setup.ts whose Anthropic key and JWT are clearly-labelled placeholders.
# Damped like doc context (capped at medium + confidence damped), never dropped.

# Minimal equivalents of the two manually-confirmed placeholders. Both carry a
# self-describing marker inside the matched VALUE itself.
FIXTURE_ANTHROPIC = "sk-ant-api03-test-placeholder-not-real-key"
FIXTURE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJ0ZXN0Ijp0cnVlfQ.placeholder_sig_for_unit_tests"
)


def test_jest_setup_placeholder_anthropic_key_is_damped():
    zf = make_zip({
        "jest.setup.ts":
            (f"  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY "
             f"|| '{FIXTURE_ANTHROPIC}',\n").encode(),
    })
    f = next(f for f in scan_secrets(zf) if f.rule_id == "anthropic-api-key")
    assert f.severity == "medium"        # capped down from critical
    assert f.confidence < 0.4            # damped
    assert "(test fixture/placeholder context)" in f.title


def test_test_fixture_damping_sets_structured_context():
    # The damping is also exposed as a machine-readable field, so the
    # future Fix Pack filter can check finding.context != "test_fixture"
    # instead of string-matching the title suffix.
    zf = make_zip({
        "jest.setup.ts":
            (f"  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY "
             f"|| '{FIXTURE_ANTHROPIC}',\n").encode(),
    })
    f = next(f for f in scan_secrets(zf) if f.rule_id == "anthropic-api-key")
    assert f.context == "test_fixture"


def test_non_damped_finding_has_null_context():
    zf = make_zip({"src/config.ts": f"const k = '{FAKE_AWS}';\n".encode()})
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].context is None


def test_jest_setup_placeholder_jwt_is_damped():
    zf = make_zip({"jest.setup.ts": f"const t = '{FIXTURE_JWT}';\n".encode()})
    f = next(f for f in scan_secrets(zf) if f.rule_id == "jwt-in-code")
    assert f.severity not in ("critical", "high")  # capped to medium
    assert f.severity == "medium"
    assert "(test fixture/placeholder context)" in f.title


def test_real_secret_in_test_path_still_flagged():
    # REGRESSION: a genuine, non-placeholder-looking secret sitting in a test
    # file must NOT be silenced. Test paths aren't inherently safe; only the
    # path+placeholder-value combination is treated as a fixture.
    zf = make_zip({"src/config.test.ts": f"const k = '{FAKE_AWS}';\n".encode()})
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.9
    assert "(test fixture" not in findings[0].title


def test_placeholder_value_outside_test_path_still_flagged():
    # The AND logic in action: a placeholder-labelled value in a real
    # production file is NOT damped (path signal absent), so it stays critical.
    zf = make_zip({"src/config.ts": f"const k = '{FIXTURE_ANTHROPIC}';\n".encode()})
    findings = scan_secrets(zf)
    f = next(f for f in findings if f.rule_id == "anthropic-api-key")
    assert f.severity == "critical"
    assert f.confidence >= 0.9
    assert "(test fixture" not in f.title
