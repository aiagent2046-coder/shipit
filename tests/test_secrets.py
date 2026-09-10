"""Tests for the secrets scanner. The masking test is the critical one:
a scanner that leaks the secrets it finds is worse than no scanner.
"""

import io
import zipfile

import pytest

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
    src = b'PASSWORD = "correct-horse-battery"\n'
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
    import base64
    import json as _json
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
            b'const example = "AKIAIOSFODNN7EXAMPLE";\n',
    })
    findings = scan_secrets(zf)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.confidence < 0.4
    assert "(documentation/example context)" in f.title


def test_same_secret_outside_doc_context_stays_critical():
    zf = make_zip({
        "src/config.ts": b'const key = "AKIAIOSFODNN7EXAMPLE";\n',
    })
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.9
    assert "(documentation" not in findings[0].title


def test_markdown_files_are_doc_context():
    zf = make_zip({"README.md": b'token: "AKIAIOSFODNN7EXAMPLE"\n'})
    findings = scan_secrets(zf)
    # EVERY finding on the line, not just the first: this fixture is matched by
    # the specific aws-access-key-id rule AND by generic-assignment, because
    # rules are applied to a line independently and neither yields to the
    # other. That overlap predates the name-vocabulary widening -- `api_key:
    # "AKIA..."` has always produced both -- and the fixture only avoided it
    # by naming the variable `token`, a word the vocabulary happened to miss.
    #
    # Pinning a COUNT here pinned that gap by accident, so the assertion now
    # states what the test is actually about: a secret in a markdown file is
    # damped to documentation context, whichever rule reports it.
    assert findings
    assert {f.severity for f in findings} == {"medium"}
    assert {f.context for f in findings} == {"doc_example"}


def test_plpgsql_secret_assignment_caught():
    zf = make_zip({
        "supabase/migrations/20260509_cron.sql":
            b"DECLARE\n  v_cron_secret text := 'sup3r-s3cret-value-123';\n",
    })
    findings = scan_secrets(zf)
    rule_ids = {f.rule_id for f in findings}
    assert "sql-secret-assignment" in rule_ids


def test_migration_context_raises_confidence_and_marks_title():
    zf = make_zip({
        "supabase/migrations/0001_seed.sql":
            b"insert into email_settings (password) values ('smtp-password-value');\n"
            b"select set_config('app.api_key', 'abcdefghijklmnop', false);\n"
            b"DECLARE v_cron_secret text := 'sup3r-s3cret-value-123';\n",
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
            b"DECLARE v_password text := 'real-committed-password';\n",
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
    # Two independent signals agree that this is a fixture -- a test path AND
    # a value that self-labels as a placeholder -- so this damps further than
    # the path alone does.
    assert f.severity == "low"
    assert f.confidence < 0.2
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
    assert f.severity == "low"
    assert "(test fixture/placeholder context)" in f.title


def test_realistic_secret_in_test_path_is_damped_but_kept():
    """POLICY REVERSAL, deliberate. This test previously asserted the opposite:
    that a non-placeholder-looking value in a test file stays critical.

    That policy was measured on this repository and failed. 23 of 26 findings
    landed in tests/, 14 of them as "Fix before launch", and none of those 14
    were in code the app runs. A realistic fake key is realistic precisely
    because it doesn't say "fake" in it, so requiring the marker meant the
    damping almost never fired.

    The finding is NOT dropped -- a real key committed to a test file is still
    committed -- it is capped at medium and reported under its own heading.
    """
    zf = make_zip({"src/config.test.ts": f"const k = '{FAKE_AWS}';\n".encode()})
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence < 0.4
    assert findings[0].context == "test_file"
    assert "(test file)" in findings[0].title


def test_same_secret_outside_a_test_path_stays_critical():
    """The other half of the reversal: damping is bounded by the path. The
    identical value in application code is untouched."""
    zf = make_zip({"src/config.ts": f"const k = '{FAKE_AWS}';\n".encode()})
    findings = scan_secrets(zf)
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.9
    assert findings[0].context is None


def test_commented_out_secret_is_damped_but_kept():
    """A match on a comment line is documentation living in a source file: a
    commented-out example, or a rule declaring the shape it searches for.
    This scanner's own pattern comments were reported as leaked credentials.

    Capped rather than dropped: a commented-out REAL key is still committed.
    """
    zf = make_zip({"app/scan/rules.py": f"# example: {FAKE_AWS}\n".encode()})
    findings = scan_secrets(zf)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].context == "comment"
    assert "(commented-out line)" in findings[0].title


def test_secret_on_a_code_line_with_a_trailing_comment_is_not_damped():
    """The comment check is a prefix check, and the boundary is deliberate:
    deciding whether an offset sits inside a comment needs a parser per
    language, and a wrong answer there silently hides a real secret."""
    zf = make_zip({"src/config.py": f"KEY = '{FAKE_AWS}'  # temporary\n".encode()})
    findings = scan_secrets(zf)
    assert findings[0].severity == "critical"
    assert findings[0].context is None


def test_placeholder_value_outside_test_path_still_flagged():
    # Damping is anchored on the path, never on the value alone. Anyone can
    # write "placeholder" next to a live key; being in a test file is the
    # signal that carries weight.
    zf = make_zip({"src/config.ts": f"const k = '{FIXTURE_ANTHROPIC}';\n".encode()})
    findings = scan_secrets(zf)
    f = next(f for f in findings if f.rule_id == "anthropic-api-key")
    assert f.severity == "critical"
    assert f.confidence >= 0.9
    assert "(test fixture" not in f.title


# --- connection strings carrying their own password ------------------------
#
# Assembled from parts, like FAKE_STRIPE above: written whole, a DSN with a
# password trips GitHub push protection and this repo's own added-secrets CI
# scanner, neither of which can tell a fixture from a leak.
def _dsn(scheme: str, user: str, password: str, host: str,
         tail: str = "/app") -> str:
    return f"{scheme}://{user}:{password}@{host}{tail}"


def _dsn_findings(body: str, path: str = "src/config.py"):
    return [f for f in scan_secrets(make_zip({path: body.encode()}))
            if f.rule_id.startswith("connection-string")]


def test_connection_string_password_is_found_in_source():
    """The gap this rule closes.

    Nothing else caught it: generic-assignment needs quotes around the value
    and a secret-shaped variable NAME, so a DSN assigned to DATABASE_URL or
    handed straight to a client constructor scanned completely clean. A
    connection string is the whole database in one line -- address, user and
    password -- so a leaked one needs no other finding to be exploitable.
    """
    body = f'DB = "{_dsn("postgresql", "svc", "zQ8vT2mKp", "db.prod.example.com", ":5432/app")}"\n'
    findings = _dsn_findings(body)

    assert [f.rule_id for f in findings] == ["connection-string-password"]
    assert findings[0].severity == "critical"


def test_the_password_never_appears_in_the_finding():
    """The scanner's own rule, applied to the value it is most tempting to
    quote back: a finding is persisted and rendered, so the mask is the only
    thing standing between "we found your password" and republishing it."""
    password = "zQ8vT2mKp"
    body = f'DB = "{_dsn("postgresql", "svc", password, "db.prod.example.com")}"\n'
    finding = _dsn_findings(body)[0]

    assert password not in finding.masked
    assert password not in finding.title
    assert password not in repr(finding)


def test_an_interpolated_password_is_not_a_finding():
    """`postgres://u:${DB_PASSWORD}@host` contains no credential at all --  scan-allow: docstring example, interpolated
    the value lives in the environment, which is exactly where we tell people
    to put it. Reporting it would punish the fix we recommend.
    """
    for placeholder in ("${DB_PASSWORD}", "%s", "{pw}", "<password>"):
        body = f'DB = "{_dsn("postgres", "u", placeholder, "prod.example.com")}"\n'
        assert _dsn_findings(body) == [], placeholder


def test_a_passwordless_connection_string_is_not_a_finding():
    body = 'DB = "postgresql://readonly@db.example.com/app"\n'
    assert _dsn_findings(body) == []


def test_a_tutorial_default_gets_its_own_rule_id_and_stays_low():
    """postgres:postgres@localhost is what every quickstart ships. Filing it
    under the same id as a live credential would collapse the two together in
    the report and offer to rewrite a docker-compose default into an
    environment variable. Same reasoning as supabase-anon-key.
    """
    for password in ("postgres", "change_me", "change-me", "changeme"):
        body = f'DB = "{_dsn("postgres", "app", password, "localhost", ":5432/app")}"\n'
        findings = _dsn_findings(body)

        assert [f.rule_id for f in findings] == [
            "connection-string-dev-password"], password
        assert findings[0].severity == "low"


def test_a_real_password_on_a_local_host_is_reported_but_not_critical():
    """Its own id, for the same reason the tutorial default has one.

    This used to assert `connection-string-password` -- the id of a live
    leak -- on a finding _dsn_severity had just titled "to a local/
    development host". The report reads the id, so the reader was told to
    "change that user's password at your database provider" about a database
    on their own laptop. See tests/test_local_dsn_advice.py.
    """
    body = f'DB = "{_dsn("postgres", "app", "zQ8vT2mK", "localhost", ":5432/app")}"\n'
    finding = _dsn_findings(body)[0]

    assert finding.rule_id == "connection-string-local-host"
    assert finding.severity == "medium"


def test_a_dev_default_is_not_escalated_by_migration_context():
    """Migration context raises confidence because a secret in applied state
    is real. A tutorial password is not, and the escalation would drag it back
    up to a leak claim -- the same exemption supabase-anon-key already has.
    """
    body = f'-- {_dsn("postgres", "postgres", "postgres", "db")}\n'
    finding = _dsn_findings(body, path="migrations/0001_init.sql")[0]

    assert finding.rule_id == "connection-string-dev-password"
    assert finding.severity == "low"


def test_the_match_spans_the_whole_connection_string():
    """The Fix Pack replaces a secret by locating the QUOTED literal around
    it. A match that stopped at the host left `:5432/app` inside the quotes
    and produced DB = "os.environ['DATABASE_URL']:5432/app" -- scrubbed, and
    not valid code. _verify_scrubbed passes that, because the password really
    is gone, so nothing downstream would have caught it.
    """
    from app.fixpack.generate import _apply_secret_fix
    from app.scan.secrets import iter_secret_matches

    dsn = _dsn("postgresql", "svc", "zQ8vT2mKp", "db.prod.example.com",
               ":5432/app")
    src = f'DB = "{dsn}"\n'
    raw = next(raw for f, raw in iter_secret_matches(make_zip({"c.py": src.encode()}))
               if f.rule_id == "connection-string-password")

    assert raw == dsn, "the match must cover port and database, not stop at the host"

    rewritten, _ = _apply_secret_fix(src, "connection-string-password", raw,
                                     "os.environ['DATABASE_URL']")
    assert rewritten.strip() == "DB = os.environ['DATABASE_URL']"


@pytest.mark.parametrize("special", ["$", "{", "}", "${literal}"])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_ordinary_quoted_credentials_keep_dollars_and_braces(special, quote):
    value = "aB3" + special + "eF6gH8jK2mN4"
    source = f"api_key = {quote}{value}{quote}\n"
    findings = scan_secrets(make_zip({"config.py": source.encode()}))
    assert any(f.rule_id == "generic-assignment" for f in findings)
    assert all(value not in f.masked for f in findings)


@pytest.mark.parametrize("value,expected", [
    ("aB3$eF6gH8jK2mN4", True),
    ("aB3{eF6gH8jK2mN4", True),
    ("aB3}eF6gH8jK2mN4", True),
    ("${process.env.API_KEY}", False),
    ("prefix-${process.env.API_KEY}", False),
])
def test_template_interpolation_is_distinct_from_literal_secret_bytes(value, expected):
    source = f"const apiKey = `{value}`;\n"
    findings = scan_secrets(make_zip({"src/config.ts": source.encode()}))
    assert any(f.rule_id == "generic-assignment" for f in findings) is expected


@pytest.mark.parametrize("value", [
    "${API_TOKEN}", "${!token_env_name:-}", "$SHIPIT_API_TOKEN",
    "${API_TOKEN:-}", "${FIRST_TOKEN}${SECOND_TOKEN}",
])
@pytest.mark.parametrize("path,prefix", [
    ("deploy/call.sh", ""), ("bin/call", "#!/usr/bin/env bash\n"),
])
def test_shell_parameter_references_do_not_become_secret_findings(path, prefix, value):
    source = prefix + f'token="{value}"\n'
    assert scan_secrets(make_zip({path: source.encode()})) == []


@pytest.mark.parametrize("source", [
    "token='${API_TOKEN}'\n",
    'token="\\${API_TOKEN}"\n',
    'token="prefix-${API_TOKEN}"\n',
    'token="${API_TOKEN:-fallback-credential}"\n',
    "printf '%s' 'token=\"${API_TOKEN}\"'\n",
    "cat <<'EOF'\ntoken=\"${API_TOKEN}\"\nEOF\n",
])
def test_shell_literal_bytes_are_not_hidden_by_parameter_filter(source):
    findings = scan_secrets(make_zip({"deploy/call.sh": source.encode()}))
    assert any(f.rule_id == "generic-assignment" for f in findings)


def test_shell_filter_continues_to_real_credential_on_the_same_line():
    value = "runtime-" + "literal-credential"
    source = f'token="${{API_TOKEN}}"; api_key="{value}"\n'
    findings = scan_secrets(make_zip({"deploy/call.sh": source.encode()}))
    generic = [f for f in findings if f.rule_id == "generic-assignment"]
    assert len(generic) == 1
    assert generic[0].masked.startswith("api_")


@pytest.mark.parametrize("path,source", [
    ("src/config.ts", 'const token="${API_TOKEN}";'),
    ("src/config.py", 'token="${API_TOKEN}"'),
    ("config.yml", 'token: "${API_TOKEN}"'),
])
def test_non_shell_literals_resembling_parameter_references_stay_visible(path, source):
    assert any(f.rule_id == "generic-assignment"
               for f in scan_secrets(make_zip({path: source.encode()})))


@pytest.mark.parametrize("run", [
    'run: |\n        token="${API_TOKEN}"\n',
    'run: token="${!token_env_name:-}"\n',
    "run: 'token=\"$SHIPIT_API_TOKEN\"'\n",
])
def test_workflow_only_excludes_parameter_references_inside_shell_run(run):
    source = (
        'jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n'
        '      token: "${API_TOKEN}"\n    steps:\n    - ' + run
    )
    findings = scan_secrets(make_zip({".github/workflows/deploy.yml": source.encode()}))
    assert [(f.rule_id, f.line) for f in findings] == [("generic-assignment", 5)]


@pytest.mark.parametrize("shell", ["python", "node"])
def test_workflow_run_with_non_shell_interpreter_keeps_quoted_literal(shell):
    source = (
        'jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n'
        f'    - shell: {shell}\n      run: |\n        token="${{API_TOKEN}}"\n'
    )
    assert any(f.rule_id == "generic-assignment" for f in scan_secrets(
        make_zip({".github/workflows/deploy.yml": source.encode()})))


def test_recursive_yaml_and_complex_keys_do_not_crash_secret_scan():
    source = (
        'defaults:\n  ? [complex, key]\n  : value\n  run:\n'
        '    ? [shell, other]\n    : bash\n'
        'extra: &recursive\n  self: *recursive\n'
        'jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n'
        '    - run: token="${API_TOKEN}"\n'
    )
    assert scan_secrets(make_zip({".github/workflows/deploy.yml": source.encode()})) == []


def test_oversized_yaml_retains_findings_when_context_parsing_is_declined():
    source = '# ' + 'x' * 256_000 + '\nrun: token="${API_TOKEN}"\n'
    findings = scan_secrets(make_zip({".github/workflows/deploy.yml": source.encode()}))
    assert any(f.rule_id == "generic-assignment" for f in findings)


@pytest.mark.parametrize("source", [
    "value = f'const db_password = \"{GENERIC_16}\";'\n",
    'value = f"update config set api_secret = \'{GENERIC_16}\';"\n',
    "label = 'кириллица'; value = f'const db_password = \"{GENERIC_16}\";'\n",
])
def test_python_formatted_fields_are_not_literal_credentials(source):
    assert scan_secrets(make_zip({"scripts/probe.py": source.encode()})) == []


@pytest.mark.parametrize("source", [
    "value = 'const db_password = \"{GENERIC_16}\";'\n",
    "value = f'const db_password = \"prefix-{GENERIC_16}\";'\n",
    "value = f'const db_password = \"literal-credential\"; {suffix}'\n",
])
def test_python_formatted_string_filter_keeps_actual_literal_secret_bytes(source):
    assert any(f.rule_id == "generic-assignment" for f in scan_secrets(
        make_zip({"scripts/probe.py": source.encode()})))


def test_aws_example_in_python_docstring_is_reported_without_automatic_fix_context():
    value = "AKIA" + "IOSFODNN7EXAMPLE"
    source = f'"""Example credential: {value}."""\nprint("ok")\n'
    findings = scan_secrets(make_zip({"scripts/probe.py": source.encode()}))
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"
    assert findings[0].context == "doc_example"
    assert findings[0].severity == "medium"


@pytest.mark.parametrize("predicate", [
    "WHERE  password", "WHERE\tpassword", "WHERE\n  password",
    "WHERE\r\n  password", "WHERE (password", "WHERE ((u.password",
    "WHERE TRUE AND  password", "WHERE FALSE OR (u.password",
    "WHERE u . password", "WHERE /* predicate */ u.password",
    "HAVING  password", "JOIN other u ON (u.password",
])
def test_sql_comparison_formatting_does_not_create_assignments(predicate):
    source = f"SELECT id FROM users {predicate} = 'redacted'" + ")" * predicate.count("(") + ";\n"
    findings = scan_secrets(make_zip({"schema.sql": source.encode()}))
    assert not any(f.rule_id == "sql-secret-assignment" for f in findings)


@pytest.mark.parametrize("source", [
    "UPDATE users SET password = 'redacted' WHERE id = 1;",
    "DECLARE password text := 'redacted';",
    "CREATE TABLE config (password varchar(255) DEFAULT ('redacted'));",
    "-- WHERE password is compared elsewhere\nUPDATE users SET password = 'redacted';",
    "/* WHERE predicate */ UPDATE users SET password = 'redacted';",
    "UPDATE users SET note = 'WHERE', password = 'redacted';",
    "WITH selected AS (SELECT id FROM users WHERE active) "
    "UPDATE users SET password = 'redacted';",
    "SELECT id FROM users WHERE (password = 'redacted'); "
    "UPDATE users SET password = 'redacted';",
])
def test_sql_predicate_context_does_not_hide_real_assignments(source):
    findings = scan_secrets(make_zip({"schema.sql": source.encode()}))
    assert any(f.rule_id == "sql-secret-assignment" for f in findings)
