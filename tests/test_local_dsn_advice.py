"""A connection string to localhost must not be handed the advice for a leak.

_dsn_severity grades a connection string on TWO independent signals: is the
password a tutorial default, and is the host the developer's own machine.
Only the first one routed the finding's rule_id, so the third outcome -- a
real-looking password against localhost or a docker-compose service name --
kept the id of a live leak while carrying the title of a local one.

What the reader saw, on dubinc/dub (audit a5fcb681), twice in one report:

    Password in a connection string to a local/development host
    → "Change that user's password at your database provider"

There is no provider. Nothing is hosting it. The one thing that IS worth
saying about that finding -- the password is now published, so change it
anywhere you reused it -- was not said, because the dictionary entry being
rendered was written about a production database.

The tests below walk the reader's path: scan a file, take the finding the
scanner produces, and ask the report layer what it would print.
"""

import io
import zipfile

from app.report.plain_language import PLAIN, plain_fields
from app.scan.secrets import scan_secrets

# Not in _DSN_DEV_PASSWORDS, and shaped like something a person chose.
# Assembled from parts like the rest of this repo's DSN fixtures: written
# whole, a connection string with a password trips GitHub push protection
# and our own added-secrets CI scanner, neither of which can tell a fixture
# from a leak.
REAL_PASSWORD = "zQ8" + "vT2mKp"
SCHEME = "postgres" + "://"
REMOTE_HOST = "db.prod.example.com"


def _dsn(password: str, host: str) -> str:
    return f"{SCHEME}app:{password}@{host}:5432/app"


def _finding(dsn: str, path: str = "src/config.ts"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(path, f'const DB = "{dsn}"\n'.encode())
    buf.seek(0)
    found = [f for f in scan_secrets(buf)
             if f.rule_id.startswith("connection-string")]
    assert len(found) == 1, found
    return found[0]


def _advice(finding) -> tuple[str, str, str]:
    """What the report prints for this finding: (what, risk, fix)."""
    return plain_fields(vars(finding))


LIVE = _dsn(REAL_PASSWORD, REMOTE_HOST)          # critical: a real database
LOCAL = _dsn(REAL_PASSWORD, "localhost")         # medium:  the dev's machine
DEFAULT = _dsn("postgres", "localhost")          # low:     a tutorial default


def test_three_verdicts_get_three_rule_ids():
    """The grader has always produced three outcomes. Two ids meant two of
    them shared a translation, and the report collapses on rule_id -- so a
    localhost DSN and a production one could also be grouped together as one
    row, with the highest severity of the pair speaking for both."""
    ids = [_finding(d).rule_id for d in (LIVE, LOCAL, DEFAULT)]

    assert ids == [
        "connection-string-password",
        "connection-string-local-host",
        "connection-string-dev-password",
    ]
    assert len(set(ids)) == 3


def test_severity_still_says_which_one_is_the_emergency():
    assert _finding(LIVE).severity == "critical"
    assert _finding(LOCAL).severity == "medium"
    assert _finding(DEFAULT).severity == "low"


def test_a_local_database_is_not_sent_to_a_provider_dashboard():
    """The defect itself, stated as the reader meets it.

    Aimed at the instruction rather than at any word: the local finding must
    not be printed the sentence written for a hosted database. Before the
    fix these two calls returned byte-identical text.
    """
    local_fix = _advice(_finding(LOCAL))[2]
    live_fix = _advice(_finding(LIVE))[2]

    # The first sentence of the live-leak advice: go to your provider and
    # change the password there.
    live_instruction = live_fix.split(",")[0]
    assert "provider" in live_instruction, "the live advice under test moved"

    assert local_fix != live_fix
    assert live_instruction not in local_fix
    # Deleting the advice is not an improvement over the wrong advice: with
    # no dictionary entry plain_fields falls back to the technical title and
    # a static secret finding has no fix_hint of its own, so "what to do"
    # renders empty. (The coverage guard in tests/test_plain_language.py is
    # the systematic version of this; here it is asserted where it is read.)
    assert len(local_fix) > 40


def test_the_live_leak_still_gets_the_rotate_it_now_advice():
    """The half that must never be damped. A production DSN with a real
    password is the database in one line, and this is the only finding of the
    three where the reader has to act today."""
    what, risk, fix = _advice(_finding(LIVE))

    assert (what, risk, fix) == PLAIN["connection-string-password"]


def test_the_headline_and_the_advice_describe_the_same_database():
    """The finding's own title said "local/development host" while the text
    under it described a hosted one. Whatever the wording becomes, the three
    outcomes must keep three distinct explanations."""
    texts = {_advice(_finding(d)) for d in (LIVE, LOCAL, DEFAULT)}

    assert len(texts) == 3


def test_a_docker_compose_service_name_counts_as_local():
    """A DSN whose host is just `db` is a compose file naming its own
    service. The host is not resolvable outside that network, so it is the
    same case as localhost -- and _DSN_LOCAL_HOSTS has always graded it that
    way; only the id was missing."""
    finding = _finding(_dsn(REAL_PASSWORD, "db"))

    assert finding.rule_id == "connection-string-local-host"
    assert finding.severity == "medium"


def test_a_local_dsn_is_not_escalated_by_migration_context():
    """Migration context raises confidence because a secret in applied state
    is real -- and it appends "(committed database migration)" to the title.
    A localhost DSN in a migration is still localhost. Same exemption the
    anon key and the tutorial password already have; it had to be extended
    by hand, so it gets a test."""
    finding = _finding(_dsn(REAL_PASSWORD, "localhost"),
                       path="migrations/0001_init.sql")

    assert finding.rule_id == "connection-string-local-host"
    assert finding.severity == "medium"
    assert "migration" not in finding.title


def test_a_local_dsn_still_takes_the_ordinary_path_damping():
    """Unlike the anon key and the tutorial password, the local-host variant
    is NOT exempt from path context, and should not be: a localhost DSN in a
    test file is a test's database twice over, and belongs in the report's
    non-production section rather than beside application code.

    Severity is unchanged -- damping caps, it never drops."""
    finding = _finding(LOCAL, path="tests/db_setup.test.ts")

    assert finding.rule_id == "connection-string-local-host"
    assert finding.severity == "medium"
    assert finding.context == "test_file"


# --- the two paths the damping table could not see (issue #353, part 2) -----
#
# One repository, one rule, three files, and the difference between damped and
# not was whether the word "playwright" landed in a directory or a filename:
#
#   apps/web/playwright/assert-local-database.ts   damped   (directory segment)
#   .github/workflows/playwright.yaml              NOT      (filename only)
#   apps/web/.env.example                          NOT      (no doc suffix)


def test_a_service_container_password_in_a_ci_workflow_is_damped():
    finding = _finding(LOCAL, path=".github/workflows/playwright.yaml")

    assert finding.context == "ci_service"
    assert finding.severity == "medium"
    assert "CI service container" in finding.title


def test_a_real_connection_string_in_a_ci_workflow_is_still_critical():
    """The mutation this pairing exists to catch: "damp everything under
    `.github/`". A workflow can hold a real cloud connection string the same
    way a migration can -- deploy jobs are where they live -- and that one is
    as direct a leak as any."""
    finding = _finding(_dsn(REAL_PASSWORD, REMOTE_HOST),
                       path=".github/workflows/deploy.yaml")

    assert finding.rule_id == "connection-string-password"
    assert finding.severity == "critical"
    assert finding.context is None


def test_only_the_workflows_folder_counts_as_ci():
    """`.github/` also holds issue templates, CODEOWNERS and a funding file.
    None of them runs anything."""
    finding = _finding(LOCAL, path=".github/ISSUE_TEMPLATE/bug_report.md")

    assert finding.context == "doc_example"   # damped as a document, not as CI


def test_the_password_is_still_never_printed():
    """The new id routes to new prose. Every path out of the scanner still
    has to mask, including this one."""
    finding = _finding(LOCAL)
    what, risk, fix = _advice(finding)

    assert REAL_PASSWORD not in finding.masked
    assert REAL_PASSWORD not in finding.title
    assert REAL_PASSWORD not in what + risk + fix
