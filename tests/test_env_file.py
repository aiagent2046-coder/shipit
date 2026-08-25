"""scripts/env_file.py: reading a deployment's env file without sourcing it.

The properties here are the ones whose failure is silent. A parser that drops
the tail of a value does not raise -- it hands back a shorter password, and
the mail server answers `535 Incorrect authentication data`, which reads
exactly like a password somebody changed. That happened on this deployment
before there was anything here to read the file, and the operator changed a
password that was correct.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "env_file.py"

SPEC = importlib.util.spec_from_file_location("shipit_env_file", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None

env_file = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = env_file
SPEC.loader.exec_module(env_file)


def write_env(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------- which file


def test_the_default_is_the_deployments_own_file(monkeypatch) -> None:
    monkeypatch.delenv("SHIPIT_ENV_FILE", raising=False)
    assert env_file.env_file_path() == Path("/opt/shipit/.env")


def test_shipit_env_file_chooses_another(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SHIPIT_ENV_FILE", str(tmp_path / "other.env"))
    assert env_file.env_file_path() == tmp_path / "other.env"


# ------------------------------------------------------------------- reading


def test_a_missing_file_is_an_empty_mapping(tmp_path) -> None:
    assert env_file.read_values(tmp_path / "nope.env") == {}


def test_a_directory_is_an_empty_mapping_not_an_exception(tmp_path) -> None:
    assert env_file.read_values(tmp_path) == {}


def test_plain_values_survive(tmp_path) -> None:
    path = write_env(tmp_path, "SMTP_HOST=smtp.example.com\nSMTP_PORT=587\n")
    values = env_file.read_values(path)
    assert values["SMTP_HOST"] == "smtp.example.com"
    assert values["SMTP_PORT"] == "587"


@pytest.mark.parametrize("quote", ["'", '"'])
def test_quotes_are_stripped_and_the_value_is_not(tmp_path, quote) -> None:
    """The whole point. bash would expand the `$`; this must not touch it."""
    secret = "pa$$w0rd#x&y"  # scan-allow: fixture password, not a credential
    path = write_env(tmp_path, f"SMTP_PASSWORD={quote}{secret}{quote}\n")
    assert env_file.read_values(path)["SMTP_PASSWORD"] == secret


def test_a_value_with_spaces_and_guillemets_survives(tmp_path) -> None:
    """Real contents of this file: a bank name and a postal address."""
    bank = "«МТС-Банк»"
    address = "214030 г. Смоленск, ул. Некрасова д. 16"
    path = write_env(
        tmp_path, f"BANK_TRANSFER_BANK='{bank}'\nBANK_ADDRESS='{address}'\n")
    values = env_file.read_values(path)
    assert values["BANK_TRANSFER_BANK"] == bank
    assert values["BANK_ADDRESS"] == address


def test_a_dsn_keeps_everything_after_its_first_special_character(
    tmp_path,
) -> None:
    dsn = "postgresql://u:p$w@127.0.0.1:5432/db"  # scan-allow: fixture DSN
    path = write_env(tmp_path, f"DATABASE_URL='{dsn}'\n")
    assert env_file.read_values(path)["DATABASE_URL"] == dsn


def test_comments_and_blank_lines_are_not_variables(tmp_path) -> None:
    path = write_env(tmp_path, "# SMTP_HOST=commented.example.com\n\nA=1\n")
    values = env_file.read_values(path)
    assert "SMTP_HOST" not in values
    assert values == {"A": "1"}


def test_an_unmatched_quote_is_left_alone(tmp_path) -> None:
    """Half a quoted value is a typo, and guessing which half was meant would
    hand back something the operator never wrote."""
    path = write_env(tmp_path, "SMTP_PASSWORD='half\n")
    assert env_file.read_values(path)["SMTP_PASSWORD"] == "'half"


# --------------------------------------------------------------- filling in


def test_only_the_asked_for_prefix_is_filled(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("YOOKASSA_SHOP_ID", raising=False)
    path = write_env(
        tmp_path, "SMTP_HOST=smtp.example.com\nYOOKASSA_SHOP_ID=1\n")

    env_file.fill_environment("SMTP_", path)

    import os
    assert os.environ["SMTP_HOST"] == "smtp.example.com"
    assert "YOOKASSA_SHOP_ID" not in os.environ


def test_the_environment_wins_over_the_file(monkeypatch, tmp_path) -> None:
    """THE SAFETY PROPERTY, and deliberately the opposite of
    deploy/scripts/check_release_migrations.py. These commands run anywhere; a
    file winning would let someone who had pointed a variable at a test server
    act on production because a file they never looked at existed on the box.
    """
    import os
    monkeypatch.setenv("SMTP_HOST", "smtp.chosen-by-hand.example.com")
    path = write_env(tmp_path, "SMTP_HOST=smtp.from-the-file.example.com\n")

    env_file.fill_environment("SMTP_", path)

    assert os.environ["SMTP_HOST"] == "smtp.chosen-by-hand.example.com"


def test_an_empty_variable_is_not_a_choice(monkeypatch, tmp_path) -> None:
    """`SMTP_HOST=` in the environment is an absent value, not a decision to
    have no host: settings_from_env treats "" as missing, so leaving it would
    make the file unreadable for anyone whose shell exports empties."""
    import os
    monkeypatch.setenv("SMTP_HOST", "")
    path = write_env(tmp_path, "SMTP_HOST=smtp.example.com\n")

    env_file.fill_environment("SMTP_", path)

    assert os.environ["SMTP_HOST"] == "smtp.example.com"


def test_filling_from_a_missing_file_changes_nothing(monkeypatch, tmp_path):
    import os
    monkeypatch.delenv("SMTP_HOST", raising=False)

    returned = env_file.fill_environment("SMTP_", tmp_path / "nope.env")

    assert returned == tmp_path / "nope.env"
    assert "SMTP_HOST" not in os.environ


def test_the_path_consulted_is_returned_so_it_can_be_named(tmp_path) -> None:
    path = write_env(tmp_path, "SMTP_HOST=smtp.example.com\n")
    assert env_file.fill_environment("SMTP_", path) == path


def test_fill_environment_defaults_to_the_deployments_file(monkeypatch, tmp_path):
    monkeypatch.setenv("SHIPIT_ENV_FILE", str(tmp_path / "chosen.env"))
    assert env_file.fill_environment("SMTP_") == tmp_path / "chosen.env"


# ------------------------------------------------- nobody may source it again


def test_the_smtp_check_never_prints_the_incantation_that_breaks_it() -> None:
    """THE FAILURE THIS MODULE EXISTS TO STOP.

    Until 2026-08-25 scripts/verify_smtp_locally.py -- the script whose entire
    job is diagnosing why mail does not send -- printed `set -a; .
    /opt/shipit/.env` as the way to run it. bash expands `$` in an unquoted
    value, so an operator who followed that advice with a CORRECT password got
    SMTPAuthenticationError from a truncated one, and every arrow then pointed
    at the password. A diagnostic that manufactures the fault it reports sends
    people to change things that were right.

    Read off the AST rather than the text, and that is the whole point of the
    test: a `#` comment explaining why this must not be done is exactly what
    should be there, while a string the program can print is the defect. The
    module docstring counts as printable -- main() prints it on bad usage.

    Not a repo-wide sweep. The developer scripts documenting `set -a; . ./.env`
    mean a laptop's own file: its contents are the developer's, and a mangled
    value surfaces in the next local run rather than in a customer's missing
    refund notice.
    """
    import ast

    path = REPO_ROOT / "scripts" / "verify_smtp_locally.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))

    printable = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]

    assert printable, "nothing was parsed; the test is not looking at the file"
    offenders = [text for text in printable if "set -a" in text]
    assert offenders == [], (
        "this script can print advice to source the production env file, "
        "which truncates values at `$` and produces the very "
        "SMTPAuthenticationError it is being run to diagnose: "
        + "; ".join(repr(text[:120]) for text in offenders)
    )
