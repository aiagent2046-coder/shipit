"""An obviously made-up value in a test file is a fixture; a real-looking one is
not.

The contract (see value_looks_synthetic and _NO_PENALTY_CONTEXTS):

  * a value that CANNOT be real secret bytes -- an ellipsis (demonstrative
    truncation), a self-labelling word -- is test data and must not charge the
    Security score;
  * anything a real credential could spell keeps its charge.

The second half is pinned HARDER than the first, on purpose. Structure alone
marks obvious fakes too (a run of "A", an ascending run, a localhost host), but
the project already measured and rejected damping on shape: see
test_realistic_secret_in_test_path_is_damped_but_kept ("a realistic fake key is
realistic precisely because it doesn't say fake in it") and
test_a_local_dsn_still_takes_the_ordinary_path_damping ("damping caps, it never
drops"). This file keeps that boundary from being widened by accident.
"""

import io
import zipfile

from app.scan.secrets import scan_secrets, value_looks_synthetic


def _context_of(text: str, name: str = "tests/test_app.py") -> str | None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, text)
    buf.seek(0)
    findings = scan_secrets(buf)
    assert findings, "expected a finding"
    return findings[0].context


# --- value_looks_synthetic: only what cannot be real bytes -------------------

def test_an_ellipsis_is_synthetic():
    assert value_looks_synthetic("ghp_0123...klmn")


def test_a_self_labelling_word_is_synthetic():
    assert value_looks_synthetic("myChangemeValue")
    assert value_looks_synthetic("redacted_key_material")


def test_a_high_entropy_value_is_not_synthetic():
    assert not value_looks_synthetic("x7Kp2mQ9fLw3RnT6Yh2Vb8C4")


# --- the boundary the project already drew: shape is NOT enough --------------

def test_a_repeated_character_is_not_synthetic():
    """`AKIA` + "A"*16 is an obvious fake by shape, yet it must stay test_file
    (test_secrets.py pins that). Shape does not damp a fixture."""
    assert not value_looks_synthetic("AKIA" + "A" * 16)


def test_an_ascending_run_is_not_synthetic():
    assert not value_looks_synthetic("abcdefghijklmnop")


def test_a_host_is_not_synthetic():
    assert not value_looks_synthetic("postgresql://u:p@localhost:5432/db")  # scan-allow: fixture DSN


# --- context assignment in a test file --------------------------------------

def test_an_obviously_fake_value_in_a_test_is_a_fixture():
    assert _context_of('api_key = "apiKeyChangemeValue"') == "test_fixture"


def test_a_real_looking_value_in_a_test_keeps_its_charge():
    assert _context_of('api_key = "x7Kp2mQ9fLw3RnT6Yh2Vb8C4"') == "test_file"
