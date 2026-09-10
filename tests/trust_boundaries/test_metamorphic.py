"""Metamorphic invariants: edits that cannot change what the code IS must
not change what the audit SAYS, and edits that change it must change the
findings in exactly the predicted way.

This is how detector stability is measured without any LLM: the first half
pins precision (no noise from formatting), the second pins recall (a real
regression cannot hide behind a benign-looking diff).
"""

from __future__ import annotations

from tests.detector_samples import SAMPLES

from app.scan.static import run_static_scan

from .conftest import clean_nextjs_repo, findings_keys, make_zip

SECRET_FILE = "src/config.ts"
SECRET_BODY = f'export const STRIPE_KEY = "{SAMPLES["STRIPE"]}"\n'


def _scan(entries: dict[str, str]):
    return run_static_scan(make_zip(entries))["findings"]


def test_renaming_a_local_variable_changes_nothing():
    # The new name must be as credential-shaped as the old one, or the rename
    # is not the only edit. PAYMENTS_API_KEY was used here until
    # generic-assignment learned to read a credential word as a COMPONENT of a
    # name: it then reported that line as well, and the test failed for a
    # correct reason -- the rename had added `api_key` to the identifier.
    # STRIPE_PUBLISHABLE is a rename that carries no such word, so it isolates
    # what this invariant is about: the VALUE is what the scanner reads, and
    # moving it to a differently named constant must not change the verdict.
    base = clean_nextjs_repo(**{SECRET_FILE: SECRET_BODY})
    renamed = clean_nextjs_repo(**{
        SECRET_FILE: SECRET_BODY.replace("STRIPE_KEY", "STRIPE_PUBLISHABLE")
    })
    assert findings_keys(_scan(base)) == findings_keys(_scan(renamed))


def test_added_comments_and_blank_lines_change_nothing_but_line_numbers():
    base = clean_nextjs_repo(**{SECRET_FILE: SECRET_BODY})
    shifted = clean_nextjs_repo(**{
        SECRET_FILE: "\n" * 40 + "// payment configuration\n" + SECRET_BODY
    })
    base_f, shifted_f = _scan(base), _scan(shifted)
    assert findings_keys(base_f) == findings_keys(shifted_f)
    # ...while the line number DOES move, which is why (rule_id, file) --
    # not line -- is a finding's identity across audits (app/monitor/diff.py).
    base_line = {f["rule_id"]: f["line"] for f in base_f}
    shifted_line = {f["rule_id"]: f["line"] for f in shifted_f}
    assert shifted_line["stripe-live-key"] > base_line["stripe-live-key"]


def test_reordering_independent_statements_changes_nothing():
    base = clean_nextjs_repo(**{
        SECRET_FILE: SECRET_BODY + 'export const REGION = "eu"\n'
    })
    reordered = clean_nextjs_repo(**{
        SECRET_FILE: 'export const REGION = "eu"\n' + SECRET_BODY
    })
    assert findings_keys(_scan(base)) == findings_keys(_scan(reordered))


def test_adding_a_credentialed_env_file_adds_exactly_the_expected_finding():
    base = clean_nextjs_repo()
    hostile = clean_nextjs_repo(**{
        ".env": f"DATABASE_URL={SAMPLES['REMOTE_DSN']}\n"
    })
    added = set(findings_keys(_scan(hostile))) - set(findings_keys(_scan(base)))
    assert ("env-file-committed", ".env", "critical") in added
    assert all(rule in {"env-file-committed", "connection-string-password"}
               for rule, _, _ in added)


def test_scanning_the_same_bytes_twice_is_deterministic():
    repo = clean_nextjs_repo(**{SECRET_FILE: SECRET_BODY})
    assert _scan(repo) == _scan(dict(repo))
