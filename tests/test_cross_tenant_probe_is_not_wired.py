"""The cross-tenant probe is library code, and this test is what keeps it so.

It is the only probe in the project that WRITES to a customer's system -- a
signup on their auth endpoint -- and two things have to be settled before any
route may reach it: the throwaway account it leaves behind (nothing deletes an
auth user without the service-role admin key, which the probe must not hold),
and the confirmation email that signup makes the CUSTOMER's project send to a
domain we do not control, against an auth-email quota that on Supabase's
built-in SMTP is a handful of messages an hour. One probe could lock a
customer's real signups for an hour.

Until both are decided this module may be imported by tests and by the
measurement script, and by nothing that serves a request. A guard in a
docstring is a hope; a guard in a test is a rule.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SERVING = ("app/routes", "app/main.py", "app/worker.py", "app/mcp")


def test_no_request_path_imports_the_signup_probe():
    offenders = []
    for base in _SERVING:
        p = _ROOT / base
        files = [p] if p.is_file() else list(p.rglob("*.py")) if p.exists() else []
        for f in files:
            if "cross_tenant_probe" in f.read_text():
                offenders.append(str(f.relative_to(_ROOT)))
    assert offenders == [], (
        "the cross-tenant probe creates an account on the customer's project; "
        f"it must stay unreachable from a request until its blockers are "
        f"resolved, and these import it: {offenders}")


def test_the_probe_module_itself_names_both_blockers():
    """The two conditions live in the module's own docstring, so whoever wires
    it later reads them at the import site and not in a test they did not
    run."""
    src = (_ROOT / "app/proof/cross_tenant_probe.py").read_text()
    assert "service-role admin key" in src, "the cleanup blocker is not named"
    assert "quota" in src, "the email-quota blocker is not named"
