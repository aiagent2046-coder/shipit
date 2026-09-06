"""Three exit codes, and why two of them must not be one.

The rehearsal exists because a day's worth of bundle-check requests went to a
hostname that was never configured. Its own failure modes have to stay
distinguishable for the same reason the thing it rehearses does:

    0   the deployment was read and classified — spending a real request now
        buys the ledger row, which is what the budget is for
    1   it ran, and the URL is not usable — a real request would learn this
        and cost one of five
   78   it could not run at all (no pepper), which is not a verdict about the
        deployment

Collapsing 1 and 78 is the exact mistake the HTTPS transport smoke made
earlier in this project: a missing interpreter reported as a failed check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "scripts" / "preflight_bundle_check.py"
_spec = importlib.util.spec_from_file_location("preflight_bundle_check", _SRC)
preflight_bundle_check = importlib.util.module_from_spec(_spec)
sys.modules["preflight_bundle_check"] = preflight_bundle_check
_spec.loader.exec_module(preflight_bundle_check)


class _Result:
    def __init__(self, status: str, findings=(), publishable=()):
        self.status = status
        self.detail = "detail"
        self.leaked = bool(findings)
        self.findings = list(findings)
        self.publishable = list(publishable)
        self.assets_read = ["(served html)"]
        self.evidence = {"reason": "x"}


class _Finding:
    def __init__(self, fp: str):
        self._fp = fp

    def evidence(self) -> dict:
        return {"pattern": "supabase_service_role", "redacted": "eyJ••••ab",
                "fingerprint": self._fp, "location": "/assets/c.js"}


def _run(monkeypatch, argv, result, pepper="test-pepper"):
    if pepper is None:
        monkeypatch.delenv("API_KEY_PEPPER", raising=False)
    else:
        monkeypatch.setenv("API_KEY_PEPPER", pepper)
    monkeypatch.setattr(preflight_bundle_check, "fetch_served_bundle",
                        lambda **kw: result)
    monkeypatch.setattr(sys, "argv", ["preflight_bundle_check.py", *argv])
    return preflight_bundle_check.main()


def test_a_readable_deployment_is_worth_a_real_request(monkeypatch, capsys):
    code = _run(monkeypatch, ["https://stand.example/"],
                _Result("checked", [_Finding("a" * 64)]))

    assert code == 0
    out = capsys.readouterr().out
    assert "supabase_service_role" in out


def test_an_unreadable_deployment_is_not_worth_one(monkeypatch, capsys):
    """The case that cost the day: `error / ConnectError`. The whole point is
    to learn it here, where it is free."""
    code = _run(monkeypatch, ["https://stand.example/"], _Result("error"))

    assert code == 1
    assert "burn one of five" in capsys.readouterr().err


def test_a_skipped_url_is_also_not_worth_one(monkeypatch):
    """`skipped` means the guard refused the URL. A real request would refuse
    it again, identically, and charge for the privilege."""
    assert _run(monkeypatch, ["https://stand.example/"],
                _Result("skipped")) == 1


def test_no_pepper_is_78_and_not_a_verdict(monkeypatch, capsys):
    """78, not 1. Without a pepper the fingerprints are empty, so the rotation
    rehearsal would compare two blanks — that is a fact about our environment,
    not about the deployment, and reporting it as a failed check is how the
    transport smoke once said a missing interpreter was a failed transport."""
    code = _run(monkeypatch, ["https://stand.example/"],
                _Result("checked"), pepper=None)

    assert code == 78
    assert "API_KEY_PEPPER" in capsys.readouterr().err


def test_an_empty_pepper_counts_as_absent(monkeypatch):
    assert _run(monkeypatch, ["https://stand.example/"],
                _Result("checked"), pepper="   ") == 78


def test_the_rotation_verdict_is_rehearsed_from_a_real_result_file(
        monkeypatch, capsys, tmp_path):
    """The baseline file is a previous run's response, stored verbatim, so the
    rehearsal reads the shape the endpoint actually writes rather than one
    hand-built to agree with it."""
    baseline = tmp_path / "rot-1.json"
    baseline.write_text('{"status":"checked","findings":'
                        '[{"pattern":"supabase_service_role",'
                        '"fingerprint":"' + "a" * 64 + '"}]}')

    code = _run(monkeypatch, ["https://stand.example/", "--baseline",
                              str(baseline)],
                _Result("checked", [_Finding("b" * 64)]))

    assert code == 0
    assert "replaced_still_shipped" in capsys.readouterr().out


def test_a_baseline_without_a_finding_list_is_refused(monkeypatch, tmp_path):
    """A file that carries no `findings` list cannot say the deployment was
    clean — it says we cannot read it. Treating a missing key as an empty list
    is the same fabrication the endpoint refuses."""
    baseline = tmp_path / "bad.json"
    baseline.write_text('{"status":"checked"}')

    assert _run(monkeypatch, ["https://stand.example/", "--baseline",
                              str(baseline)], _Result("checked")) == 1
