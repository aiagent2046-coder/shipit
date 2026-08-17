"""The proof stage must not be able to die unnoticed inside the test suite.

run_proof_stage catches every exception and returns an empty result, because
proof must never kill Fix Pack delivery (app/proof/stage.py). That fail-open
is right in production and dangerous in tests: when the fixpack repo fake
lacked ``set_proof_json``, every delivery test in
tests/test_fixpack_process_endpoint.py ran with a dead proof stage, logged
``AttributeError`` at ERROR, and passed. 1683 lines of coverage over the
endpoint that hosts the proof gate, exercising none of it — and CI green the
whole time.

A committed note (tests/restore_fixpack_process_endpoint.patch) had described
the missing method as a TODO rather than adding it, and named only one of the
four fakes that needed it.

Two guards here, because each catches what the other misses:

* the structural one finds a fake that will silently skip proof BEFORE it is
  used in a new test;
* the behavioural one proves the fail-open really does hide the failure, so
  the first guard's reason cannot quietly stop being true.
"""

from __future__ import annotations

import asyncio
import pathlib
import re

from app.proof.stage import run_proof_stage

_TESTS_DIR = pathlib.Path(__file__).resolve().parent

# A class standing in for the fixpack repository is recognised by the methods
# the processor calls on it; either one alone is enough to reach delivery.
_REPO_MARKERS = ("mark_fixpack_delivered", "claim_one_paid")


def _fakes_missing_set_proof_json() -> list[str]:
    offenders: list[str] = []
    for path in sorted(_TESTS_DIR.glob("*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^class (\w+).*?(?=^class |\Z)", source,
                                 re.S | re.M):
            body = match.group(0)
            if not any(marker in body for marker in _REPO_MARKERS):
                continue
            # A test class (pytest collects `Test*`) is not a repo stand-in;
            # it only mentions the methods it asserts on.
            if match.group(1).startswith("Test"):
                continue
            if "set_proof_json" not in body:
                offenders.append(f"{path.name}:{match.group(1)}")
    return offenders


def test_every_fixpack_repo_fake_can_persist_proof_json() -> None:
    offenders = _fakes_missing_set_proof_json()
    assert not offenders, (
        "these fixpack repo fakes lack set_proof_json, so any test using them "
        "runs with a silently dead proof stage and still passes: "
        + ", ".join(offenders)
    )


def test_a_repo_without_set_proof_json_really_does_fail_open(caplog) -> None:
    """The premise of the guard above, pinned.

    If run_proof_stage ever stopped swallowing this, a missing method would
    announce itself and the structural check would be redundant — worth
    knowing rather than assuming.

    The log assertion is not decoration. Written without it, this test passed
    while never reaching the setter at all: the plan touched a file the
    templates had no finding in, so routing selected nothing and the stage
    returned empty at its first branch — the right result for the wrong
    reason, which is the exact defect the file is about.
    """

    class _NoSetter:
        """Deliberately missing set_proof_json."""

    # The plan has to look like a secrets Fix Pack, or stage routing selects
    # no template (select_templates keys secrets_leak off secret_fixes /
    # leaked_env_*) and the AttributeError below is never reached.
    plan = type("_Plan", (), {
        "files": {"config.py": "STRIPE_KEY = os.environ['STRIPE_KEY']\n"},
        "deletions": [],
        "secret_fixes": [{"file": "config.py", "rule_id": "stripe-live-key"}],
    })()

    with caplog.at_level("INFO", logger="app.proof.stage"):
        result = asyncio.run(run_proof_stage(
            job_id="j-silent",
            zip_bytes=_zip_with_secret(),
            plan=plan,
            fixpack_repo=_NoSetter(),
        ))

    text = caplog.text
    assert "proof stage failed" in text, text
    assert "set_proof_json" in text, text

    # Fail-open: no exception reaches the caller, and the stage reports
    # nothing rather than reporting a failure.
    assert result.primary is None
    assert list(result.reports) == []


# Matches app.scan.secrets' stripe-live-key rule without putting a literal
# sk_live_… in this file — same runtime assembly tests/test_proof_secrets_leak
# uses, and the reason is the same: GitHub push protection rejects the branch
# otherwise (it rejected this one).
_FAKE_STRIPE = "sk_" + "live_" + ("A" * 24)


def _zip_with_secret() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo/config.py", f'STRIPE_KEY = "{_FAKE_STRIPE}"\n')
    return buf.getvalue()
