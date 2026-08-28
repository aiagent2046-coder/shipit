"""The model-comparison harness must at least be runnable.

It is the tool this project uses to decide which model reads customers' code,
and it had been unable to even IMPORT since batch_audit.py renamed its sample
(`REPOS` -> `SERIES`). Nothing noticed, because nothing imported it: it is a
hand-run script whose only reader is an operator typing it at the moment they
need the answer, which is the worst moment to discover an ImportError.

So this file is deliberately cheap and makes no network calls. It asserts the
things that were actually broken -- the module loads, the default sample
resolves, the URL is built for both kinds of ref -- and nothing about what a
comparison concludes, which is a judgement no test can make.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


def _stub_run(compare, monkeypatch, fake_scan, *, repos: int, models: int):
    """Neutralise everything a comparison does except the part under test:
    no network, no provider, no real scan."""
    monkeypatch.setattr(compare, "fetch", lambda slug, ref: _ONE_FILE_ZIP)
    monkeypatch.setattr(compare, "run_scan", fake_scan)
    monkeypatch.setattr(compare, "load_provider_credentials", lambda: None)
    monkeypatch.setattr(
        compare, "LLMClient",
        lambda *a, **k: type("C", (), {
            "providers": [object()],
            "with_model": lambda self, m: self,
        })())


def _make_one_file_zip() -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("r/README.md", "# hi")
    return buf.getvalue()


_ONE_FILE_ZIP = _make_one_file_zip()


@pytest.fixture(scope="module")
def compare():
    return importlib.import_module("scripts.compare_models")


def test_the_harness_imports(compare) -> None:
    assert callable(compare.main)


def test_the_default_sample_comes_from_the_batch_series(compare) -> None:
    """Imported, not copied: one list, so a comparison and a batch run can be
    said to have covered the same repositories."""
    from scripts.batch_audit import SERIES

    assert compare.SERIES is SERIES
    assert SERIES, "the sample is empty; a comparison would measure nothing"
    for series in SERIES:
        assert series.slug.count("/") == 1, series.slug
        assert len(series.sha) == 40, series.sha


def test_a_pinned_sha_and_a_branch_get_different_urls(compare, monkeypatch):
    """codeload wants `zip/<sha>` for a commit and `zip/refs/heads/<name>` for
    a branch. Asking for a branch under the first spelling 404s, which is how
    a switch to pinned SHAs breaks `--repos owner/x` a week later."""
    urls: list[str] = []

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b"zip-bytes"

    monkeypatch.setattr(compare.urllib.request, "urlopen",
                        lambda url, timeout=0: urls.append(url) or _Resp())

    compare.fetch("acme/app", "c15be34f488521123a0ff77a30a7f885c3f1fdc6")
    compare.fetch("acme/app", "main")

    assert urls == [
        "https://codeload.github.com/acme/app/zip/"
        "c15be34f488521123a0ff77a30a7f885c3f1fdc6",
        "https://codeload.github.com/acme/app/zip/refs/heads/main",
    ]


def test_an_unpriced_model_is_refused_before_any_call(compare, capsys) -> None:
    """The estimate would be fiction at DEFAULT_PRICE, and the run would spend
    real money to produce it."""
    assert compare.main(["--models", "no-such-model", "--dry-run"]) == 2
    assert "not in app/llm/pricing.py" in capsys.readouterr().err


def test_every_priced_model_has_a_dry_run_estimate(compare) -> None:
    """--dry-run exists to answer "what will this cost" BEFORE spending it. A
    priced model missing here silently falls back to $1.00 per audit, which for
    the models in this table is wrong by up to 4x in either direction."""
    from app.llm import pricing

    missing = sorted(set(pricing.PRICE_TABLE) - set(compare._ROUGH_COST_PER_AUDIT))
    assert missing == [], (
        f"priced but not estimated: {missing}. Add a row to "
        "_ROUGH_COST_PER_AUDIT in scripts/compare_models.py.")


def test_the_estimate_and_the_harness_agree_on_how_many_passes(compare) -> None:
    """_ROUGH_COST_PER_AUDIT is measured at ONE pass, because that is what
    this script runs: it calls run_scan without llm_passes and takes the
    default.

    Production paid audits run PAID_AUDIT_PASSES=2 and cost about twice as
    much -- median $3.42 against $0.96, maximum $9.18 against $4.60, measured
    over llm_usage on 2026-08-28. Comparing across that line is easy and was
    done: a $7.61 production audit was read as "above the documented spread"
    when it was an ordinary two-pass run held against a one-pass yardstick.

    If the default ever moves, every number in that table silently doubles
    wrong and --dry-run under-quotes by half. This is the coupling, pinned.
    """
    import inspect

    from app.scan.pipeline import run_scan

    assert inspect.signature(run_scan).parameters["llm_passes"].default == 1, (
        "run_scan's default pass count changed. Either pass llm_passes=1 "
        "explicitly in this script, or re-measure _ROUGH_COST_PER_AUDIT -- "
        "the estimates there are one-pass figures.")


# --- a long run must not lose what it has already paid for -----------------
#
# On 2026-08-28 a run of three repositories died on the last one and left no
# file at all: two repositories' worth of provider calls -- real money, already
# spent -- went with it, and the question had to be asked again from scratch.


def test_results_are_written_after_every_audit(compare, tmp_path, monkeypatch):
    """Not once at the end. Asserted by looking at the file DURING the run,
    which is the only moment the difference exists."""
    out = tmp_path / "cmp.json"
    seen: list[dict] = []

    def fake_scan(raw, client, **kwargs):
        # Read the file as it stands before this audit's row is added.
        seen.append(json.loads(out.read_text()) if out.exists() else {})
        return {"score": {"total": 5.0, "basis": "static+llm", "categories": {}},
                "findings": [], "llm": {}, "llm_usage": {"model": "m"}}

    _stub_run(compare, monkeypatch, fake_scan, repos=2, models=1)

    assert compare.main(["--models", "claude-haiku-4.5",
                         "--repos", "acme/one", "acme/two",
                         "--json", str(out)]) == 0

    # Before the first audit: nothing. Before the second: the first is already
    # on disk -- which is exactly what an interrupted run keeps.
    assert seen[0] == {}
    assert list(seen[1]) == ["acme/one"]


def test_a_scan_that_raises_does_not_discard_the_run(compare, tmp_path,
                                                     monkeypatch):
    """Same posture the fetch and zip failures already have, extended to the
    scan itself. The failure is recorded rather than skipped -- "this pair was
    attempted and raised" is a result -- and `findings` stays a list so the
    pairwise summary and the overlap maths keep working."""
    out = tmp_path / "cmp.json"
    calls = {"n": 0}

    def fake_scan(raw, client, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("provider exploded")
        return {"score": {"total": 5.0, "basis": "static+llm", "categories": {}},
                "findings": [], "llm": {}, "llm_usage": {"model": "m"}}

    _stub_run(compare, monkeypatch, fake_scan, repos=2, models=1)

    assert compare.main(["--models", "claude-haiku-4.5",
                         "--repos", "acme/one", "acme/two",
                         "--json", str(out)]) == 0

    saved = json.loads(out.read_text())
    assert "provider exploded" in saved["acme/one"]["claude-haiku-4.5"]["raised"]
    assert saved["acme/one"]["claude-haiku-4.5"]["findings"] == []
    # ...and the second repository was still measured.
    assert saved["acme/two"]["claude-haiku-4.5"]["total"] == 5.0


def test_the_file_is_never_left_half_written(compare, tmp_path, monkeypatch):
    """A truncated JSON is worse than a missing one: it looks like a result.
    The write goes through a temporary and a rename, so the reader sees either
    the previous complete file or the new complete one."""
    out = tmp_path / "cmp.json"
    compare.save(out, {"first": 1})

    seen_during: list[str] = []
    real_replace = Path.replace

    def watching_replace(self, target):
        # Mid-write: the target still holds the PREVIOUS complete document.
        seen_during.append(Path(target).read_text())
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", watching_replace)
    compare.save(out, {"second": 2})

    assert json.loads(seen_during[0]) == {"first": 1}
    assert json.loads(out.read_text()) == {"second": 2}
    assert not list(tmp_path.glob("*.partial")), "the temporary must not linger"
