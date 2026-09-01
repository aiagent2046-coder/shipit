"""The rotation stand's build, checked the way the stand checks itself.

A fixture that silently fails to contain what it is a fixture FOR is the worst
kind: every run against it comes back clean and reads as a passing result. This
stand would report `gone_from_bundle` — proving the opposite of what it is built
to prove — and nothing in the output would say so. So the builder verifies its
own product, and these tests verify the verifier.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SRC = (Path(__file__).resolve().parents[1] / "smoke" / "service_role_bundle"
        / "build_rotation_stand.py")
_spec = importlib.util.spec_from_file_location("build_rotation_stand", _SRC)
build_rotation_stand = importlib.util.module_from_spec(_spec)
sys.modules["build_rotation_stand"] = build_rotation_stand
_spec.loader.exec_module(build_rotation_stand)

_build = build_rotation_stand._build
_verify = build_rotation_stand._verify

# Structurally a Supabase JWT, semantically nothing: three dot-separated
# base64 segments. The real stand mints one with a `service_role` claim; this
# file only tests where the string LANDS, so it needs no claim at all and
# carries none.
FAKE = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidGVzdCJ9.not-a-signature"


def test_the_credential_lands_two_hops_from_the_html(tmp_path):
    """The stand's reason for existing. drydock.co's live run read 8 chunks and
    found nothing, because there is nothing there — so the transitive walk has
    never been shown to reach a FINDING. A key in the first script would prove
    the crawl exactly where it was never in doubt."""
    out = tmp_path / "dist"
    _build(out, FAKE)

    html = (out / "index.html").read_text()
    assert FAKE not in html, "one hop would not exercise the transitive walk"

    entry = next(p for p in (out / "assets").iterdir()
                 if p.name.startswith("entry-"))
    assert FAKE not in entry.read_text(), "two hops means the key is not here"

    client = next(p for p in (out / "assets").iterdir()
                  if p.name.startswith("client-"))
    assert FAKE in client.read_text()

    # And the second chunk has to be REACHABLE from the first by a quoted
    # filename -- the shape app/proof/served_bundle._asset_refs_in_js follows.
    assert client.name in entry.read_text()


def test_a_build_that_lost_the_key_is_refused(tmp_path):
    """The check that stops the stand from proving the opposite of its purpose.
    A directory that does not carry the credential yields a clean bundle-check,
    which reads as `gone_from_bundle` — a passing-looking result from a broken
    fixture."""
    out = tmp_path / "dist"
    _build(out, FAKE)
    client = next(p for p in (out / "assets").iterdir()
                  if p.name.startswith("client-"))
    client.write_text(client.read_text().replace(FAKE, "REMOVED"))

    with pytest.raises(SystemExit, match="prove the opposite"):
        _verify(out, FAKE, expect_present=True)


def test_a_key_that_leaked_into_the_html_is_refused(tmp_path):
    """The other way the stand degrades quietly: still a finding, but a one-hop
    one, and the transitive claim would be made on evidence that never tested
    it."""
    out = tmp_path / "dist"
    _build(out, FAKE)
    index = out / "index.html"
    index.write_text(index.read_text().replace("loading…", FAKE))

    with pytest.raises(SystemExit, match="one-hop crawl"):
        _verify(out, FAKE, expect_present=True)


def test_a_rebuild_with_a_different_key_changes_the_chunk_name(tmp_path):
    """Content-hashed asset names, so the three variants cannot be confused for
    one another by a cache or by a reader comparing two runs. It also means the
    URL in `assets_read` differs between run 3 and run 2, which is how a person
    checking the ledger sees that the deployment really changed."""
    a, b = tmp_path / "a", tmp_path / "b"
    _build(a, FAKE)
    _build(b, FAKE.replace("not-a-signature", "a-different-signature"))

    names_a = {p.name for p in (a / "assets").iterdir()}
    names_b = {p.name for p in (b / "assets").iterdir()}

    assert names_a.isdisjoint(names_b)


def test_building_twice_over_an_existing_directory_is_clean(tmp_path):
    """The second and fourth runs rebuild in place. A leftover chunk from the
    previous variant would keep serving the OLD key, and the check would report
    `unchanged` about a deployment that did change."""
    out = tmp_path / "dist"
    _build(out, FAKE)
    stale = {p.name for p in (out / "assets").iterdir()}

    _build(out, FAKE.replace("not-a-signature", "another-signature"))
    now = {p.name for p in (out / "assets").iterdir()}

    assert stale.isdisjoint(now)
    assert len(now) == 2, "exactly the entry and client chunks, nothing carried over"
