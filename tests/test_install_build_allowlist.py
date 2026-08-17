"""The squid.conf rewrite, tested against the config prod actually has.

This transform edits the one control that decides what a build container may
fetch, on a proxy whose failure to start takes every build on the host down.
The fixture below is the prod config as read on 2026-08-17 — line for line,
including the `http_access` rules the rewrite must not touch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy.scripts.install_build_allowlist import rewrite

LIST = Path("/etc/squid/squid-build-allowlist.conf")

# Verbatim shape of /etc/squid/squid.conf on the prod VPS.
PROD = """\
# minimal egress allowlist for sandbox builds
acl allowed_dst dstdomain .npmjs.org
acl allowed_dst dstdomain .pypi.org
acl allowed_dst dstdomain .pythonhosted.org
acl SSL_ports port 443
acl CONNECT method CONNECT
http_access deny CONNECT !SSL_ports
http_access allow allowed_dst
http_access deny all
http_port 3128
cache deny all
access_log /var/log/squid/access.log squid
"""


def test_the_three_inline_entries_collapse_into_one_reference() -> None:
    out = rewrite(PROD, LIST).splitlines()
    assert out.count(f'acl allowed_dst dstdomain "{LIST}"') == 1
    for gone in (".npmjs.org", ".pypi.org", ".pythonhosted.org"):
        assert not any(
            line.startswith("acl allowed_dst") and gone in line for line in out
        )


def test_the_reference_stays_above_the_http_access_rule_that_uses_it() -> None:
    """squid evaluates in order; an ACL defined after the `http_access allow`
    referring to it is a config that will not parse."""
    out = rewrite(PROD, LIST).splitlines()
    assert out.index(f'acl allowed_dst dstdomain "{LIST}"') < out.index(
        "http_access allow allowed_dst"
    )


def test_nothing_but_the_allowed_dst_lines_is_touched() -> None:
    """The blast radius has to be exactly three lines. Everything else in this
    file governs whether the proxy denies, listens, or logs at all."""
    out = rewrite(PROD, LIST).splitlines()
    for preserved in (
        "acl SSL_ports port 443",
        "acl CONNECT method CONNECT",
        "http_access deny CONNECT !SSL_ports",
        "http_access allow allowed_dst",
        "http_access deny all",
        "http_port 3128",
        "cache deny all",
        "access_log /var/log/squid/access.log squid",
        "# minimal egress allowlist for sandbox builds",
    ):
        assert preserved in out, f"rewrite dropped {preserved!r}"


def test_running_it_twice_changes_nothing_the_second_time() -> None:
    """The operator will re-run this after a failed attempt — that is exactly
    how it got run the first two times."""
    once = rewrite(PROD, LIST)
    assert rewrite(once, LIST) == once


def test_a_config_without_the_acl_is_refused_rather_than_guessed() -> None:
    """Inventing an ACL in a config we were not shown would silently change
    what the proxy permits."""
    with pytest.raises(SystemExit):
        rewrite("http_port 3128\nhttp_access deny all\n", LIST)


def test_the_trailing_newline_survives() -> None:
    assert rewrite(PROD, LIST).endswith("\n")


# --- inline mode ------------------------------------------------------------

def test_inline_writes_one_acl_line_per_domain_and_no_file_reference() -> None:
    """The escape hatch for a squid that will not read the referenced file:
    same grant, no dependency on ACL-file parsing."""
    out = rewrite(PROD, LIST, domains=[".npmjs.org", "dl-cdn.alpinelinux.org"])
    lines = out.splitlines()
    assert "acl allowed_dst dstdomain .npmjs.org" in lines
    assert "acl allowed_dst dstdomain dl-cdn.alpinelinux.org" in lines
    assert str(LIST) not in out


def test_inline_keeps_every_domain_above_the_rule_that_uses_them() -> None:
    domains = [".npmjs.org", ".pypi.org", "dl-cdn.alpinelinux.org"]
    lines = rewrite(PROD, LIST, domains=domains).splitlines()
    rule = lines.index("http_access allow allowed_dst")
    for d in domains:
        assert lines.index(f"acl allowed_dst dstdomain {d}") < rule


def test_inline_is_idempotent_too() -> None:
    domains = [".npmjs.org", "dl-cdn.alpinelinux.org"]
    once = rewrite(PROD, LIST, domains=domains)
    assert rewrite(once, LIST, domains=domains) == once


def test_switching_between_file_and_inline_does_not_accumulate() -> None:
    """The operator will try one, then the other. Neither may leave the other's
    lines behind — a stale reference beside inline domains would grant twice
    and confuse the next reader about which one is live."""
    domains = [".npmjs.org", "dl-cdn.alpinelinux.org"]
    as_file = rewrite(PROD, LIST)
    as_inline = rewrite(as_file, LIST, domains=domains)
    assert str(LIST) not in as_inline
    back_to_file = rewrite(as_inline, LIST)
    assert back_to_file.count("acl allowed_dst") == 1
