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
