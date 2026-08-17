"""Guards on the shipped build-step egress allowlist.

The list itself is host config (squid `dstdomain`), but it is in the repo so it
can be reviewed, and these checks exist so review is not the only thing
standing between a green build and a wildcard.

The failure mode being guarded is specific and likely: someone hits a build
that fails on a domain nobody allowlisted — exactly what happened to LibreChat
on 2026-08-17 — and makes it pass by widening the entry instead of naming the
domain. A bare `.com` turns the list into "allow all" while still reading, at a
glance, like an allowlist.
"""

from __future__ import annotations

from pathlib import Path

ALLOWLIST = (
    Path(__file__).resolve().parent.parent
    / "deploy" / "sandbox-runner" / "squid-build-allowlist.conf"
)

# Public suffixes that must never appear as an entry. squid's `dstdomain`
# treats a leading dot as "domain and all subdomains", so `.com` matches every
# .com host — but even the bare form is a mistake worth failing on, since a
# reader cannot tell which one the author meant.
_TLDS = {
    "com", "org", "io", "net", "dev", "co", "sh", "app", "cloud", "ai",
}


def _entries() -> list[str]:
    """Domain entries only — squid ignores blank lines and `#` comments, and
    so does the review this file exists for."""
    return [
        line.strip()
        for line in ALLOWLIST.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_the_allowlist_ships_in_the_repo() -> None:
    """It lived only on the prod host until 2026-08-17, which is why a failed
    measurement could not be diagnosed from anything a reviewer could see."""
    assert ALLOWLIST.is_file()
    assert _entries(), "an allowlist with no entries would deny every build"


def test_no_entry_is_a_bare_tld_or_wildcard() -> None:
    for entry in _entries():
        stripped = entry.lstrip(".")
        assert stripped not in _TLDS, (
            f"{entry!r} matches every host under .{stripped} — that is not an "
            "allowlist. Name the registry instead."
        )
        assert "*" not in entry, f"{entry!r}: squid dstdomain uses a leading dot, not a glob"


def test_the_registry_that_blocked_the_detector_run_is_present() -> None:
    """LibreChat died at step 2/31 on `apk upgrade` with HTTP 403 from this
    proxy. This entry is the fix; a regression here silently restores a
    measurement that reports 0-booted for a reason unrelated to the apps."""
    assert "dl-cdn.alpinelinux.org" in _entries()


def test_pip_can_reach_the_host_that_actually_serves_wheels() -> None:
    """pypi.org resolves metadata; the wheel comes from files.pythonhosted.org.
    A list carrying only the first fails every pip build at the download step —
    the kind of half-configuration that looks correct in review."""
    entries = _entries()
    if "pypi.org" in entries:
        assert "files.pythonhosted.org" in entries


def test_the_broader_github_grant_is_not_quietly_added() -> None:
    """Not a security boundary (see the file's header — build egress is not
    enforced), but a scope decision that should be made deliberately and in the
    open rather than to make one build pass."""
    entries = {e.lstrip(".") for e in _entries()}
    assert "github.com" not in entries
    assert "objects.githubusercontent.com" not in entries
