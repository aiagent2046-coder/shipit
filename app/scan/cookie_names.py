"""Which cookie names are authentication names -- the one language-independent part.

Both halves of the rule need the same answer, so it lives here rather than in
whichever half was written first. The vocabulary is deliberately small: a theme or
locale cookie is read by scripts on purpose, and reporting it would make the rule
noise. An UNRESOLVED name is not a match either: a name passed as a parameter or
built at run time cannot be shown to be a session cookie, and guessing is how a
scanner starts asserting what it cannot see.

Excluded on purpose, with the reason the rule's docstring repeats:

  * `csrf` / `xsrf` / `state` / `nonce` -- the double-submit pattern REQUIRES the
    cookie to be readable by script, so a missing HttpOnly there is the design.
"""

from __future__ import annotations

import re

_AUTH_TOKENS = frozenset({
    "auth", "authorization", "bearer", "credential", "jwt", "login", "password",
    "refresh", "session", "sessionid", "sid", "token",
})
_AUTH_PHRASES = ("api_key", "apikey", "access_token", "refresh_token", "session_id", "session_token")
_NON_AUTH_TOKENS = frozenset({"csrf", "xsrf", "state", "nonce"})


def normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def is_auth_cookie(name: str) -> bool:
    """True only for a name that says, on its own, that it carries identity."""
    normalised = normalise(name)
    if not normalised:
        return False
    tokens = set(normalised.split("_"))
    if tokens & _NON_AUTH_TOKENS:
        return False
    if tokens & _AUTH_TOKENS:
        return True
    return any(phrase in normalised for phrase in _AUTH_PHRASES)
