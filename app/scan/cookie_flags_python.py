"""The Python half: cookie-setting calls, and the settings that decide the flags.

WHAT IT READS. A call to `set_cookie`/`set_signed_cookie` whose cookie name is an
authentication-shaped name -- a literal string, or a module-level constant holding
one, resolved one hop -- and the HttpOnly/SameSite keywords on that call. Plus the
two Django settings that decide the same thing for the session cookie,
`SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE`.

WHY THE NAME DECIDES. A theme or locale cookie is read by scripts on purpose, and
reporting it would make the rule noise. The vocabulary is deliberately small
(session, sid, token, jwt, auth, bearer, login, access, refresh, credential,
password, api_key) and an UNRESOLVED name is silence: a name passed as a parameter
or built by an f-string cannot be shown to be a session cookie, and guessing it is
how a scanner starts asserting what it cannot see.

EXCLUSIONS, each one a claim this rule must not make:

  * `csrf`/`xsrf`/`state` names -- the double-submit pattern REQUIRES the cookie to
    be readable by script, so a missing HttpOnly there is the design, not the bug;
  * `SESSION_COOKIE_SAMESITE = None` -- Django's own documentation: the Python
    value None means the attribute is not sent and the BROWSER default applies.
    The STRING "None" is the cross-site value. Mechanically adjacent, semantically
    opposite, and the corpus pins both;
  * a missing SameSite on a call -- every browser in use defaults to Lax, so the
    absence of the attribute is a default, not a decision. Only an explicit
    SameSite=None removes the protection;
  * a missing `secure` -- a developer's localhost is the ordinary reason, and
    browsers already treat localhost as a secure context. Not this rule's claim;
  * `delete_cookie` -- clearing a cookie is not setting one.

WHAT IT DOES NOT RESOLVE. Middleware that rewrites the cookie on the way out,
framework defaults changing between versions, a name built at run time, and any
value that arrives as a variable instead of a literal.
"""

from __future__ import annotations

import ast

from app.scan.cookie_names import is_auth_cookie, normalise

_COOKIE_CALLS = frozenset({"set_cookie", "set_signed_cookie"})
_HTTPONLY_KEYS = ("httponly", "http_only")
_SAMESITE_KEYS = ("samesite", "same_site")

_SETTINGS = {
    "SESSION_COOKIE_HTTPONLY": "httponly",
    "SESSION_COOKIE_SAMESITE": "samesite",
}


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level `NAME = \"literal\"`, resolved one hop and no further."""
    constants: dict[str, str] = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            constants[node.targets[0].id] = node.value.value
    return constants


def _cookie_name(arg: ast.AST | None, constants: dict[str, str]) -> str:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return constants.get(arg.id, "")
    return ""


def _keyword(call: ast.Call, keys: tuple[str, ...]) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg in keys:
            return keyword.value
    return None


class _Unknown:
    """A value this rule will not guess at."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unknown>"


_UNKNOWN = _Unknown()


def _literal(node: ast.AST | None) -> object:
    """The value of a literal, or _UNKNOWN when it is anything else."""
    if isinstance(node, ast.Constant):
        return node.value
    return _UNKNOWN


def _call_evidence(call: ast.Call, constants: dict[str, str]) -> list[tuple[int, str, str]]:
    callee = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
    if callee not in _COOKIE_CALLS or not call.args:
        return []
    name = _cookie_name(call.args[0], constants)
    if not is_auth_cookie(name):
        return []

    evidence: list[tuple[int, str, str]] = []
    problems: list[str] = []
    httponly_problem = ""
    httponly_node = _keyword(call, _HTTPONLY_KEYS)
    if httponly_node is None:
        httponly_problem = "no HttpOnly"
    else:
        httponly = _literal(httponly_node)
        if httponly is not _UNKNOWN and not httponly:
            httponly_problem = "HttpOnly switched off"
    samesite_problem = ""
    samesite = _literal(_keyword(call, _SAMESITE_KEYS))
    if isinstance(samesite, str) and normalise(samesite) == "none":
        samesite_problem = "SameSite=None"
    problems = [problem for problem in (httponly_problem, samesite_problem) if problem]
    if problems:
        # One cookie is one finding, however many attributes are missing: the
        # claim is "this cookie is unprotected", and reporting a single cookie
        # twice would inflate the score for one defect. The kind only picks which
        # sentence explains the risk; `what` names every attribute found missing.
        evidence.append((
            call.lineno,
            f"sets the authentication cookie {name!r} with " + " and ".join(problems),
            "httponly" if httponly_problem else "samesite",
        ))
    return evidence


def _settings_evidence(node: ast.Assign | ast.AnnAssign) -> list[tuple[int, str, str]]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = node.value
    evidence: list[tuple[int, str, str]] = []
    for target in targets:
        if not isinstance(target, ast.Name) or target.id not in _SETTINGS:
            continue
        setting = target.id
        literal = _literal(value)
        if setting == "SESSION_COOKIE_HTTPONLY" and literal is not _UNKNOWN and not literal:
            evidence.append((
                node.lineno,
                "turns SESSION_COOKIE_HTTPONLY off, so the session cookie is readable by any script on the page",
                "httponly",
            ))
        if setting == "SESSION_COOKIE_SAMESITE" and isinstance(literal, str) and normalise(literal) == "none":
            evidence.append((
                node.lineno,
                "sets SESSION_COOKIE_SAMESITE to 'None', so browsers attach the session cookie to cross-site requests",
                "samesite",
            ))
    return evidence


def python_evidence(text: str) -> list[tuple[int, str, str]]:
    """(line, what, kind) for every unprotected authentication cookie in one file."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    constants = _module_string_constants(tree)
    evidence: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            evidence += _call_evidence(node, constants)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            evidence += _settings_evidence(node)
    return sorted(evidence)
