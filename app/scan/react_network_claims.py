"""Project bounded network-cleanup prose into source-bound atomic claims.

This is a small compositional parser, not a semantic-similarity classifier.
Source names supply entity roles; independent clauses supply raise, await,
reset, rejection and same-state UI roles. Clause order and conjunctions do not
supply identity. Every character must be consumed: an unknown clause, foreign
binding, extra mechanism or changed polarity keeps the observation separate.
The projection selects a hypothesis; it does not verify its consequences.
"""
from __future__ import annotations

import re


_LINE = r"(?:\s+on line [0-9]{1,6})?"
_GAP = r"\s+"
_ART = r"(?:the\s+)?"
_NETWORK = r"(?:network(?:\s+level)?|transport)"
_ERROR = r"(?:error|exception|failure|rejection)"
_FETCH = r"(?:fetch(?:\s+(?:call|request))?|network(?:\s+request)?|request)"
_NO_CLEANUP = (r"(?:no|without(?:\s+any)?)\s+(?:surrounding\s+)?"
               r"(?:try/catch|catch(?:\s+or\s+finally)?|finally)(?:\s+block)?")
_UNTIL = r"(?:\s+(?:until|unless)\s+(?:the\s+)?(?:page\s+is\s+reloaded|user\s+reloads(?:\s+the\s+page)?))?"
_EXAMPLES = (r"(?:for example\s+)?(?:offline|dns failure|timeout|connection reset|the connection drops mid flight)"
             r"(?:\s*,\s*(?:offline|dns failure|timeout|connection reset))*")
_HTTP_CONTRAST = r"not\s+an?\s+http\s+error\s+response"
_REJECTED = r"(?:a\s+)?(?:rejected\s+promise|thrown\s+exception(?:\s+such as\s+a\s+connection reset)?)"
_QUALIFIER = (r"(?:" + _HTTP_CONTRAST + r"(?:,\s*but\s+" + _REJECTED + r")?|" + _REJECTED
              + r"(?:,\s*" + _HTTP_CONTRAST + r")?|" + _EXAMPLES + r")"
              + r"(?:\s+for example\s+" + _EXAMPLES + r")?")
_FAILURE = r"(?:a\s+)?" + _NETWORK + _GAP + _ERROR


def _entity(name):
    # Source spellings are exact, with a presentation-only initial capital.
    return r"(?:" + re.escape(name) + "|" + re.escape(name[:1].upper() + name[1:]) + r")"


def _normalize(text, names, response_names):
    if not isinstance(text, str) or len(text) > 16000:
        return None
    if re.search(r"\b(?:component_name|handler_name|state_name|setter_name|BOUND[A-Z_]+)\b", text, re.I):
        return None
    text = re.sub(r"[-‐‑‒–—]", " ", text.replace("`", ""))
    text = text.replace("e.g.", "for example")
    # Bind before case folding. Case-ambiguous source definitions were already
    # rejected by the source collector; a model cannot introduce role tokens.
    for name, role in sorted(names.items(), key=lambda item: len(item[0]), reverse=True):
        text = re.sub(r"(?<![\w$])" + _entity(name) + r"(?![\w$])", role, text)
    for name in response_names:
        text = re.sub(r"(?<![\w$])" + re.escape(name) + r"\.json\(\)", "BOUNDJSON", text)
    return re.sub(r"\s+", " ", text.casefold()).strip()


def project_network_claim(text, *, component, handler, state, setter, response_names=(),
                          has_button=False, has_visible_state=False, condition=False):
    """Consume atomic relations and return roles, or None for any residual.

    A source-bound JSON call can describe successful sequencing. A JSON failure
    is a different condition and cannot be consumed as a network rejection.
    Button/indicator language needs same-state source syntax; that syntax does
    not establish that the observed user outcome occurred.
    """
    if len({name.casefold() for name in (component, handler, state, setter)}) != 4:
        return None
    names = {component: "BOUNDCOMPONENT", handler: "BOUNDHANDLER", state: "BOUNDSTATE", setter: "BOUNDSETTER"}
    text = _normalize(text, names, response_names)
    if text is None:
        return None
    if not text:
        return ()
    handler_ref = _ART + r"boundhandler(?:\(\))?(?:\s+(?:function|handler))?"
    request = _ART + _FETCH + r"(?:\s+in\s+boundhandler)?" + _LINE
    reset = r"boundsetter\(false\)" + _LINE
    raise_call = r"boundsetter\(true\)"
    prefix = r"(?:in\s+boundcomponent,?\s+)?"
    before = r"(?:\s+before\s+" + _ART + r"fetch" + _LINE + r")?"
    # These productions describe one relation each. The parser below composes
    # them without matching whole sentences or ignoring unrecognized words.
    rules = [
        ("raise", prefix + r"(?:" + handler_ref + r"\s+(?:calls|sets)\s+" + raise_call + _LINE
         + r"|line [0-9]{1,6}\s+sets\s+" + raise_call
         + r"|" + raise_call + r"\s+is\s+(?:called|set)" + _LINE + r")" + before),
        ("await", r"(?:" + handler_ref + r"\s+)?awaits\s+" + _ART + r"(?:a\s+)?fetch" + _LINE),
        ("await", request + r"\s+is\s+awaited" + _LINE),
        ("cleanup_absent", r"(?:there\s+is\s+)?" + _NO_CLEANUP + r"(?:\s+resets\s+it)?"),
        ("cleanup_absent", r"(?:has|with)\s+" + _NO_CLEANUP),
        ("success_reset", reset + r"\s+is\s+only\s+(?:reached\s+)?"
         r"(?:on\s+the\s+success\s+path|after\s+(?:a\s+)?successful\s+boundjson\s+call)"),
        ("skipped_reset", reset + r"\s+is\s+(?:never|not)\s+reached"),
        ("skipped_reset", _ART + _FAILURE + r"\s+skips\s+it(?:\s+entirely)?"),
        ("propagation", _ART + r"rejection\s+propagates(?:\s+out\s+of\s+the\s+async\s+function)?"),
        ("network_condition", request + r"\s+(?:throws(?:\s+" + _FAILURE
         + r")?|rejects(?:\s+with\s+" + _FAILURE + r")?)"
         + r"(?:\s*\(" + _QUALIFIER + r"\)|\s+rather than returning an http error response)?"),
    ]
    if has_button:
        label = r"(?:boundhandler(?:\s+embedding)?\s+)?"
        if state == "suggesting":
            label = r"(?:boundhandler\s+|ai\s+suggestion\s+)?"
        rules.extend([
            ("disabled", _ART + label + r"button\s+(?:(?:stays|remains|is)\s+)?(?:permanently\s+)?disabled" + _UNTIL),
            ("retry_blocked", r"the\s+user\s+loses\s+the\s+ability\s+to\s+(?:boundhandler|retry)"
             r"\s+without\s+a\s+(?:full\s+)?reload"),
            ("retry_blocked", r"preventing\s+the\s+user\s+from\s+retrying"),
        ])
    if has_visible_state:
        rules.append(("visible", _ART + r"(?:typing\s+indicator|loading\s+indicator|spinner)"
                      r"\s+(?:stays|remains)\s+visible" + _UNTIL))
    if condition:
        rules = [rule for rule in rules if rule[0] == "network_condition"] + [
            ("page_present", r"the\s+user\s+(?:has\s+not\s+navigated\s+away(?:\s+from\s+the\s+page)?"
             r"|remains\s+on\s+the\s+(?:chat\s+page|test\s+conversation\s+tab))"),
        ]
    compiled = [(role, re.compile(pattern + r"(?=$|[\s.,;!?])")) for role, pattern in rules]
    roles = []
    cursor = 0
    # Only connectors compose propositions. Polarity/conditions are never
    # discarded as stop words. Unknown tokens return None even after a match.
    connector = re.compile(r"(?:\s+|\s*(?:[.,;!?]|\band\b|\bbut\b|\bthen\b|\bso\b|\bleaving\b)\s*)+")
    while cursor < len(text):
        if len(roles) >= 64:
            return None
        if text.startswith(("if ", "when "), cursor):
            if condition:
                return None
            cursor += 3 if text.startswith("if ", cursor) else 5
            must_condition = True
        else:
            must_condition = False
        matches = [(match.end(), role) for role, pattern in compiled
                   if (match := pattern.match(text, cursor)) and (not must_condition or role == "network_condition")]
        if not matches:
            return None
        cursor, role = max(matches)
        roles.append(role)
        if cursor == len(text):
            break
        joined = connector.match(text, cursor)
        if not joined:
            return None
        cursor = joined.end()
    # An independent negative statement must not be treated as an effect of
    # request rejection just because a previous sentence named the network.
    if "retry_blocked" in roles and "disabled" not in roles:
        return None
    return tuple(roles)
