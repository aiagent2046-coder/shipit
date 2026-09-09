"""Source identities for a deliberately small React cleanup claim vocabulary.

The source inventory supplies the operation, bindings and byte spans. English
only selects that hypothesis; it never establishes an error, an absent guard,
or a UI consequence. Unrecognized prose stays separate instead of invoking
semantic similarity. Original premise checks are retained in every finding.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.scan.react_async_context import _NETWORK_CLAIM, react_async_finding_context

MECHANISM = "react_network_rejection_cleanup"
CLAIM_SCOPE = "single_network_rejection"

def _text(value, limit=16000):
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        return None  # Do not classify only a truncated prefix of a compound.
    return re.sub(r"[-‐‑‒–—]", " ", value.replace("`", ""))


def _prefix_matches(prefix, component):
    prefix = prefix.strip().casefold()
    if prefix in {"", "the", component.casefold()}:
        return True
    words = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", component)
    # A component description can omit a trailing Page/Tab suffix, but an
    # arbitrary prefix (especially another concern) is not accepted.
    variants = {" ".join(words).casefold()}
    if len(words) > 2 and words[-1] in {"Page", "Tab"}:
        variants.add(" ".join(words[:-1]).casefold())
    return prefix in variants


def _narrow_narrative(text, names, *, condition=False):
    if not text:
        return True
    if re.search(r"\b(?:component_name|handler_name|state_name|setter_name)\b", text, re.I):
        return False  # Only the scanner may introduce the grammar's roles.
    # Substitution is bounded by the source-derived names. The full sentence
    # grammar below, not a bag of allowed words or a compound-word blacklist,
    # distinguishes a skipped reset from another state/concurrency concern.
    for name, role in sorted(names.items(), key=lambda item: len(item[0]), reverse=True):
        spellings = {name, name[:1].upper() + name[1:]}
        pattern = "|".join(re.escape(spelling) for spelling in sorted(spellings))
        text = re.sub(r"(?<![\w$])(?:" + pattern + r")(?![\w$])", role, text)
    text = re.sub(r"\s+", " ", text.casefold().replace("e.g.", "for example")).strip()
    line = r"(?: on line [0-9]{1,6})?"
    reset = r"setter_name\(false\)" + line
    missed = reset + r" is (?:never|not) reached"
    successful = reset + r" is only (?:reached )?on the success path"
    # A label must describe the selected operation. The narrow suggestion noun
    # belongs to the selected suggesting flag; it cannot describe save/send.
    labels = r"handler_name(?: embedding)?"
    if names.get("suggesting") == "state_name":
        labels += r"|ai suggestion"
    label = r"(?:(?:" + labels + r") )?"
    until = r"(?: until (?:the page is reloaded|the user reloads the page))?"
    disabled = r"the " + label + r"button (?:stays |remains )?(?:permanently )?disabled" + until
    raised = (r"(?:(?:the )?handler_name function (?:calls|sets) setter_name\(true\)" + line
              + r"|line [0-9]{1,6} sets setter_name\(true\)"
              + r"|setter_name\(true\) is called on line [0-9]{1,6})")
    request = r"(?:the )?(?:network request|network|fetch)(?: in handler_name| on line [0-9]{1,6})?"
    rejected = (r"if " + request + r" throws(?: a network (?:error|exception|failure))?"
                + r"(?: \(for example the connection drops mid flight\))?, ")
    consequence = (r"(?:the rejection propagates(?: out of the async function)? with no catch block|"
                   + missed + r"(?:, (?:so |leaving )" + disabled + r")?)")
    if condition:
        patterns = [
            r"the fetch call throws a network(?: level)? (?:error|exception|failure)"
            r"(?: \(not an http error response(?:, but a thrown exception such as a connection reset)?\)"
            r"| rather than returning an http error response)?",
            r"the user has not navigated away(?: from the page)?",
            r"the user remains on the (?:test conversation tab|chat page)",
        ]
    else:
        patterns = [
            rejected + consequence,
            missed + r", so " + disabled,
            disabled,
            r"the user loses the ability to handler_name without a reload",
            r"a network rejection skips it entirely",
            successful,
            raised,
            raised + r" but has no try/catch",
            r"in component_name, " + raised + r" before the fetch but has no try/catch",
            raised + r", then awaits a fetch on line [0-9]{1,6} with no try/catch",
            r"the fetch on line [0-9]{1,6} is awaited with no surrounding try/catch",
            raised + r", the fetch is awaited on line [0-9]{1,6} with no surrounding try/catch, and " + successful,
        ]
    sentences = [sentence.strip() for sentence in text.split(".") if sentence.strip()]
    return bool(sentences) and all(any(re.fullmatch(pattern, sentence) for pattern in patterns)
                                   for sentence in sentences)


def network_cleanup_identity(finding, source_facts):
    """Return a scanner-bound single-mechanism identity, or stay unresolved."""
    path = finding.get("file")
    if (not isinstance(path, str) or len(path) > 512 or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts):
        return None
    title = _text(finding.get("title"), 2000)
    if title is None:
        return None
    matches = list(_NETWORK_CLAIM.finditer(title))
    contexts = react_async_finding_context(finding, source_facts or {})
    if len(matches) != 1 or len(contexts) != 1:
        return None
    match, context = matches[0], contexts[0]
    component, handler = context["scope"].rsplit(".", 1)
    if (match["handler"] not in {handler, handler[:1].upper() + handler[1:]}
            or not _prefix_matches(title[:match.start()], component)
            or title[match.end():].strip() not in {"", "."}):
        return None
    candidates = [item for item in context.get("network_cleanup_bindings", [])
                  if item["state"] == match["state"]]
    if len(candidates) != 1:
        return None
    binding = candidates[0]
    names = {component: "component_name", handler: "handler_name",
             binding["state"]: "state_name", binding["setter"]: "setter_name"}
    for key in ("explanation", "observation"):
        text = _text(finding.get(key))
        if text is None or not _narrow_narrative(text, names):
            return None
    conditions = finding.get("required_conditions") or []
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    for condition in conditions:
        text = _text(condition, 2000)
        if text is None or not _narrow_narrative(text, names, condition=True):
            return None
    # These are model check requests, not results. Only the known stray request
    # about this same handler may coexist with the selected network narrative.
    premises = finding.get("premises") or []
    if not isinstance(premises, list) or len(premises) > 1:
        return None
    for premise in premises:
        if (not isinstance(premise, dict) or premise.get("kind") != "http_status_guard_absent"
                or premise.get("target") != handler
                or type(premise.get("line_start")) is not int
                or type(premise.get("line_end")) is not int
                or not context["line"] <= premise["line_start"] <= premise["line_end"] <= context["line_end"]):
            return None
    digest = context.get("source_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    return {"version": 1, "method": "source_ast", "mechanism": MECHANISM,
            "claim_scope": CLAIM_SCOPE, "file": context["file"], "source_sha256": digest,
            "component": component, "handler": handler,
            "component_span": context["component_span"], "function_span": context["function_span"],
            "handler_line_start": context["line"], "handler_line_end": context["line_end"], **binding}


def network_premise_projection(checks, identity):
    """Comparison only: retain every original check in the stored evidence.

    A pending HTTP check request adds no disposition to a source-bound pure
    network claim. Actual results and any other scope/target still distinguish
    rows. Do not generalize this exception to other identities or check kinds.
    """
    if (not isinstance(checks, list) or not isinstance(identity, dict)
            or identity.get("mechanism") != MECHANISM or identity.get("claim_scope") != CLAIM_SCOPE
            or not isinstance(identity.get("handler"), str)
            or type(identity.get("handler_line_start")) is not int
            or type(identity.get("handler_line_end")) is not int
            or not 1 <= identity["handler_line_start"] <= identity["handler_line_end"]):
        return checks
    def irrelevant(check):
        allowed = {"kind", "result", "claim", "detail", "target", "line_start", "line_end",
                   "anchor_line_start", "anchor_line_end"}
        if (not isinstance(check, dict) or not set(check) <= allowed
                or check.get("kind") != "http_status_guard_absent"
                or check.get("result") != "not_checked" or check.get("target") != identity["handler"]):
            return False
        return all(type(check.get(a)) is int and type(check.get(b)) is int
                   and identity["handler_line_start"] <= check[a] <= check[b] <= identity["handler_line_end"]
                   for a, b in (("line_start", "line_end"), ("anchor_line_start", "anchor_line_end")))
    return [check for check in checks if not irrelevant(check)]


def valid_network_identity(identity, path):
    """Reject malformed saved identities before the comparison exception."""
    if (not isinstance(identity, dict) or identity.get("version") != 1
            or identity.get("method") != "source_ast" or identity.get("mechanism") != MECHANISM
            or identity.get("claim_scope") != CLAIM_SCOPE or identity.get("file") != path
            or not isinstance(identity.get("source_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["source_sha256"])):
        return False
    for key in ("component", "handler", "state", "setter"):
        if not isinstance(identity.get(key), str) or not re.fullmatch(r"[A-Za-z_$][\w$]{0,127}", identity[key]):
            return False
    for key in ("component_span", "function_span", "state_binding_span", "operation_span",
                "set_true_span", "reset_span"):
        span = identity.get(key)
        if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                or not 0 <= span[0] < span[1]):
            return False
    component, function = identity["component_span"], identity["function_span"]
    if not component[0] <= function[0] < function[1] <= component[1]:
        return False
    state = identity["state_binding_span"]
    if not component[0] <= state[0] < state[1] <= component[1]:
        return False
    for key in ("operation_span", "set_true_span", "reset_span"):
        span = identity[key]
        if not function[0] <= span[0] < span[1] <= function[1]:
            return False
    if not identity["set_true_span"][1] < identity["operation_span"][0] < identity["reset_span"][0]:
        return False
    keys = ("handler_line_start", "operation_line_start", "operation_line_end", "handler_line_end")
    values = [identity.get(key) for key in keys]
    return all(type(value) is int for value in values) and 1 <= values[0] <= values[1] <= values[2] <= values[3]
