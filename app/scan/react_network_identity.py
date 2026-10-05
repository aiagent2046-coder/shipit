"""Source identities for compositional, bounded React cleanup claims.

The source inventory supplies the operation, bindings and byte spans. English
only selects that hypothesis; it never establishes an error, an absent guard,
or a UI consequence. Unrecognized prose stays separate instead of invoking
semantic similarity. Original premise checks are retained in every finding.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import PurePosixPath

from app.scan.react_async_context import _NETWORK_CLAIM, react_async_finding_context
from app.scan.react_network_claims import project_network_claim
from app.scan import guard_context as g

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


def title_label_disagreement(title, identity):
    """A display label can differ from the cited source handler; retain that fact."""
    text = _text(title, 2000)
    matches = list(_NETWORK_CLAIM.finditer(text or ""))
    if len(matches) != 1:
        return False
    handler = identity.get("handler", "")
    return matches[0]["handler"] not in {handler, handler[:1].upper() + handler[1:]}


def _qualified_source_reference(finding, component, handler):
    # A mislabeled title cannot pick a handler. Both actual source identifiers
    # must occur together in the prose, inside a citation selecting one scope.
    text = " ".join(str(finding.get(key) or "") for key in ("explanation", "observation"))
    return (re.search(r"(?<![\w$])" + re.escape(component) + r"(?![\w$])", text)
            and re.search(r"(?<![\w$])" + re.escape(handler) + r"(?![\w$])", text))


def _request_labels(context, binding, document_loader):
    """A display endpoint/method label must select the recorded fetch AST."""
    if document_loader is None:
        return ()
    try:
        document = document_loader(context["file"])
    except (UnicodeError, ValueError, TypeError, RecursionError, RuntimeError, OSError, zipfile.BadZipFile):
        return ()
    if not document or document[2] != context.get("source_sha256"):
        return ()
    calls = [node for node in document[1] if node.type == "call_expression"
             and [node.start_byte, node.end_byte] == binding["operation_span"]
             and g._name(node.child_by_field_name("function")) == "fetch"]
    if len(calls) != 1:
        return ()
    args = g._children(calls[0].child_by_field_name("arguments"))
    if len(args) != 2 or args[1].type != "object":
        return ()
    endpoint = g._literal(args[0])
    if not isinstance(endpoint, str) or not re.fullmatch(r"/(?:[A-Za-z0-9_]+/)*[A-Za-z][A-Za-z0-9_]*", endpoint):
        return ()
    methods = []
    for prop in g._children(args[1]):
        if prop.type != "pair":
            return ()  # A spread/computed override can replace the method.
        key = prop.child_by_field_name("key")
        if key.type not in {"property_identifier", "string"}:
            return ()
        if (g._literal(key) if key.type == "string" else g._text(key)) == "method":
            methods.append(g._literal(prop.child_by_field_name("value")))
    if len(methods) != 1 or methods[0] not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return ()
    return (endpoint.rsplit("/", 1)[1] + " " + methods[0],)


def _context(finding, facts):
    contexts = react_async_finding_context(finding, facts)
    if contexts:
        return contexts
    start, end = finding.get("line_start"), finding.get("line_end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= start + 80:
        return []
    # A small excerpt can include a comment or closing brace around a handler.
    # Any other handler interior makes scope selection ambiguous; the first or
    # last line alone can be a neighbouring declaration or closing brace.
    overlapping = [rec for rec in (facts.get("react_async") or {}).get("records", [])
                   if rec["file"] == finding.get("file") and rec["line"] < end and start < rec["line_end"]]
    if len(overlapping) == 1 and start <= overlapping[0]["line"] <= overlapping[0]["line_end"] <= end:
        return overlapping
    return []


def _ancillary_annotations(text, source_paths):
    """Keep an exact path-set claim, never silently discard extra file scope."""
    if not isinstance(text, str) or len(text) > 16000:
        return None
    pattern = re.compile(
        r"The same (?:uncaught-rejection pattern affects other loading controls in |"
        r"pattern also appears in (?P<count>[1-9][0-9]?) other supplied files: )"
        r"(?P<paths>`[^`]+`(?:, `[^`]+`)*(?:,? and `[^`]+`)?)[.;]")
    matches = list(pattern.finditer(text))
    if not matches:
        return text, ()
    if len(matches) != 1:
        return None
    match = matches[0]
    paths = re.findall(r"`([^`]+)`", match["paths"])
    if len(paths) > 16 or (match["count"] and int(match["count"]) != len(paths)):
        return None
    normalized = []
    for item in paths:
        if (len(item) > 512 or PurePosixPath(item).is_absolute() or ".." in PurePosixPath(item).parts
                or not re.fullmatch(r"[A-Za-z0-9_./\[\]-]+\.(?:tsx|jsx)", item)):
            return None
        candidates = [known for known in source_paths if known == item or known.endswith("/" + item)]
        if len(candidates) != 1:
            return None
        normalized.append(candidates[0])
    if len(set(normalized)) != len(normalized):
        return None
    return text[:match.start()] + text[match.end():], tuple(sorted(normalized))


def network_cleanup_identity(finding, source_facts, *, document_loader=None):
    """Return a scanner-bound single-mechanism identity, or stay unresolved."""
    path = finding.get("file")
    if (not isinstance(path, str) or len(path) > 512 or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts):
        return None
    title = _text(finding.get("title"), 2000)
    if title is None:
        return None
    matches = list(_NETWORK_CLAIM.finditer(title))
    contexts = _context(finding, source_facts or {})
    if len(contexts) != 1:
        return None
    context = contexts[0]
    component, handler = context["scope"].rsplit(".", 1)
    if len(matches) == 1:
        match = matches[0]
        source_label = match["handler"] in {handler, handler[:1].upper() + handler[1:]}
        prefix = title[:match.start()].strip()
        known_prefix = _prefix_matches(prefix, component)
        route_label = prefix.casefold() in {part.casefold() for part in PurePosixPath(path).parts[:-1]}
        if (title[match.end():].strip() not in {"", "."}
                or not (known_prefix or (not source_label and route_label))
                or (not source_label and not _qualified_source_reference(finding, component, handler))):
            return None
        candidates = [item for item in context.get("network_cleanup_bindings", [])
                      if item["state"] == match["state"]]
    elif not matches and re.fullmatch(
            r"(?:A rejected " + re.escape(handler) + r" request can leave the " + re.escape(handler)
            + r" control stuck|" + re.escape(handler[:1].upper() + handler[1:])
            + r" can remain stuck after a network rejection)", title):
        candidates = context.get("network_cleanup_bindings", [])
    else:
        return None
    if len(candidates) != 1:
        return None
    binding = candidates[0]
    projection = context.get("network_projection_context") or {}
    response_names = {item["binding"] for item in projection.get("response_json_calls", [])
                      if binding["operation_span"][1] < item["span"][0]
                      and item["span"][1] < binding["reset_span"][0]}
    kwargs = {"component": component, "handler": handler, "state": binding["state"],
              "setter": binding["setter"], "response_names": response_names,
              "request_labels": _request_labels(context, binding, document_loader),
              "has_button": any((item.get("state") == binding["state"] and item.get("disabled") == "state_truthy")
                                or binding["state"] in item.get("truthy_disabled_states", [])
                                for item in context.get("controls", [])),
              "has_visible_state": any(item["state"] == binding["state"]
                                       for item in projection.get("visible_states", []))}
    ancillary = []
    source_paths = {rec["file"] for rec in ((source_facts or {}).get("react_async") or {}).get("records", [])}
    for key in ("explanation", "observation"):
        value = finding.get(key)
        annotation = _ancillary_annotations("" if value is None else value, source_paths)
        if annotation is None:
            return None
        value, paths = annotation
        ancillary.extend(paths)
        if project_network_claim(value, **kwargs) is None:
            return None
    conditions = finding.get("required_conditions")
    if conditions is None:
        conditions = []
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    for condition in conditions:
        if not isinstance(condition, str) or len(condition) > 2000:
            return None
        if project_network_claim(condition, **kwargs, condition=True) is None:
            return None
    # These are model check requests, not results. Only the known stray request
    # about this same handler may coexist with the selected network narrative.
    premises = finding.get("premises")
    if premises is None:
        premises = []
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
            "handler_line_start": context["line"], "handler_line_end": context["line_end"],
            **({"ancillary_network_files": sorted(set(ancillary))} if ancillary else {}), **binding}


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
    ancillary = identity.get("ancillary_network_files", [])
    if (not isinstance(ancillary, list) or len(ancillary) > 16
            or any(not isinstance(item, str) or len(item) > 512 or PurePosixPath(item).is_absolute()
                   or ".." in PurePosixPath(item).parts for item in ancillary)
            or ancillary != sorted(set(ancillary))):
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
