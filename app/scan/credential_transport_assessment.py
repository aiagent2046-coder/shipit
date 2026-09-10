"""Bounded source assessment of credential-transport-only model hypotheses.

Expected provider authentication syntax is not evidence of leaked credentials.
This check can reject that consequence only for a narrow, completely matched
hypothesis and direct server fetch. It never certifies network, proxy, logging,
module-loading or runtime safety. Unknown wrappers and compound claims abstain.
No uploaded source executes and no credential literals are retained.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import re
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g
from app.scan import imported_error_context as imported
from app.scan.consequence_evidence import _loc

KIND = "credential_transport_only"
MAX_CHECKS = 40
MAX_WORK_NODES = 400_000
MAX_CALLS = 256
MAX_NARRATIVE = 28_000
CLAIM = "The finding's leakage consequence is based only on expected provider credential transport."
LIMITS = (
    "This is a bounded source assessment of the stated hypothesis, not verified safety. "
    "Runtime transport, network interception, external middleware, logging configuration and other "
    "files are not verified. A distinct evidenced leak or compound premise requires separate review."
)
DETAIL = (
    "The cited source uses a private server environment credential in the expected authentication "
    "position of a source-bound fetch to the exact logical HTTPS provider endpoint. That source fact alone does "
    "not support a credential-leak consequence. " + LIMITS
)
_ENDPOINTS = {
    "github_oauth": "https://github.com/login/oauth/access_token",
    "anthropic_api": "https://api.anthropic.com/v1/messages",
}
_ENV_KEYS = {
    "github_oauth": {"GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_CLIENT_SECRET"},
    "anthropic_api": {"ANTHROPIC_API_KEY"},
}
_TITLES = {
    "github_oauth": re.compile(
        r"GitHub OAuth client[_ ]secret (?:exposed|sent|transmitted) in "
        r"(?:server-side fetch|(?:a )?(?:POST )?request body)",
        re.I,
    ),
    "anthropic_api": re.compile(
        r"Anthropic API key (?:transmitted|sent|exposed) in (?:fetch request headers|(?:the )?x-api-key header)"
        r"(?: \((?:auto-reply|engineer tools|essence generation|avatar suggest)\))?",
        re.I,
    ),
}


# Small source grammars for the checked one-hop proxy factory and transparent
# timeout wrapper. AST matching ignores comments and erased TS annotations;
# every runtime statement, call, object member and operator must still match.
# Capital placeholders bind identifiers consistently, never arbitrary syntax.
_PROXY_SOURCE = """import {ProxyAgent} from 'undici';
let agent;
let resolved = false;
export function _FACTORY() {
 if (!resolved) {
  const url = process.env.ANTHROPIC_PROXY_URL;
  if (url) agent = new ProxyAgent(url);
  resolved = true;
 }
 return agent;
}"""
_WRAPPER_SOURCE = """async function _WRAPPER(url, init) {
 const timeout = init.timeout ?? _DEFAULT;
 const controller = new AbortController();
 const timer = setTimeout(() => controller.abort(), timeout);
 const dispatcher = url.startsWith('https://api.anthropic.com') ? _FACTORY() : undefined;
 try {
  const res = await fetch(url, { ...init, signal: controller.signal, dispatcher });
  return res;
 } finally { clearTimeout(timer); }
}"""


def _erased(node):
    return node.type in {"comment", "type_annotation", "type_arguments", "type_parameters"} or (
        node.type == "import_specifier" and any(child.type == "type" for child in node.children)
    )


def _syntax(node):
    node = _unwrap(node)
    if _erased(node):
        return None
    children = [child for n in node.children if n.type != "," and (child := _syntax(n)) is not None]
    if node.type == "string":
        value = g._literal(node)
        return ("literal", value) if value is not None else ("unsupported_literal",)
    return (node.type, tuple(children)) if children else (node.type, g._text(node))


@lru_cache(maxsize=3)
def _template(text, function=False):
    root = Parser(Language(tree_sitter_typescript.language_typescript())).parse(text.encode()).root_node
    return _syntax(root.named_children[0] if function else root)


def _matches(value, pattern, bindings=None):
    bindings = {} if bindings is None else bindings
    if pattern[0] == "identifier" and isinstance(pattern[1], str) and pattern[1].startswith("_"):
        name = pattern[1]
        if value[0] != "identifier" or not isinstance(value[1], str):
            return False
        if name in bindings:
            return bindings[name] == value[1]
        bindings[name] = value[1]
        return True
    if len(value) != len(pattern) or value[0] != pattern[0]:
        return False
    if len(value) < 2 or not isinstance(pattern[1], tuple):
        return value == pattern
    return len(value[1]) == len(pattern[1]) and all(
        _matches(actual, expected, bindings) for actual, expected in zip(value[1], pattern[1])
    )


def _result(detail, **extra):
    return {
        "kind": KIND,
        "claim": CLAIM,
        "result": "not_checked",
        "whole_finding": False,
        "scope": "bounded_source_context",
        "method": "source_ast",
        "detail": detail + " " + LIMITS,
        **extra,
    }


def _unwrap(node):
    while node and node.type in {"parenthesized_expression", "as_expression", "non_null_expression"}:
        children = g._children(node)
        if not children:
            return None
        node = children[0]
    return node


def _key(node):
    if not node:
        return None
    if node.type in {"identifier", "property_identifier"}:
        return g._text(node)
    return g._literal(node)


def _object(node, *, shorthand=False):
    node = _unwrap(node)
    if not node or node.type != "object":
        return None
    pairs = {}
    for part in g._children(node):
        if part.type == "shorthand_property_identifier" and shorthand:
            key, value = g._text(part), part
        elif part.type == "pair":
            key, value = _key(part.child_by_field_name("key")), part.child_by_field_name("value")
        else:
            return None
        if not key or key in pairs or key in {"__proto__", "constructor", "prototype", "toJSON"}:
            return None
        pairs[key] = value
    return pairs


def _selected(finding):
    if finding.get("source") is not None and finding["source"] != "llm":
        return None
    title = finding.get("title")
    if not isinstance(title, str) or len(title) > 512:
        return None
    return next((kind for kind, pattern in _TITLES.items() if pattern.fullmatch(title.strip())), None)


def _transport_only(finding):
    """Conservative lexical boundary in addition to source credential-use binding.

    Source checks never establish a compound hypothesis false. Explicit harmful
    sinks, independent vulnerability types and concrete logging assertions keep
    the finding. Advisory conditional interception scenarios remain unverified.
    """
    evidence = finding.get("claim_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    values = [finding.get(k, evidence.get(k, "")) for k in ("explanation", "observation")]
    if any(not isinstance(value, str) for value in values):
        return False
    narrative = "\n".join(values)
    if len(narrative) > MAX_NARRATIVE:
        return False
    if re.search(
        r"\b(?:hardcod\w*|attacker\w*|exfiltrat\w*|public(?:ly)? accessible|unauthenticated|"
        r"cross-site|csrf|ssrf|sql injection|XSS|browser bundle|client bundle|localStorage|"
        r"database|persist\w*|stored|storage|additionally|also|authorization bypass|"
        r"rejectUnauthorized|setGlobalDispatcher|console\.(?:log|error|warn)|logger\.)\b",
        narrative,
        re.I,
    ):
        return False
    # Only conditional warnings can accompany the transport-only title. A
    # concrete statement about a second sink must not disappear with transport.
    for sentence in re.split(r"(?<=[.!?])\s+|\n", narrative):
        if not re.search(
            r"\b(?:log(?:ged|ging|s|ger)?|record(?:ed|ing|s)?|debug\w*|print\w*|trace\w*|"
            r"intercept\w*|proxy|proxies|browser|plaintext|plain text)\b",
            sentence,
            re.I,
        ):
            continue
        conditional = re.search(r"\b(?:if|could|may|might|should|never|not exposed|correct OAuth)\b", sentence, re.I)
        # A header's plaintext application representation is not an HTTP wire
        # claim. Explicit insecure transport remains outside this grammar.
        header_plaintext = re.search(r"plaintext (?:in (?:the )?HTTP header|headers)", sentence, re.I)
        hypothetical_risk = re.fullmatch(
            r"This is (?:a|the) (?:first|second|third|fourth|fifth|sixth|another) instance of "
            r"the same pattern and poses the same risk of (?:API key|credential) exposure "
            r"through logging or interception[.]?",
            sentence.strip(),
            re.I,
        )
        if not conditional and not header_plaintext and not hypothetical_risk:
            return False
        if re.search(r"\b(?:also|actually|currently|already)\b.*\b(?:logs?|logged|exposed|leak\w*)\b", sentence, re.I):
            return False
    return True


def _server_context(path, root):
    statements = g._children(root)
    directives = {
        g._literal(g._children(n)[0])
        for n in statements
        if n.type == "expression_statement" and len(g._children(n)) == 1
    }
    if "use client" in directives:
        return False
    if "use server" in directives:
        return True
    if any(
        n.type == "import_statement"
        and g._literal(n.child_by_field_name("source")) == "server-only"
        and not any(c.type == "import_clause" for c in n.named_children)
        for n in statements
    ):
        return True
    return bool(re.search(r"(?:^|/)app/api/(?:[^/]+/)*route\.(?:ts|js)$", path)) and any(
        n.type == "export_statement"
        and (dec := n.child_by_field_name("declaration")) is not None
        and dec.type == "function_declaration"
        and g._name(dec.child_by_field_name("name")) in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        for n in statements
    )


def _environment(node, provider):
    node = _unwrap(node)
    if not node or node.type != "member_expression":
        return False
    if g._text(node.child_by_field_name("property")) not in _ENV_KEYS[provider]:
        return False
    env = node.child_by_field_name("object")
    return bool(
        env
        and env.type == "member_expression"
        and g._text(env.child_by_field_name("property")) == "env"
        and g._name(env.child_by_field_name("object")) == "process"
        and not node.child_by_field_name("optional_chain")
        and not env.child_by_field_name("optional_chain")
    )


def _boolean_guard(node):
    current = node
    while current.parent and current.parent.type in {
        "parenthesized_expression",
        "unary_expression",
        "binary_expression",
    }:
        parent = current.parent
        if parent.type == "unary_expression" and g._text(parent.child_by_field_name("operator")) != "!":
            return False
        if parent.type == "binary_expression" and g._text(parent.child_by_field_name("operator")) not in {
            "&&",
            "||",
            "===",
            "!==",
        }:
            return False
        current = parent
    return bool(
        current.parent
        and current.parent.type == "if_statement"
        and current.parent.child_by_field_name("condition") == current
    )


class CredentialTransportVerifier:
    def __init__(self, archive):
        self.loader = imported.ImportedErrorVerifier(archive)
        self.checks = 0
        self.remaining_work = MAX_WORK_NODES
        self._files = {}
        self._results = {}
        self._transport_cache = {}
        self._proxy_cache = {}
        self._native_cache = {}

    def _file(self, path):
        if path not in self._files:
            data, root = self.loader._read(path)
            nodes = []
            for node in g._walk(root):
                self.remaining_work -= 1
                if self.remaining_work < 0:
                    raise ValueError("Source syntax work budget exhausted.")
                nodes.append(node)
            self._files[path] = data, root, nodes, imported._file_facts(root)
        return self._files[path]

    @staticmethod
    def _unshadowed(root, nodes, facts):
        _, imports, bindings, conflicting, dynamic = facts
        if dynamic or any(imports[n] or bindings[n] or n in conflicting for n in ("fetch", "process", "JSON")):
            return False
        # Exclude visible builtin replacement and aliases without resolving
        # runtime mutation; source imports and runtime interception stay unknown.
        if any(g._name(n) in {"window", "globalThis", "global", "self", "Function"} for n in nodes):
            return False
        if any(
            _key(n)
            in {
                "__proto__",
                "prototype",
                "__defineGetter__",
                "defineProperty",
                "defineProperties",
                "setPrototypeOf",
                "Reflect",
            }
            for n in nodes
            if n.type in {"identifier", "property_identifier", "string"}
        ):
            return False
        for node in nodes:
            if g._name(node) == "fetch" and not (
                node.parent
                and node.parent.type == "call_expression"
                and node.parent.child_by_field_name("function") == node
            ):
                return False
            if g._name(node) == "JSON" and not (
                node.parent
                and node.parent.type == "member_expression"
                and g._text(node.parent.child_by_field_name("property")) in {"stringify", "parse"}
                and node.parent.parent
                and node.parent.parent.type == "call_expression"
                and node.parent.parent.child_by_field_name("function") == node.parent
            ):
                return False
            if g._name(node) == "process" and not (
                node.parent
                and node.parent.type == "member_expression"
                and g._text(node.parent.child_by_field_name("property")) == "env"
                and node.parent.parent
                and node.parent.parent.type == "member_expression"
            ):
                return False
        return True

    @staticmethod
    def _request(call, provider, root=None, facts=None):
        args = g._children(call.child_by_field_name("arguments"))
        if len(args) != 2:
            return None
        destination = g._literal(args[0])
        if destination is None and root is not None:
            name = g._name(args[0])
            dec = g._consts(root).get(name)
            if (
                dec
                and dec.end_byte < call.start_byte
                and facts[2][name] == 1
                and not facts[1][name]
                and name not in facts[3]
            ):
                destination = g._literal(dec.child_by_field_name("value"))
        if destination != _ENDPOINTS[provider]:
            return None
        options = _object(args[1])
        if not options or g._literal(options.get("method")) != "POST":
            return None
        headers = _object(options.get("headers"))
        if headers is None:
            return None
        folded = {k.lower(): v for k, v in headers.items()}
        if len(folded) != len(headers):
            return None
        if provider == "anthropic_api":
            credential = folded.get("x-api-key")
            position = "provider_auth_header"
        else:
            body = _unwrap(options.get("body"))
            args_body = g._native(body, "JSON", "stringify") if body else None
            pairs = _object(args_body[0], shorthand=True) if args_body and len(args_body) == 1 else None
            if pairs is None or not {"client_id", "client_secret", "code"} <= pairs.keys():
                return None
            if g._literal(folded.get("content-type")) != "application/json":
                return None
            credential = pairs["client_secret"]
            position = "oauth_token_body"
        if credential is None:
            return None
        return credential, position, options

    @staticmethod
    def _credential_uses(nodes, facts, credential, provider, auth_values):
        """Permit only private env reads, one immutable alias, guards and auth slots."""
        aliases = {}
        envs = [n for n in nodes if _environment(n, provider) and n.type == "member_expression"]
        for env in envs:
            current = env
            while current.parent and current.parent.type in {"non_null_expression", "parenthesized_expression"}:
                current = current.parent
            if current.parent and current.parent.type == "variable_declarator":
                dec = current.parent
                name = g._name(dec.child_by_field_name("name"))
                if (
                    not name
                    or dec.child_by_field_name("value") != current
                    or not dec.parent
                    or dec.parent.type != "lexical_declaration"
                    or (dec.parent.parent and dec.parent.parent.type == "export_statement")
                    or not any(c.type == "const" for c in dec.parent.children)
                    or facts[2][name] != 1
                    or facts[1][name]
                    or name in facts[3]
                ):
                    return False
                aliases[name] = dec
            elif current not in auth_values:
                return False
        selected = _unwrap(credential)
        if not _environment(selected, provider) and g._name(selected) not in aliases:
            return False
        for node in nodes:
            name = g._text(node) if node.type == "shorthand_property_identifier" else g._name(node)
            if name not in aliases:
                continue
            dec = aliases[name]
            if node == dec.child_by_field_name("name") or node in auth_values or _boolean_guard(node):
                continue
            return False
        return True

    def _proxy_factory(self, path, root, facts, call):
        key = (path, call.start_byte) if call else (path, None)
        if key not in self._proxy_cache:
            self._proxy_cache[key] = self._proxy_factory_result(path, root, facts, call)
        return self._proxy_cache[key]

    def _proxy_factory_result(self, path, root, facts, call):
        name = g._name(call.child_by_field_name("function")) if call else ""
        if not name or g._children(call.child_by_field_name("arguments")):
            return None
        imports = [entry for entry in facts[0] if entry["name"] == name]
        if len(imports) != 1 or not imported._unambiguous(root, name, facts=facts):
            return None
        target, resolution = self.loader._resolve(path, imports[0]["specifier"])
        data, proxy_root, _, _ = self._file(target)
        bindings = {}
        if not _matches(_syntax(proxy_root), _template(_PROXY_SOURCE), bindings) or bindings.get("_FACTORY") != name:
            return None
        return {
            **self.loader._binding(target),
            "import": _loc(imports[0]["node"]),
            "resolution": resolution,
            "factory_call": _loc(call),
            "configuration_source": "private_environment",
            "factory_syntax": "undici_proxy_agent",
            "proxy_configuration": "not_checked",
            "proxy_logging": "not_checked",
            "runtime_routing": "not_checked",
            "runtime_module_identity": "not_checked",
        }

    def _transport(self, path, root, nodes, facts, call, options):
        key = (path, call.start_byte)
        if key not in self._transport_cache:
            self._transport_cache[key] = self._transport_result(path, root, nodes, facts, call, options)
        return self._transport_cache[key]

    def _transport_result(self, path, root, nodes, facts, call, options):
        name = g._name(call.child_by_field_name("function"))
        if path not in self._native_cache:
            self._native_cache[path] = self._unshadowed(root, nodes, facts)
        if not self._native_cache[path]:
            return None
        if name == "fetch":
            if not options.keys() <= {"method", "headers", "body", "signal", "dispatcher"}:
                return None
            if "dispatcher" not in options:
                return {"invocation": "direct_fetch", "runtime_routing": "not_checked"}
            proxy = self._proxy_factory(path, root, facts, options["dispatcher"])
            return {"invocation": "direct_fetch", "proxy_factory": proxy} if proxy else None
        functions = [
            node
            for node in root.named_children
            if node.type == "function_declaration" and g._name(node.child_by_field_name("name")) == name
        ]
        if (
            len(functions) != 1
            or not options.keys() <= {"method", "headers", "body", "timeout"}
            or not imported._unambiguous(root, name, declaration=True, facts=facts)
        ):
            return None
        fn = functions[0]
        bindings = {}
        candidates = [
            _WRAPPER_SOURCE,
            _WRAPPER_SOURCE.replace(
                "const res = await fetch(url, { ...init, signal: controller.signal, dispatcher });\n  return res;",
                "return await fetch(url, { ...init, signal: controller.signal, dispatcher });",
            ),
        ]
        if not any(_matches(_syntax(fn), _template(template, True), bindings) for template in candidates):
            return None
        if any(facts[1][n] or facts[2][n] or n in facts[3] for n in ("AbortController", "setTimeout", "clearTimeout")):
            return None
        factory_calls = [
            n
            for n in g._walk(fn)
            if n.type == "call_expression" and g._name(n.child_by_field_name("function")) == bindings.get("_FACTORY")
        ]
        proxy = self._proxy_factory(path, root, facts, factory_calls[0]) if len(factory_calls) == 1 else None
        if not proxy:
            return None
        return {
            "invocation": "local_timeout_wrapper",
            "wrapper": self.loader._binding(path, fn),
            "proxy_factory": proxy,
            "forwarded_destination": "unchanged_parameter",
            "forwarded_options": "spread_then_signal_and_dispatcher",
        }

    def checks_for(self, finding):
        provider = _selected(finding)
        if not provider:
            return []
        path = finding.get("file")
        start = finding.get("line_start", finding.get("line"))
        end = finding.get("line_end", start)
        whole = _transport_only(finding)
        if not imported._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return [_result("Unsupported source path or coordinates.")]
        key = (path, start, end, provider, whole)
        if key in self._results:
            return deepcopy(self._results[key])
        if self.checks >= MAX_CHECKS:
            return [_result("Per-audit credential assessment budget exhausted.")]
        self.checks += 1
        try:
            data, root, nodes, facts = self._file(path)
            if end > len(data.splitlines()) or end - start > 80:
                raise ValueError("Source coordinates exceed the bounded source anchor.")
            calls = [n for n in nodes if n.type == "call_expression"]
            if len(calls) > MAX_CALLS:
                raise ValueError("Source call budget exhausted.")
            candidates = []
            for call in calls:
                # Require a cited span covering the operation, or a line within
                # its own call span; merely sharing the same function is not enough.
                if not (g._line(call) <= end and start <= call.end_point[0] + 1):
                    continue
                request = self._request(call, provider, root, facts)
                if request:
                    candidates.append((call, request))
            if len(candidates) != 1:
                raise ValueError("No single exact provider authentication operation at the cited source anchor.")
            call, (credential, position, options) = candidates[0]
            binding = {
                "file": path,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "call": _loc(call),
                "credential_position": _loc(credential),
                "provider": provider,
                "authentication_position": position,
                "runtime_transport": "not_checked",
            }
            extra = {
                "file": path,
                "line_start": g._line(call),
                "line_end": call.end_point[0] + 1,
                "source_sha256": binding["source_sha256"],
                "source_binding": binding,
            }
            transport = self._transport(path, root, nodes, facts, call, options)
            if transport:
                binding["transport"] = transport
            if not whole:
                result = _result(
                    "The narrative includes an unsupported or compound premise requiring separate review.", **extra
                )
            elif not _server_context(path, root):
                result = _result(
                    "Server-only execution context is not established by supported source syntax.", **extra
                )
            elif not transport:
                result = _result(
                    "A wrapper, shadowed binding or visible builtin escape requires separate review.", **extra
                )
            else:
                auth_values = []
                for candidate in calls:
                    request = self._request(candidate, provider, root, facts)
                    if request and self._transport(path, root, nodes, facts, candidate, request[2]):
                        auth_values.append(request[0])
                if not self._credential_uses(nodes, facts, credential, provider, auth_values):
                    result = _result(
                        "Credential origin, aliases or additional source uses require separate review.", **extra
                    )
                else:
                    binding["transport"] = transport
                    result = _result(DETAIL, result="unsupported", whole_finding=True, **extra)
                    result["detail"] = DETAIL
        except (
            ValueError,
            TypeError,
            AttributeError,
            UnicodeError,
            OSError,
            RuntimeError,
            RecursionError,
            zipfile.BadZipFile,
        ):
            result = _result("Source binding unavailable or outside the bounded parser and archive checks.")
        self._results[key] = [deepcopy(result)]
        return [result]
