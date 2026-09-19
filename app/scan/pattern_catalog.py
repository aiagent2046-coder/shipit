"""Versioned weakness candidates bound to existing checks, not executable repairs.

Capabilities own scanner scope; rule coverage owns what a particular scan read.
This catalog adds classification, evidence requirements and review guidance. Its
test references describe registered regressions, never a customer's runtime.
Only bundled data is read, and every public result is an independent copy.
"""

from __future__ import annotations

import hashlib
import json
import re

from app.capabilities import CAPABILITIES


_CATALOG = {
    "schema_version": 1,
    "catalog_version": "2026-09-19.3",
    "cards": [
        {
            "id": "python-sql-string-assembly",
            "revision": 3,
            "title": "SQL text assembled from Python values",
            "languages": ["Python"],
            "weaknesses": [{
                "id": "CWE-89", "relationship": "candidate_class",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            }],
            "detection": {
                "check": "sql_injection",
                "rule_ids": ["sql-injection-string-built-query"],
                "evidence_kind": "static_observation",
            },
            "applicability": {
                "candidate_conditions": ["python_source", "sql_string_assembly_at_recognized_sink"],
                "required_evidence": ["sql_source_observation", "request_input_source", "local_input_flow",
                                      "caller_authorization", "route_reachability"],
                "evidence_descriptions": {
                    "sql_source_observation": "The Python SQL check observed nonliteral query assembly at a sink.",
                    "request_input_source": "Resolve a supported HTTP parameter declaration in the source.",
                    "local_input_flow": (
                        "Trace that parameter through supported local assignments to the exact SQL slot."),
                    "caller_authorization": "Establish which callers are permitted to reach the operation.",
                    "route_reachability": (
                        "Establish the deployed route and a feasible execution path to this operation."),
                    "psycopg3_cursor_provenance": (
                        "Trace a same-file import → connect() → cursor() chain; execute() alone is insufficient."),
                    "sql_value_position": "Establish that the expression supplies a SQL value, not an identifier.",
                    "intended_value_type": "Establish the intended parameter type, including NULL handling.",
                    "runtime_behavior_contract": "Establish expected results, API behavior and transaction semantics.",
                },
                "unresolved_boundaries": [
                    "The source observation does not establish attacker control or runtime exploitability.",
                    "A Python SQL candidate does not establish the narrower Psycopg 3 repair preconditions.",
                    "Static driver provenance does not verify installed modules, input control or runtime behavior.",
                    "Source evidence collection supports a bounded FastAPI/Psycopg subset; "
                    "ambiguous paths remain unknown.",
                    "Cross-file builders, dynamic drivers and authorization require separate evidence.",
                    "Missing or partial rule coverage remains incomplete even when a candidate is present.",
                ],
            },
            "recipe": {
                "id": "sql-value-parameterization-python-psycopg3",
                "revision": 1,
                "status": "manual_guidance",
                "automatic_apply": False,
                "preconditions": [
                    "psycopg3_cursor_provenance", "sql_value_position", "intended_value_type",
                    "runtime_behavior_contract",
                ],
                "steps": [
                    "After establishing the preconditions, pass values separately as the second execute() argument.",
                    "Use unquoted %s value placeholders and a sequence, including the comma in a one-value tuple.",
                    "Preserve parameters and fixed fragments; identifiers need a separate composition contract.",
                ],
                "verification_requirements": [
                    "Use an authorized synthetic Psycopg 3 database harness with the intended schema and types.",
                    "Compare ordinary values, quotes, NULL behavior, result shape and transaction behavior.",
                    "Demonstrate the defect and corrected behavior, then restore the construction as a mutation.",
                ],
            },
            "verification": {
                "positive_refs": [
                    "tests/detectors/sql-injection-string-built-query/positive/concatenated-query",
                ],
                "negative_refs": [
                    "tests/detectors/sql-injection-string-built-query/negative/parameterised-query",
                ],
                "unknown_refs": [
                    "tests/test_psycopg_provenance.py::test_ambiguous_chains_keep_the_driver_prerequisite",
                    "tests/test_sql_injection_coverage.py::test_decode_parse_and_byte_size_gaps_keep_independent_findings",
                    "tests/test_sql_coverage_contracts.py::test_sql_parse_gap_cannot_report_success_with_retained_positive",
                ],
                "mutation": {
                    "status": "static_regressions_registered",
                    "refs": ["scripts/check_security_mutations.py"],
                },
                "runtime_status": "not_run",
            },
            "sources": [
                {"title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
                {"title": "Psycopg value binding", "url": "https://www.psycopg.org/psycopg3/docs/basic/params.html"},
                {"title": "Psycopg identifier composition", "url": "https://www.psycopg.org/psycopg3/docs/api/sql.html"},
            ],
        },
        {
            "id": "python-unsafe-deserialization",
            "revision": 2,
            "title": "Python deserialization requiring trusted input",
            "languages": ["Python"],
            "weaknesses": [{
                "id": "CWE-502", "relationship": "candidate_class",
                "url": "https://cwe.mitre.org/data/definitions/502.html",
            }],
            "detection": {
                "check": "unsafe_deserialization",
                "rule_ids": ["unsafe-deserialization"],
                "evidence_kind": "static_observation",
            },
            "applicability": {
                "candidate_conditions": ["python_source", "recognized_deserialization_operation"],
                "required_evidence": ["source_pattern", "request_input_source", "local_input_flow",
                                      "input_trust_boundary", "loader_runtime_contract"],
                "evidence_descriptions": {
                    "source_pattern": "The check observed a supported import-resolved deserialization operation.",
                    "request_input_source": "Resolve a supported FastAPI Body bytes declaration in the source.",
                    "local_input_flow": "Trace that body through local assignments to the exact pickle.loads argument.",
                    "input_trust_boundary": "Establish the producer, authentication and ability to alter the bytes.",
                    "loader_runtime_contract": "Establish the loader, version, options and expected object types.",
                },
                "unresolved_boundaries": [
                    "The operation does not establish that its input is untrusted or that code execution occurred.",
                    "Marshal can return code objects without executing them; missing YAML Loader is version-dependent.",
                    "Unknown wrappers, cross-file provenance and application trust policy require separate evidence.",
                    "A bounded Body-to-pickle source trace does not establish caller authentication, "
                    "deployed reachability, byte integrity or runtime loader behavior.",
                    "A safe-format replacement requires an application schema and compatibility decisions.",
                ],
            },
            "recipe": {
                "id": None, "revision": None, "status": "not_available", "automatic_apply": False,
                "preconditions": [], "steps": [], "verification_requirements": [],
            },
            "verification": {
                "positive_refs": [
                    "tests/detectors/unsafe-deserialization/positive/pickle-loads-from-request",
                ],
                "negative_refs": [
                    "tests/detectors/unsafe-deserialization/negative/json-and-literal-eval",
                ],
                "unknown_refs": [
                    "tests/test_unsafe_deserialization.py::test_unknown_or_shadowed_objects_are_not_claimed_to_be_library_loaders",
                    "tests/test_unsafe_deserialization.py::test_deep_or_large_ast_is_outside_the_bounded_trace",
                ],
                "mutation": {
                    "status": "static_regressions_registered",
                    "refs": [
                        "tests/test_unsafe_deserialization.py::test_each_corpus_negative_goes_silent_for_its_stated_reason",
                    ],
                },
                "runtime_status": "not_run",
            },
            "sources": [
                {"title": "CWE-502", "url": "https://cwe.mitre.org/data/definitions/502.html"},
                {"title": "Python pickle trust boundary", "url": "https://docs.python.org/3/library/pickle.html"},
            ],
        },
        {
            "id": "python-outbound-request-input",
            "revision": 1,
            "title": "Python outbound address influenced by a request",
            "languages": ["Python"],
            "weaknesses": [{
                "id": "CWE-918", "relationship": "candidate_class",
                "url": "https://cwe.mitre.org/data/definitions/918.html",
            }],
            "detection": {
                "check": "outbound_url",
                "rule_ids": ["python-outbound-request-unvalidated-url"],
                "evidence_kind": "static_observation",
            },
            "applicability": {
                "candidate_conditions": ["python_source", "local_fastapi_request_to_outbound_address"],
                "required_evidence": ["source_pattern", "destination_policy", "network_runtime_contract"],
                "evidence_descriptions": {
                    "source_pattern": "The check traced caller input into a supported outbound address locally.",
                    "destination_policy": "Establish authorized schemes, hosts and destinations for this operation.",
                    "network_runtime_contract": "Establish DNS, redirects, egress enforcement and route reachability.",
                },
                "unresolved_boundaries": [
                    "The source trace does not establish that a network request ran or reached an internal service.",
                    "Recognizing a local validation call does not prove its correctness or resistance to DNS changes.",
                    "Cross-function builders and runtime network policy require separate evidence.",
                    "Destination restrictions depend on the product contract; a generic URL rewrite is not a repair.",
                ],
            },
            "recipe": {
                "id": None, "revision": None, "status": "not_available", "automatic_apply": False,
                "preconditions": [], "steps": [], "verification_requirements": [],
            },
            "verification": {
                "positive_refs": [
                    "tests/detectors/python-outbound-request-unvalidated-url/positive/fstring-host-from-path-param",
                ],
                "negative_refs": [
                    "tests/detectors/python-outbound-request-unvalidated-url/negative/literal-url",
                ],
                "unknown_refs": [
                    "tests/detectors/python-outbound-request-unvalidated-url/negative/helper-builds-the-url",
                    "tests/test_outbound_url.py::test_deep_ast_is_skipped_without_recursing_into_the_rule",
                ],
                "mutation": {
                    "status": "static_regressions_registered",
                    "refs": ["tests/test_outbound_url.py::test_each_corpus_negative_goes_silent_for_its_stated_reason"],
                },
                "runtime_status": "not_run",
            },
            "sources": [
                {"title": "CWE-918", "url": "https://cwe.mitre.org/data/definitions/918.html"},
                {"title": "OWASP SSRF prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
            ],
        },
    ],
}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid bundled pattern catalog")


def _strings(value: object, *, empty: bool = False, slugs: bool = False) -> bool:
    return (isinstance(value, list) and (empty or bool(value))
            and all(isinstance(item, str) and bool(item.strip())
                    and (not slugs or re.fullmatch(r"[a-z][a-z0-9_]*", item)) for item in value)
            and len(value) == len(set(value)))


def validate_catalog(value: object) -> None:
    """Reject broken check links and claims this static pilot cannot support."""
    _require(isinstance(value, dict) and set(value) == {"schema_version", "catalog_version", "cards"})
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    _require(isinstance(value["catalog_version"], str) and bool(value["catalog_version"].strip()))
    _require(isinstance(value["cards"], list) and bool(value["cards"]))
    registry = {capability.check: capability for capability in CAPABILITIES}
    ids: set[str] = set()
    bindings: set[tuple[str, str]] = set()
    for card in value["cards"]:
        _require(isinstance(card, dict) and set(card) == {
            "id", "revision", "title", "languages", "weaknesses", "detection", "applicability",
            "recipe", "verification", "sources",
        })
        card_id = card["id"]
        _require(isinstance(card_id, str) and bool(re.fullmatch(r"[a-z][a-z0-9-]*", card_id)) and card_id not in ids)
        ids.add(card_id)
        _require(type(card["revision"]) is int and card["revision"] > 0)
        _require(isinstance(card["title"], str) and bool(card["title"].strip()))
        _require(card["languages"] == ["Python"])
        detection = card["detection"]
        _require(isinstance(detection, dict) and set(detection) == {"check", "rule_ids", "evidence_kind"})
        check = detection["check"]
        _require(isinstance(check, str) and check in registry)
        _require(_strings(detection["rule_ids"]) and detection["evidence_kind"] == "static_observation")
        for rule_id in detection["rule_ids"]:
            _require(rule_id in registry[check].rule_ids and (check, rule_id) not in bindings)
            bindings.add((check, rule_id))
        _require(isinstance(card["weaknesses"], list) and bool(card["weaknesses"]))
        for weakness in card["weaknesses"]:
            _require(isinstance(weakness, dict) and set(weakness) == {"id", "relationship", "url"})
            _require(isinstance(weakness["id"], str) and bool(re.fullmatch(r"CWE-[1-9][0-9]*", weakness["id"])))
            _require(weakness["relationship"] == "candidate_class"
                     and weakness["url"] == f'https://cwe.mitre.org/data/definitions/{weakness["id"][4:]}.html')
        applicability = card["applicability"]
        _require(isinstance(applicability, dict) and set(applicability) == {
            "candidate_conditions", "required_evidence", "evidence_descriptions", "unresolved_boundaries",
        })
        _require(_strings(applicability["candidate_conditions"], slugs=True)
                 and _strings(applicability["required_evidence"], slugs=True)
                 and _strings(applicability["unresolved_boundaries"]))
        recipe = card["recipe"]
        _require(isinstance(recipe, dict) and set(recipe) == {
            "id", "revision", "status", "automatic_apply", "preconditions", "steps", "verification_requirements",
        })
        _require(recipe["automatic_apply"] is False)
        _require(_strings(recipe["preconditions"], empty=True, slugs=True)
                 and _strings(recipe["steps"], empty=True)
                 and _strings(recipe["verification_requirements"], empty=True))
        if recipe["status"] == "not_available":
            _require(recipe["id"] is None and recipe["revision"] is None
                     and not recipe["preconditions"] and not recipe["steps"]
                     and not recipe["verification_requirements"])
        else:
            _require(recipe["status"] == "manual_guidance" and check == "sql_injection"
                     and recipe["id"] == "sql-value-parameterization-python-psycopg3"
                     and type(recipe["revision"]) is int and recipe["revision"] > 0
                     and bool(recipe["steps"]) and bool(recipe["verification_requirements"]))
            _require({"psycopg3_cursor_provenance", "sql_value_position", "intended_value_type",
                      "runtime_behavior_contract"}.issubset(recipe["preconditions"]))
        descriptions = applicability["evidence_descriptions"]
        _require(isinstance(descriptions, dict)
                 and set(descriptions) == set(applicability["required_evidence"] + recipe["preconditions"])
                 and all(isinstance(text, str) and text.strip() for text in descriptions.values()))
        verification = card["verification"]
        _require(isinstance(verification, dict) and set(verification) == {
            "positive_refs", "negative_refs", "unknown_refs", "mutation", "runtime_status",
        })
        _require(verification["runtime_status"] == "not_run")
        for name in ("positive_refs", "negative_refs", "unknown_refs"):
            _require(_strings(verification[name]))
        mutation = verification["mutation"]
        _require(isinstance(mutation, dict) and set(mutation) == {"status", "refs"}
                 and mutation["status"] == "static_regressions_registered" and _strings(mutation["refs"]))
        _require(isinstance(card["sources"], list) and bool(card["sources"]))
        for source in card["sources"]:
            _require(isinstance(source, dict) and set(source) == {"title", "url"}
                     and isinstance(source["title"], str) and bool(source["title"].strip())
                     and isinstance(source["url"], str) and source["url"].startswith("https://"))


def catalog_manifest() -> dict:
    """Return the validated catalog and a digest of its canonical UTF-8 JSON."""
    validate_catalog(_CATALOG)
    content = json.dumps(_CATALOG, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {**json.loads(content), "catalog_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}


def cards() -> tuple[dict, ...]:
    return tuple(catalog_manifest()["cards"])


def get_card(card_id: str) -> dict:
    for card in cards():
        if card["id"] == card_id:
            return card
    raise KeyError(card_id)


def cards_for(check: str, rule_id: str) -> tuple[dict, ...]:
    """Bind both keys: Python and JavaScript SQL share a finding rule ID."""
    return tuple(card for card in cards()
                 if card["detection"]["check"] == check and rule_id in card["detection"]["rule_ids"])
