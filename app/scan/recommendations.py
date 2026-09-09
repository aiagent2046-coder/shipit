"""Deterministic advice guards; these do not verify source code or consequences.

The API check recognizes the literal identifier in recommendation text. It
does not parse arbitrary JavaScript, infer bindings, or certify apparent guards.
No target code is executed and no additional model request is made.
"""
import re

from app.scan.recommendation_contract import (
    has_recommendation_check, recommendation_record, require_prerequisites,
)
from app.scan.rls_recommendations import client_change_prerequisites, is_client_change

TIMING_SAFE_EQUAL_KIND = "node_crypto_timing_safe_equal"
TIMING_SAFE_EQUAL_REFERENCE = "https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b"
# Exact API-name mentions include calls, bracket access, named imports and
# prose. Aliases/escaped names without this identifier are outside the scope.
_TIMING_SAFE_EQUAL = re.compile(r"(?<![\w$])timingSafeEqual(?![\w$])")
TIMING_SAFE_EQUAL_SCOPE = (
    "Literal timingSafeEqual identifier in recommendation text only. API binding, "
    "control flow, input types, encoding, guards and runtime behavior are not checked. "
    "Apparently guarded examples are not verified; aliases or escaped names without "
    "the literal identifier are outside this check."
)
TIMING_SAFE_EQUAL_PREREQUISITES = (
    "Validate the expected input types and nonempty configured secret; reject missing or malformed values.",
    "Define the expected encoding and validate its format before conversion, including strict hex/base64 "
    "validation when used. Convert each value once into a Buffer representing the intended bytes.",
    "Compare the two converted buffers' byteLength values before calling the API. A mismatch must take "
    "the normal authentication/signature rejection path without calling timingSafeEqual. String lengths "
    "or typed-array element counts are not byte lengths.",
    "Call Node.js crypto.timingSafeEqual only with the validated equal-byte-length buffers. Reject a false "
    "result normally; handle malformed input without an uncaught exception or an empty-value fallback.",
    "Test missing, wrong-type, malformed-encoding, unequal-byte-length, equal-length wrong and valid inputs. "
    "Review the surrounding handler separately; this API alone does not establish timing safety.",
)
TIMING_SAFE_EQUAL_HINT = (
    "If using Node.js crypto.timingSafeEqual for this comparison, first validate the input types and "
    "require a nonempty configured secret. Define the expected encoding (for example UTF-8 text or a "
    "strictly validated hex/base64 digest); reject missing, wrong-type or malformed input through the "
    "normal authentication/signature rejection path. Convert both values to buffers once using that "
    "encoding. Compare the converted buffers' byteLength values before the call: on mismatch, reject "
    "normally without calling timingSafeEqual. Only compare equal-byte-length buffers, and treat a false "
    "result as an ordinary rejection. Do not use empty-value fallbacks or rely on an uncaught conversion "
    "or length exception. Test valid, equal-length wrong, missing, malformed and unequal-byte-length "
    "inputs, including non-ASCII text where applicable. Review surrounding control flow separately; "
    "neither exploitability nor the timing safety of the whole handler has been verified."
)


def prepare_recommendation(finding, facts):
    """Compose RLS and API prerequisites, keeping the first original canonical."""
    previous = recommendation_record(finding)
    # Match the canonical original as well as the active hint. This recovers
    # mixed advice already rewritten by the legacy RLS-only guard.
    texts = [text for text in (previous.get("original_fix_hint"), finding.fix_hint) if isinstance(text, str)]
    candidates = [{**vars(finding), "fix_hint": text} for text in texts]
    rls_raw = next((raw for raw in candidates if is_client_change(raw)), None)
    checks, contexts = [], []
    if rls_raw is not None or has_recommendation_check(finding, "rls_client_change"):
        check, contexts = client_change_prerequisites(rls_raw or vars(finding), facts)
        checks.append(check)
    mentions_api = any(_TIMING_SAFE_EQUAL.search(text) for text in texts)
    if mentions_api or has_recommendation_check(finding, TIMING_SAFE_EQUAL_KIND):
        checks.append(timing_safe_equal_prerequisites())
    if not checks:
        return finding
    # A stored marker, prior record, or arbitrary replacement_fix_hint never
    # grants permission to keep unchecked free-form advice active. Rebuild all
    # recognized templates; the evidence upsert makes repeated runs idempotent.
    hint = " ".join(check["replacement_fix_hint"] for check in checks)
    return require_prerequisites(finding, hint, checks, contexts=contexts)


def timing_safe_equal_prerequisites():
    return {
        "kind": TIMING_SAFE_EQUAL_KIND,
        "detail": "Advice mentioning timingSafeEqual is superseded by a conditional recommendation. "
                  "Required input, encoding and equal-byte-length checks have not been verified. "
                  "This does not confirm a timing vulnerability or the safety of a proposed fix.",
        "scope": TIMING_SAFE_EQUAL_SCOPE, "reference": TIMING_SAFE_EQUAL_REFERENCE,
        "prerequisites": list(TIMING_SAFE_EQUAL_PREREQUISITES),
        "replacement_fix_hint": TIMING_SAFE_EQUAL_HINT,
    }
