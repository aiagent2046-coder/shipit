"""What a served bundle can leak, graded by whether we can PROVE it live.

`served_bundle.extract_service_role` reads one credential class. The same
extraction channel — a `VITE_`/`NEXT_PUBLIC_` var inlined into client JS — leaks
dozens more: LLM keys, Stripe secret keys, cloud keys, third-party service
tokens. This registry is the table that turns a raw token found in a bundle into
a graded finding, and, for the classes we can verify, points at the read-only
probe that turns a finding into a proof.

THREE DISCIPLINES, inherited from the rest of the proof layer, are the reason
this is a registry and not a pile of regexes:

  1. SECRET vs PUBLISHABLE is a first-class field, not an afterthought. A
     `pk_live_` Stripe key and a Supabase `anon` key are DESIGNED to ship in the
     browser; counting them as leaks is the false-alarm that burns a security
     tool's credibility. They are in the registry — tracked — but marked
     `publishable`, and `scan_text` keeps them out of the finding list. This is
     the same carve-out `_is_demo_jwt` makes for demo JWTs: knowing what is NOT
     a finding is half the oracle.

  2. THE JWT ORACLE IS PRODUCTION'S. The Supabase entries do not re-decode a
     JWT and guess the role — they delegate to `app.scan.secrets._jwt_severity`
     and `_is_demo_jwt`, so this registry and the customer-facing scanner agree
     on the word, and the demo-key carve-out lives in exactly one place. A
     second copy is the two-readers failure this codebase has already paid for.

  3. NEVER STORE THE RAW SECRET. A `Finding` carries the raw token only so a
     probe can use it in-process; `Finding.evidence()` returns a redacted mask
     and metadata, never the token. High-value keys are abused within single-
     digit minutes of exposure, so the raw value must never reach a log, a
     report, or a stored `proof_json`.

TIERS — the axis that matters, because live proof is the whole differentiator:

  A  Live-provable. A single READ-ONLY authenticated request distinguishes a
     valid, privileged key from a revoked one: it succeeds before the fix and
     401s after — a real before/after pair, the same shape as the RLS and
     service_role proofs. Only Tier A carries a probe.
  B  Finding, plus an optional probe that touches a third party's cloud/DB and
     therefore runs only under explicit consent (AWS, GCP, raw DB URIs). No
     probe stub here — the safe default is to report, not reach.
  C  Finding only. Present and extractable, but a live check is out of scope or
     unsafe (source maps, `.env`, admin endpoints). These often CONTAIN Tier A
     secrets, which then get their own probe.

SCOPE. This registry is for credentials EXTRACTED FROM A BUNDLE. Endpoint
classes that are not "a key in the JS" — RLS-open tables, public storage
buckets, IDOR — are their own probe family (see rls_probe); they are proofs too,
but they are not entries here.

NOT EXHAUSTIVE. Industry trackers fingerprint 90+ secret formats. This is the
high-value core; add patterns as classifiers, never loosen the secret/
publishable split to catch more.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Pattern

from app.scan.secrets import _is_demo_jwt, _jwt_severity

Tier = Literal["A", "B", "C"]
Kind = Literal["secret", "publishable"]
Severity = Literal["critical", "high", "medium", "low", "info"]

# Probe status. "stub" is deliberate and honest: the classifier is live, the
# liveness check is declared but not yet wired. Replacing a stub body with the
# real read-only request is how a Tier A class ships (its Part B/C).
ProbeStatus = Literal["stub", "success", "failure", "error"]


# --------------------------------------------------------------------------- #
# redaction — the raw token never leaves, only this does
# --------------------------------------------------------------------------- #

def redact(secret: str) -> str:
    """Keep the classifying prefix and the last 4 chars; mask the middle.

    The prefix (`sk_live_`, `AKIA`, `ghp_`) is what identifies the key TYPE, not
    the secret itself, so showing it costs nothing and helps a human confirm the
    class. Everything that makes the key usable is masked.
    """
    if len(secret) <= 12:
        return (secret[:2] + "•••") if secret else "•••"
    head = secret[:8]
    tail = secret[-4:]
    return f"{head}••••{tail}"


# --------------------------------------------------------------------------- #
# probe result + stubs (Tier A only)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ProbeResult:
    status: ProbeStatus
    detail: str
    # The exact read-only request the live probe makes. Declared as data so the
    # intent is reviewable now and executable later — never a write.
    plan: dict = field(default_factory=dict)


# A probe takes the raw secret (in-process only) and returns a ProbeResult.
ProbeFn = Callable[[str], ProbeResult]


def _stub(method: str, url: str, success_when: str) -> ProbeFn:
    """Build a Tier A probe stub that DECLARES its read-only check without
    running it. Every plan is a GET/read; there is no code path here that
    writes, charges, or mutates — that is a permanent property of this family,
    not a default that could be flipped."""
    assert method.upper() in ("GET", "HEAD"), "probes are read-only, forever"
    plan = {"method": method.upper(), "url": url, "success_when": success_when,
            "read_only": True}

    def probe(_secret: str) -> ProbeResult:
        # Intentionally does not execute. Wiring the live call (auth header from
        # _secret, one request, success->failure before/after) is this class's
        # Part B/C, gated on consent and owned/consented targets.
        return ProbeResult(
            status="stub",
            detail=f"declared read-only liveness check ({method.upper()} {url}); "
                   f"not yet wired to a live before/after",
            plan=plan)
    return probe


# The declared read-only liveness checks for each Tier A class. A key that
# answers these is a valid, privileged, live credential; after rotation it 401s.
_PROBE_OPENAI = _stub("GET", "https://api.openai.com/v1/models",
                      "200 with a model list => key is live and billable")
_PROBE_ANTHROPIC = _stub("GET", "https://api.anthropic.com/v1/models",
                         "200 => key is live and billable")
_PROBE_STRIPE = _stub("GET", "https://api.stripe.com/v1/balance",
                      "200 => secret key is live (READ ONLY — never create a "
                      "charge, refund, or any write)")


# --------------------------------------------------------------------------- #
# pattern matching — regex, or a delegate for the JWT classes
# --------------------------------------------------------------------------- #

Matcher = Callable[[str], bool]


@dataclass(frozen=True)
class SecretPattern:
    id: str                       # stable slug, e.g. "stripe_secret_key"
    name: str                     # human-facing name
    kind: Kind                    # secret => a finding; publishable => tracked, not a finding
    severity: Severity
    tier: Tier
    note: str
    regex: Pattern | None = None  # most classes match by prefix/shape
    matcher: Matcher | None = None  # JWT classes delegate to the production oracle
    probe: ProbeFn | None = None  # present iff tier == "A"

    def matches(self, token: str) -> bool:
        if self.matcher is not None:
            return self.matcher(token)
        return self.regex is not None and self.regex.search(token) is not None


# --- Supabase JWT delegates (no re-decoding of role, no second demo check) --- #

def _jwt_role(token: str) -> str:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("role", ""))
    except Exception:  # noqa: BLE001
        return ""


def _is_supabase_service_role(token: str) -> bool:
    # critical from the production grader AND not demo-signed — same test
    # served_bundle.extract_service_role uses, kept in one place.
    if _jwt_role(token) != "service_role" or _is_demo_jwt(token):
        return False
    sev, _c, _m = _jwt_severity(token)
    return sev == "critical"


def _is_supabase_anon(token: str) -> bool:
    return _jwt_role(token) == "anon" and not _is_demo_jwt(token)


# --------------------------------------------------------------------------- #
# THE REGISTRY
# --------------------------------------------------------------------------- #
# Order matters: more specific patterns first, because classify() returns the
# first match (sk-ant- before sk-, rk_/sk_ Stripe before the bare sk- OpenAI).

REGISTRY: tuple[SecretPattern, ...] = (

    # ---- Tier A: live-provable ------------------------------------------- #

    SecretPattern(
        id="supabase_service_role",
        name="Supabase service_role key",
        kind="secret", severity="critical", tier="A",
        matcher=_is_supabase_service_role,
        probe=None,  # its probe is run_rls_probe (endpoint family), not a key call
        note="Bypasses every RLS policy. Proof lives in rls_probe: read a row "
             "the anon key is refused. Demo-signed tokens excluded by the oracle."),

    SecretPattern(
        id="anthropic_api_key",
        name="Anthropic API key",
        kind="secret", severity="critical", tier="A",
        regex=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        probe=_PROBE_ANTHROPIC,
        note="Client-side LLM key. Abuse is billable, automatable, and invisible "
             "from the inside until the invoice arrives."),

    SecretPattern(
        id="openai_api_key",
        name="OpenAI API key",
        kind="secret", severity="critical", tier="A",
        regex=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
        probe=_PROBE_OPENAI,
        note="The single most common leak in vibe-coded apps: "
             "NEXT_PUBLIC_OPENAI_API_KEY / VITE_ ... prefixes publish it."),

    SecretPattern(
        id="stripe_secret_key",
        name="Stripe secret / restricted key",
        kind="secret", severity="critical", tier="A",
        regex=re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        probe=_PROBE_STRIPE,
        note="Read/write access to payments data. Probe is READ ONLY — never a "
             "charge or refund."),

    # ---- Tier B: finding + consented, cloud/DB-touching probe (no stub) --- #

    SecretPattern(
        id="aws_access_key_id",
        name="AWS access key id",
        kind="secret", severity="critical", tier="B",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        note="Paired with a secret access key, opens the account. Liveness = "
             "sts:GetCallerIdentity (read-only) but touches their cloud — "
             "consent-gated, no stub here."),

    SecretPattern(
        id="gcp_service_account",
        name="GCP / Firebase service-account JSON",
        kind="secret", severity="critical", tier="B",
        regex=re.compile(r'"type"\s*:\s*"service_account"'),
        note="Full project credentials. The $82k-in-48h class. Any probe reaches "
             "into their GCP project — consent only."),

    SecretPattern(
        id="google_api_key",
        name="Google API key",
        kind="secret", severity="high", tier="B",
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        note="Risk depends on the key's API restrictions, which can change "
             "without warning. Report; do not assume scope."),

    SecretPattern(
        id="postgres_uri",
        name="Postgres connection string",
        kind="secret", severity="critical", tier="B",
        regex=re.compile(r"\bpostgres(?:ql)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+/\w+"),
        note="Credentials + host in one string. Proof = connecting to their DB; "
             "heavy and consent-gated."),

    # ---- Tier B: other high-value service tokens ------------------------- #

    SecretPattern(
        id="github_pat",
        name="GitHub personal access token",
        kind="secret", severity="high", tier="B",
        regex=re.compile(r"\b(?:ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{50,})\b"),
        note="Repo access. Liveness touches the user's GitHub account — consent."),

    SecretPattern(
        id="slack_token",
        name="Slack token",
        kind="secret", severity="high", tier="B",
        regex=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        note="Workspace access depending on scope."),

    SecretPattern(
        id="sendgrid_key",
        name="SendGrid API key",
        kind="secret", severity="high", tier="B",
        regex=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        note="Send mail as the customer's domain."),

    SecretPattern(
        id="mapbox_secret",
        name="Mapbox secret token",
        kind="secret", severity="medium", tier="B",
        regex=re.compile(r"\bsk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        note="`sk.` is the secret Mapbox scope — distinct from public `pk.`."),

    # ---- publishable: TRACKED, NEVER COUNTED AS A LEAK ------------------- #
    # These are designed to ship in the browser. They are here so classify()
    # can positively identify them and scan_text can EXCLUDE them — that
    # exclusion is the anti-false-alarm discipline, not an omission.

    SecretPattern(
        id="supabase_anon_key",
        name="Supabase anon key",
        kind="publishable", severity="info", tier="C",
        matcher=_is_supabase_anon,
        note="Public by design. Only a risk when paired with weak RLS — which is "
             "the rls_probe finding, not a key leak."),

    SecretPattern(
        id="stripe_publishable_key",
        name="Stripe publishable key",
        kind="publishable", severity="info", tier="C",
        regex=re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        note="Designed for the browser. Not a leak."),

    SecretPattern(
        id="mapbox_public",
        name="Mapbox public token",
        kind="publishable", severity="info", tier="C",
        regex=re.compile(r"\bpk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        note="Public `pk.` scope. Not a leak."),
)


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    pattern_id: str
    name: str
    kind: Kind
    severity: Severity
    tier: Tier
    redacted: str
    # Raw token, IN-PROCESS ONLY, for a probe to consume. Never serialize this;
    # evidence() is what may be stored or rendered.
    secret: str = field(repr=False, default="")

    def evidence(self) -> dict:
        """What is safe to store or render — redaction and metadata, no token."""
        return {"pattern": self.pattern_id, "name": self.name,
                "kind": self.kind, "severity": self.severity,
                "tier": self.tier, "redacted": self.redacted}

    def probe(self) -> ProbeResult | None:
        """The declared read-only liveness check for Tier A classes, else None."""
        pat = _BY_ID.get(self.pattern_id)
        if pat is None or pat.probe is None:
            return None
        return pat.probe(self.secret)


_BY_ID = {p.id: p for p in REGISTRY}

# A conservative token shape to pull candidates out of minified JS before
# classifying — JWTs, prefixed keys, long base64-ish runs, and the JSON marker
# for service-account blobs.
_CANDIDATE = re.compile(
    r'"type"\s*:\s*"service_account"'
    r'|postgres(?:ql)?://[^\s"\']+'
    r'|\b[A-Za-z][A-Za-z0-9_.\-]{8,}\b'
    r'|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')


def classify(token: str) -> SecretPattern | None:
    """First registry pattern that matches, or None. Order gives specific
    patterns precedence (Anthropic before OpenAI, Stripe before OpenAI,
    secret before publishable where shapes could overlap)."""
    for pattern in REGISTRY:
        if pattern.matches(token):
            return pattern
    return None


def scan_text(text: str) -> tuple[list[Finding], list[Finding]]:
    """Classify every credential in a blob of JS.

    Returns (findings, publishable): `findings` is what a report counts —
    `kind == "secret"` only; `publishable` is the designed-to-ship keys,
    surfaced separately so a human sees they were recognised and deliberately
    NOT alarmed on. De-duplicated by (pattern_id, token).
    """
    findings: list[Finding] = []
    publishable: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for raw in _CANDIDATE.findall(text):
        pat = classify(raw)
        if pat is None:
            continue
        key = (pat.id, raw)
        if key in seen:
            continue
        seen.add(key)
        finding = Finding(
            pattern_id=pat.id, name=pat.name, kind=pat.kind,
            severity=pat.severity, tier=pat.tier,
            redacted=redact(raw), secret=raw)
        (publishable if pat.kind == "publishable" else findings).append(finding)

    return findings, publishable
