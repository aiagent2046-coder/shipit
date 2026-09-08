"""Inert detector inputs generated for tests, never copied from an account.

Corpus files contain named placeholders. Repeated characters and an invented
signing seed build format examples only at test time; none grants access to
any service. The incomplete PEM is deliberately not valid key material.
"""
import base64
import hashlib
import hmac
import json


def _jwt(role: str, issuer: str, *, demo: bool = False) -> str:
    def encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    head = encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = encode(json.dumps({"iss": issuer, "role": role, "exp": 1983812996}, separators=(",", ":")).encode())
    # The demo seed is published by Supabase; the other one is invented here.
    seed = ("super-secret-jwt-token-with-at-least-32-characters-long" if demo
            else "synthetic-corpus-signing-seed-no-live-project")
    signed = f"{head}.{body}"
    signature = encode(hmac.new(seed.encode(), signed.encode(), hashlib.sha256).digest())
    return f"{signed}.{signature}"


def _dsn(host: str, password: str) -> str:
    return "postgres" + "://admin:" + password + "@" + host + ":5432/project"


SAMPLES = {
    "STRIPE": "sk_live_" + "Z" * 28,
    "STRIPE_PLACEHOLDER": "sk_live_" + "REPLACE_ME_" + "x" * 16,
    "AWS": "AKIA" + "Z" * 16,
    "GITHUB": "ghp_" + "Z" * 36,
    "ANTHROPIC": "sk-ant-api03-" + "Z" * 24,
    "TELEGRAM": str(100000001) + ":" + "Z" * 35,
    "PRIVATE_KEY": "-----BEGIN " + "RSA PRIVATE KEY-----\nINCOMPLETE-SYNTHETIC-MATERIAL\n-----END "
                   + "RSA PRIVATE KEY-----",
    "REMOTE_DSN": _dsn("db.example.com", "Z" * 24),
    "LOCAL_DSN": _dsn("localhost", "Z" * 24),
    "DEV_DSN": _dsn("db.example.com", "postgres"),
    "JWT": _jwt("user", "synthetic-corpus"),
    "ANON_JWT": _jwt("anon", "supabase"),
    "SERVICE_JWT": _jwt("service_role", "supabase"),
    "DEMO_JWT": _jwt("service_role", "supabase-demo", demo=True),
    "NONDEMO_JWT": _jwt("service_role", "supabase-demo"),
}


def expand_samples(text: str) -> str:
    for name, value in SAMPLES.items():
        text = text.replace(f"@DRYDOCK_SAMPLE:{name}@", value)
    assert "@DRYDOCK_SAMPLE:" not in text, "Unknown synthetic sample placeholder"
    return text
