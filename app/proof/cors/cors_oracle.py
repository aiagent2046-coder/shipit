"""Decision logic for the runtime CORS probe (P0 of PROOF_RUNTIME_CORS_PLAN).

Pure function over response headers: no docker, no network, no runner. The
probe that produces those headers does not exist yet, and this module is
deliberately NOT registered in app/proof/registry.py — a template id that
appears in the registry is a capability the product claims, and there is
nothing behind this one until P1 boots a container.

What it decides: given the response to a cross-origin request made from an
origin we control, did the application grant an attacker's page access it
should not have?

THE PLAN THIS IMPLEMENTS WAS WRONG ON ONE POINT, AND THE CORRECTION IS THE
WHOLE REASON THIS IS A SEPARATE, TESTED MODULE.

PROOF_RUNTIME_CORS_PLAN.md defined the oracle as "Allow-Origin reflects our
origin OR is `*`, together with Allow-Credentials: true". The `*` half of that
is not exploitable and browsers say so: per the Fetch standard, a response
whose `Access-Control-Allow-Origin` is the literal `*` is rejected outright
when the request's credentials mode is `include`. A page on evil.example
cannot read a credentialed response from a server that answers `*`, however
loudly the configuration announces its intent. Treating that pair as a
confirmed exploit would have printed "атака сработала" over an attack the
browser blocks — the exact class of overstatement this project removed from
the static templates in the release that preceded this file.

So `*` with credentials is reported as a real misconfiguration and NOT as a
confirmed exploit. The only shape that earns `exploitable=True` is
REFLECTION: the server echoes back the arbitrary origin it was handed, and
allows credentials with it. That one is unambiguous — it means any origin at
all is trusted with authenticated responses.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# Reserved by RFC 2606: `.invalid` can never resolve and can never be a
# legitimate entry in a customer's allowlist, so a reflection of it cannot be
# mistaken for correct configuration. Any probe must send this exact value.
PROBE_ORIGIN = "https://drydock-proof.invalid"

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"


@dataclass(frozen=True)
class CorsVerdict:
    """One response, judged.

    ``exploitable`` is the only field the proof gate may key on: it means a
    page on an arbitrary origin can read authenticated responses from this
    app. ``reason`` is the machine-readable case for tests and logs;
    ``detail`` is the sentence a human reads.
    """

    exploitable: bool
    reason: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def evaluate_cors_response(
    headers: Mapping[str, str],
    probe_origin: str = PROBE_ORIGIN,
) -> CorsVerdict:
    """Judge one cross-origin response.

    ``headers`` is the response header map as received; lookup is
    case-insensitive because HTTP header names are, and frameworks disagree
    about casing (Starlette lowercases, Express title-cases).
    """
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    allow_origin = lowered.get(_ACAO)
    allow_credentials = _is_true(lowered.get(_ACAC))

    evidence: dict[str, Any] = {
        "allow_origin": allow_origin,
        "allow_credentials": lowered.get(_ACAC),
        "probe_origin": probe_origin,
    }

    if allow_origin is None:
        return CorsVerdict(
            exploitable=False,
            reason="no_cors_headers",
            detail=(
                "ответ не содержит Access-Control-Allow-Origin — "
                "кросс-доменный доступ не разрешён"
            ),
            evidence=evidence,
        )

    value = allow_origin.strip()

    # The finding. The server took an origin it had never seen, echoed it
    # back, and allowed credentials with it: any page anywhere can read this
    # app's authenticated responses.
    if _same_origin(value, probe_origin) and allow_credentials:
        return CorsVerdict(
            exploitable=True,
            reason="credentialed_reflection",
            detail=(
                "приложение отразило посторонний Origin и разрешило "
                "передачу учётных данных — страница на любом домене может "
                "читать ответы от лица залогиненного пользователя"
            ),
            evidence=evidence,
        )

    # Reflection WITHOUT credentials still means every origin is trusted, but
    # only for data the app hands out to anonymous callers. Worth reporting,
    # not worth calling a confirmed credentialed exploit.
    if _same_origin(value, probe_origin):
        return CorsVerdict(
            exploitable=False,
            reason="reflection_without_credentials",
            detail=(
                "Origin отражается, но учётные данные не разрешены — "
                "кросс-доменно читается только то, что доступно анониму"
            ),
            evidence=evidence,
        )

    if value == "*" and allow_credentials:
        # See the module docstring: the browser refuses this combination when
        # credentials are included, so it is a misconfiguration rather than a
        # working attack. Reported, never as `exploitable`.
        return CorsVerdict(
            exploitable=False,
            reason="wildcard_with_credentials_blocked_by_browser",
            detail=(
                "сервер отвечает `*` вместе с Allow-Credentials: браузер "
                "отклоняет такую пару при запросе с учётными данными, так "
                "что чтение приватных ответов не подтверждается — но "
                "конфигурация всё равно неверна"
            ),
            evidence=evidence,
        )

    if value == "*":
        return CorsVerdict(
            exploitable=False,
            reason="wildcard_without_credentials",
            detail=(
                "публичный CORS (`*` без учётных данных) — ожидаемо для "
                "открытого API, приватные ответы не раскрываются"
            ),
            evidence=evidence,
        )

    return CorsVerdict(
        exploitable=False,
        reason="allowed_other_origin",
        detail=(
            f"разрешён другой origin ({value!r}), наш пробный не отражён — "
            "конфигурация выглядит закреплённой"
        ),
        evidence=evidence,
    )


def _is_true(value: str | None) -> bool:
    """`Access-Control-Allow-Credentials` is the literal `true` per spec.

    Compared case-insensitively and trimmed because real servers emit `True`
    and pad with whitespace; anything else (absent, `false`, `1`) is not
    credentials-allowed. `1` is deliberately NOT accepted: browsers honour
    only `true`, and accepting it would report an exploit no browser performs.
    """
    return value is not None and value.strip().lower() == "true"


def _same_origin(value: str, probe_origin: str) -> bool:
    """Origin comparison, case-insensitive on scheme+host and trailing-slash
    tolerant.

    An origin has no path, but servers that build the header by string
    concatenation sometimes append one; a reflection is still a reflection.
    """
    return value.rstrip("/").lower() == probe_origin.rstrip("/").lower()
