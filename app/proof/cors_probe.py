"""Runtime CORS probe (P1 of PROOF_RUNTIME_CORS_PLAN).

Boots one workspace in the sandbox, sends a real cross-origin request to it,
and judges the response with app.proof.cors_oracle. One workspace in, one
ExploitAttempt out — the before/after pair is two calls, compared by the
existing app.proof.compare.build_proof_report.

DEVIATION FROM THE PLAN, ON PURPOSE. The plan sketched a single endpoint
taking both zips and returning both attempts. One workspace per call is
simpler transport (a single zip body, exactly like /deploypack/verify),
gives each boot its own timeout instead of one budget for two, and leaves the
comparison in compare.py where the static path already does it. Nothing is
lost: the caller runs it twice.

THIS RUNS ON THE RUNNER HOST, NOT IN THE API PROCESS. verify_deploy_pack
publishes the container on 127.0.0.1 of whichever host started it, so the
probe has to execute where the container is. That is why there is a
/proof/cors-probe endpoint rather than an API-side helper.

SECURITY: the probe addresses ONLY 127.0.0.1 on the port we published. It
never reads a host, URL or port out of the repository under test — a
repository that could steer this at an address of its choosing would turn the
runner into an SSRF relay against its own network. Test enforced.
"""

from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.deploypack.sandbox import verify_deploy_pack
from app.proof.cors_oracle import PROBE_ORIGIN, evaluate_cors_response
from app.proof.types import ExploitAttempt

logger = logging.getLogger(__name__)

TEMPLATE_ID = "cors_open_runtime"

# Seconds for the probe request itself. Short: the app already answered a boot
# check, so a slow reply here means something is wrong rather than warming up.
PROBE_TIMEOUT_S = 10

# The probe MUST send a credential, and the first real boot is what taught us
# that (2026-08-17, scripts/e2e_proof_cors_probe.py against a container).
#
# The claim this template makes is about CREDENTIALED cross-origin reads, and a
# request carrying no credentials cannot demonstrate one. Frameworks know that
# too, and gate their behaviour on it: Starlette 0.40 — what `fastapi==0.115.0`
# pulls — reflects the caller's Origin only `if self.allow_all_origins and
# has_cookie`, answering a bare `*` otherwise. (Starlette 1.6 keys the same
# branch off allow_credentials instead, so the two versions disagree about the
# identical application.)
#
# Without a cookie the probe therefore UNDER-REPORTS: an app that a real
# browser session could read cross-origin comes back as "not exploitable,
# the browser blocks `*` with credentials". A false negative that understates
# risk, on the one template that exists to state risk precisely. The plan
# specified this header; the implementation dropped it; nothing but a real
# container could have caught it, which is exactly what the e2e was for.
#
# Value is inert and self-identifying: it is a fabricated name that matches no
# session scheme, sent to a container in a sandbox with no egress.
PROBE_COOKIE = "drydock_proof=1"


def run_cors_probe(
    build_dir: Path,
    *,
    host_port: int,
    container_port: int,
    path: str = "/",
    build_timeout_s: int = 300,
    boot_timeout_s: int = 60,
    memory_limit: str | None = None,
    probe_origin: str = PROBE_ORIGIN,
    verify: Callable[..., Any] = verify_deploy_pack,
    fetch: Callable[..., Mapping[str, str]] | None = None,
    stop: Callable[[str | None, str | None], None] | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> ExploitAttempt:
    """Boot ``build_dir``, probe it cross-origin, tear it down.

    ``verify``/``fetch``/``stop`` are injectable so the status table below can
    be tested without docker — the same pattern sandbox.py uses for ``run``.

    ``diagnostics``, when given, is filled with the tail of a failed build's
    output. It is DELIBERATELY NOT evidence: app/proof/types.py forbids raw
    customer content there because evidence is stored in proof_json and
    rendered into a PR, and a build log can echo an ARG or a token. This
    channel goes to the caller that asked for it and no further.

    It exists because "docker build failed" is not a diagnosis. Measured
    2026-08-17: LibreChat failed in seven seconds and the run could not say
    whether that was a missing build arg, a blocked package registry or a
    full disk — three answers implying three different decisions about
    whether this feature can work at all.
    """
    started = time.monotonic()
    fetch = fetch or _default_fetch
    stop = stop or _default_stop

    try:
        result = verify(
            build_dir,
            host_port,
            container_port,
            path=path,
            build_timeout_s=build_timeout_s,
            boot_timeout_s=boot_timeout_s,
            keep_alive_on_success=True,
            memory_limit=memory_limit,
        )
    except Exception as exc:  # noqa: BLE001 — infrastructure, not a verdict
        return _error(f"sandbox raised {type(exc).__name__}", started)

    if diagnostics is not None:
        log = str(getattr(result, "build_log", "") or "")
        if log:
            diagnostics["build_log_tail"] = log[-4000:]

    if not getattr(result, "ok", False):
        # THE LOAD-BEARING BRANCH. A workspace that did not build or never
        # answered 200 tells us nothing about its CORS configuration. Reporting
        # that as `failure` would render as "проба не подтвердила" and read, to
        # anyone skimming, as "safe" — the inflation this project removed in
        # #22, where a static-only scan scored 9.9 over an unauthenticated RCE.
        # It is `error`: the check did not run.
        return _error(
            f"стенд не поднялся: {getattr(result, 'detail', 'unknown')}",
            started,
            evidence={"boot_detail": getattr(result, "detail", "")},
        )

    container = getattr(result, "container", None)
    image_tag = getattr(result, "image_tag", None)
    try:
        try:
            headers = fetch(host_port, path, probe_origin)
        except Exception as exc:  # noqa: BLE001
            return _error(
                f"запрос к поднятому приложению не выполнился: "
                f"{type(exc).__name__}",
                started,
                evidence={"boot_detail": getattr(result, "detail", "")},
            )

        verdict = evaluate_cors_response(headers, probe_origin)
        evidence: dict[str, Any] = {
            **verdict.evidence,
            "reason": verdict.reason,
            "boot_detail": getattr(result, "detail", ""),
        }
        # Response bodies are deliberately absent from evidence: a body from a
        # customer's application can contain their users' data, and this
        # record is rendered into a PR and stored in proof_json.
        return ExploitAttempt(
            template_id=TEMPLATE_ID,
            status="success" if verdict.exploitable else "failure",
            success=verdict.exploitable,
            detail=verdict.detail,
            evidence=evidence,
            duration_ms=_ms(started),
        )
    finally:
        try:
            stop(container, image_tag)
        except Exception:  # noqa: BLE001 — teardown must not mask a verdict
            logger.warning(
                "cors probe: teardown failed for %s", container, exc_info=True,
            )


def _default_fetch(
    host_port: int, path: str, probe_origin: str,
) -> Mapping[str, str]:
    """GET the booted app from a foreign origin, with a credential, and return
    its headers.

    The URL is built from the port WE published on loopback; nothing from the
    repository under test contributes to it (see the module's SECURITY note).
    The Cookie is what makes this a credentialed request — see PROBE_COOKIE
    for the measurement that forced it.

    A preflight OPTIONS is not sent: the oracle judges the actual response,
    and a server that reflects on GET is exploitable whether or not its
    preflight agrees.
    """
    import httpx

    url = f"http://127.0.0.1:{int(host_port)}{path if path.startswith('/') else '/' + path}"
    response = httpx.get(
        url,
        headers={"Origin": probe_origin, "Cookie": PROBE_COOKIE},
        timeout=PROBE_TIMEOUT_S,
        follow_redirects=False,
    )
    return dict(response.headers)


def _default_stop(container: str | None, image_tag: str | None) -> None:
    if container:
        subprocess.run(["docker", "stop", container],
                       capture_output=True, text=True, timeout=15)
    if image_tag:
        subprocess.run(["docker", "rmi", "-f", image_tag],
                       capture_output=True, text=True, timeout=15)


def _error(detail: str, started: float,
           evidence: dict[str, Any] | None = None) -> ExploitAttempt:
    return ExploitAttempt(
        template_id=TEMPLATE_ID,
        status="error",
        success=False,
        detail=detail,
        evidence=evidence or {},
        duration_ms=_ms(started),
    )


def _ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
