#!/usr/bin/env python3
"""Wait until all ShipIt production health probes are stable."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Probe:
    path: str
    required_values: dict[str, Any]


PROBES = (
    Probe(
        "/healthz",
        {"status": "ok"},
    ),
    Probe(
        "/readyz",
        {
            "status": "ready",
            "db": True,
        },
    ),
    Probe(
        "/health",
        {"db": True},
    ),
)


class ProbeFailure(RuntimeError):
    """A health probe failed."""


def fetch_json(
    url: str,
    *,
    timeout: float,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "shipit-health-gate/1",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            status = response.status
            body = response.read(64 * 1024)

    except urllib.error.HTTPError as error:
        body = error.read(4096)
        raise ProbeFailure(
            f"HTTP {error.code}: "
            f"{body.decode('utf-8', errors='replace')}"
        ) from error

    except OSError as error:
        raise ProbeFailure(str(error)) from error

    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise ProbeFailure(
            "response is not valid JSON"
        ) from error

    if not isinstance(value, dict):
        raise ProbeFailure(
            "JSON response is not an object"
        )

    return status, value


def check_once(
    base_url: str,
    *,
    timeout: float,
) -> None:
    for probe in PROBES:
        status, payload = fetch_json(
            base_url.rstrip("/") + probe.path,
            timeout=timeout,
        )

        if status != 200:
            raise ProbeFailure(
                f"{probe.path}: expected HTTP 200, got {status}"
            )

        for key, expected in probe.required_values.items():
            actual = payload.get(key)

            if actual != expected:
                raise ProbeFailure(
                    f"{probe.path}: expected {key}={expected!r}, "
                    f"got {actual!r}"
                )


def wait_for_health(
    base_url: str,
    *,
    attempts: int,
    interval: float,
    timeout: float,
    consecutive: int,
) -> bool:
    successes = 0
    last_error = "no probe attempts performed"

    for attempt in range(1, attempts + 1):
        try:
            check_once(
                base_url,
                timeout=timeout,
            )
        except ProbeFailure as error:
            successes = 0
            last_error = str(error)

            print(
                f"Health attempt {attempt}/{attempts}: "
                f"NOT READY — {last_error}"
            )
        else:
            successes += 1

            print(
                f"Health attempt {attempt}/{attempts}: "
                f"OK ({successes}/{consecutive} consecutive)"
            )

            if successes >= consecutive:
                print("Production health gate: PASSED")
                return True

        if attempt < attempts:
            time.sleep(interval)

    print(
        "Production health gate: FAILED — "
        + last_error
    )

    return False


def parse_args(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=45,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
    )
    parser.add_argument(
        "--consecutive",
        type=int,
        default=3,
    )

    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = parse_args(argv)

    if arguments.attempts < 1:
        raise SystemExit("--attempts must be positive")

    if arguments.consecutive < 1:
        raise SystemExit("--consecutive must be positive")

    passed = wait_for_health(
        arguments.base_url,
        attempts=arguments.attempts,
        interval=arguments.interval,
        timeout=arguments.timeout,
        consecutive=arguments.consecutive,
    )

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
