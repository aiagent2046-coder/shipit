#!/usr/bin/env python3
"""Wait until all ShipIt production health probes are stable."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Sequence


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
    """A health probe failed.

    `reachable` says which of two different things went wrong. False means the
    probe never got an answer -- DNS, connection refused, timeout -- and says
    nothing whatsoever about the application's health. True means the
    application answered and the answer was wrong: a 5xx, a body that is not
    JSON, `db: false`.

    Both are failures while a deploy waits for a release to come up, and the
    retry loop treats them identically on purpose. The distinction is for the
    line an operator reads afterwards. Collapsing them is how an external
    watchdog on this service came to send "DRYDOCK ALERT - health endpoint
    unreachable after 3 attempts: URLError: Temporary failure in name
    resolution" -- a report that production was down, from a host that could
    not resolve DNS, while production was serving fine.
    """

    def __init__(self, message: str, *, reachable: bool = True) -> None:
        super().__init__(message)
        self.reachable = reachable


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
        # Everything that never reached the application: URLError wrapping a
        # DNS failure or a refused connection, and socket.timeout. HTTPError
        # is caught above and is deliberately NOT here -- it means the
        # application answered.
        raise ProbeFailure(str(error), reachable=False) from error

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
    last_reachable = True

    for attempt in range(1, attempts + 1):
        try:
            check_once(
                base_url,
                timeout=timeout,
            )
        except ProbeFailure as error:
            successes = 0
            last_error = str(error)
            last_reachable = error.reachable

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

    # Two verdicts, because they send a reader to two different places. An
    # unreachable endpoint is a claim about the path between here and there;
    # only the other one is a claim about the application.
    if last_reachable:
        print(
            "Production health gate: FAILED — "
            f"{base_url} answered and the answer was unhealthy: {last_error}"
        )
    else:
        print(
            "Production health gate: FAILED — "
            f"could not reach {base_url} on any of {attempts} attempts: "
            f"{last_error}. This says the prober could not get there, NOT "
            "that the application is down; check DNS, the network path and "
            "the port before concluding anything about the release."
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
