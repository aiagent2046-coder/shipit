"""Bounded failure metadata shared by scoring and report exporters."""

import re

from app.capabilities import CHECKS_RUN


def normalize_check_failures(value: object) -> list[dict[str, str]]:
    """Keep a recorded failure visible without reflecting exception messages.

    Older or malformed records still signal incomplete execution. Only known
    check identifiers and an exception class name may enter the public report.
    """
    if value is None or value == []:
        return []
    records = value if isinstance(value, list) else [value]
    result = []
    for record in records[:128]:
        record = record if isinstance(record, dict) else {}
        check = record.get("check")
        check = check if isinstance(check, str) and check in CHECKS_RUN else "unknown_check"
        reason = record.get("reason")
        reason = (reason if isinstance(reason, str)
                  and re.fullmatch(r"check_error: [A-Za-z_][A-Za-z0-9_]{0,79}", reason)
                  else "reason_not_recorded")
        item = {"check": check, "reason": reason}
        if item not in result:
            result.append(item)
    if len(records) > 128:
        result.append({"check": "unknown_check", "reason": "additional_failures_omitted"})
    return result
