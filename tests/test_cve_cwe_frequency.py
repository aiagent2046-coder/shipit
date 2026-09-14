import json
import sys
from collections import Counter

from scripts import cve_cwe_frequency


def _record(cve_id: str, cwes: list[str], registry: str | None = None) -> dict:
    cna = {
        "problemTypes": [{"descriptions": [{"cweId": cwe} for cwe in cwes]}],
    }
    if registry:
        cna["affected"] = [{
            "collectionURL": registry,
            "packageName": cve_id.lower(),
        }]
    return {"cveMetadata": {"cveId": cve_id}, "containers": {"cna": cna}}


def _write_checkout(root, ordered_records: list[dict]) -> None:
    destination = root / "cves" / "2026" / "0xxx"
    destination.mkdir(parents=True)
    for record in ordered_records:
        cve_id = record["cveMetadata"]["cveId"]
        (destination / f"{cve_id}.json").write_text(json.dumps(record), encoding="utf-8")


def _run(source, monkeypatch, capsys) -> str:
    monkeypatch.setattr(sys, "argv", ["cve_cwe_frequency.py", "--source", str(source), "--top", "3"])
    assert cve_cwe_frequency.main() == 0
    return capsys.readouterr().out


def test_frequency_report_is_stable_across_creation_order(tmp_path, monkeypatch, capsys):
    records = [
        _record("CVE-2026-0002", ["CWE-79", "CWE-22"], "https://registry.npmjs.org"),
        _record("CVE-2026-0001", ["CWE-89", "CWE-79"], "https://pypi.org"),
        _record("CVE-2026-0003", ["CWE-22", "CWE-89"]),
    ]
    first, second = tmp_path / "first", tmp_path / "second"
    _write_checkout(first, records)
    _write_checkout(second, list(reversed(records)))

    report = _run(first, monkeypatch, capsys)
    assert report == _run(second, monkeypatch, capsys)
    assert report.index("CWE-22") < report.index("CWE-79") < report.index("CWE-89")
    assert "CWE-79         2  (100%)  e.g. CVE-2026-0001, CVE-2026-0002" in report


def test_equal_frequency_rows_are_ranked_by_cwe_id():
    counts = Counter({"CWE-79": 2, "CWE-22": 2, "CWE-89": 1})
    assert cve_cwe_frequency._ranked(counts, 3) == [
        ("CWE-22", 2),
        ("CWE-79", 2),
        ("CWE-89", 1),
    ]
