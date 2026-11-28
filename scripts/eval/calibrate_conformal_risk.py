"""Calibrate Conformal Risk Control (CRC) thresholds over the golden corpus.

Scans every negative and positive fixture in `tests/detectors/` through the
shipped deterministic static stage, computes each unit's spurious nonconformity
score s(x), and derives finite-sample risk-controlled thresholds lambda_hat_alpha
at alpha_fix = 0.05 and alpha_review = 0.15.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.scan.reporting.conformal.nonconformity import (  # noqa: E402
    STRATUM_AST_CFG,
    STRATUM_CONFIG,
    STRATUM_SECRET,
    finding_nonconformity,
    producer_stratum,
)
from app.scan.reporting.conformal.risk_control import (  # noqa: E402
    CalibrationSample,
    calibrate_conformal_threshold,
)
from app.scan.static import run_static_scan  # noqa: E402
from tests.detector_samples import expand_samples  # noqa: E402


def _build_case_zip(case_dir: Path) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(case_dir.rglob("*")):
            if path.is_file() and path.name != "expected.json" and path.name.endswith(".fixture"):
                rel = path.relative_to(case_dir).as_posix().removesuffix(".fixture")
                zf.writestr(rel, expand_samples(path.read_text(encoding="utf-8")))
    buf.seek(0)
    return buf


def collect_corpus_samples(corpus_root: Path) -> list[CalibrationSample]:
    samples: list[CalibrationSample] = []
    for rule_dir in sorted(corpus_root.iterdir()):
        if not rule_dir.is_dir() or rule_dir.name.startswith(("_", ".")):
            continue
        rule_id = rule_dir.name
        stratum = producer_stratum(rule_id=rule_id, source="static")
        neg_dir = rule_dir / "negative"
        if not neg_dir.is_dir():
            continue
        for case_dir in sorted(neg_dir.iterdir()):
            if not case_dir.is_dir() or not (case_dir / "expected.json").is_file():
                continue
            expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
            forbid = set(expected.get("forbid") or [rule_id])
            findings = run_static_scan(_build_case_zip(case_dir))["findings"]
            spurious_scores = [
                finding_nonconformity(f)
                for f in findings
                if f.get("rule_id") in forbid
            ]
            min_s = min(spurious_scores) if spurious_scores else None
            samples.append(
                CalibrationSample(
                    sample_id=f"{rule_id}/negative/{case_dir.name}",
                    stratum=stratum,
                    min_spurious_nonconformity=min_s,
                )
            )
    return samples


def run_calibration(corpus_root: Path) -> dict:
    samples = collect_corpus_samples(corpus_root)
    report: dict = {"total_negative_units": len(samples), "strata": {}}
    for stratum in (STRATUM_AST_CFG, STRATUM_SECRET, STRATUM_CONFIG):
        sub = [s for s in samples if s.stratum == stratum]
        if not sub:
            continue
        res_fix = calibrate_conformal_threshold(sub, 0.05, stratum=stratum)
        res_rev = calibrate_conformal_threshold(sub, 0.15, stratum=stratum)
        report["strata"][stratum] = {
            "n": len(sub),
            "alpha_0.05": {
                "feasible": res_fix.feasible,
                "lambda_hat": res_fix.lambda_hat,
                "empirical_risk": res_fix.empirical_risk,
                "finite_sample_upper_bound": res_fix.finite_sample_upper_bound,
            },
            "alpha_0.15": {
                "feasible": res_rev.feasible,
                "lambda_hat": res_rev.lambda_hat,
                "empirical_risk": res_rev.empirical_risk,
                "finite_sample_upper_bound": res_rev.finite_sample_upper_bound,
            },
        }
    global_fix = calibrate_conformal_threshold(samples, 0.05, stratum="global_static")
    report["global_static_alpha_0.05"] = {
        "n": global_fix.sample_size,
        "feasible": global_fix.feasible,
        "lambda_hat": global_fix.lambda_hat,
        "empirical_risk": global_fix.empirical_risk,
        "finite_sample_upper_bound": global_fix.finite_sample_upper_bound,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=ROOT / "tests" / "detectors",
        help="Path to golden detector corpus root",
    )
    args = parser.parse_args()
    summary = run_calibration(args.corpus)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
