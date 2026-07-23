"""Manual smoke test: REAL docker build + docker run + curl.

Run only where Docker is actually available. Triggered on a GitHub
Actions runner (has Docker pre-installed) via
.github/workflows/smoke-deploy-pack.yml (workflow_dispatch) — not part
of the regular pytest suite, which runs in sandboxes that mostly don't
have a docker binary at all.

Zips up smoke/fastapi_sample, smoke/vite_sample and smoke/next_sample
(minimal but genuinely bootable apps — real routes, real build scripts)
and runs them through the exact same app.deploypack.pipeline.run_deploy_pack
the API uses. Exits non-zero if any fails to verify.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.deploypack.pipeline import run_deploy_pack
from app.ingest.stack_detect import detect_stack


def zip_dir(root: Path) -> bytes:
    """Zip with a single top-level folder, matching real Lovable/Bolt
    exports (and what detect_stack/extract_repo expect)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, arcname=str(path.relative_to(root.parent)))
    return buf.getvalue()


def main() -> int:
    all_ok = True
    for name in ("fastapi_sample", "vite_sample", "next_sample"):
        root = REPO_ROOT / "smoke" / name
        raw = zip_dir(root)
        stack = detect_stack(io.BytesIO(raw))
        print(f"\n=== {name} (detected stack: {stack.value}) ===", flush=True)

        result = run_deploy_pack(raw, stack)
        print(f"verified={result['verified']!r}  detail={result['detail']}")
        if result["build_log"]:
            print("--- build_log (tail, 4000 chars) ---")
            print(result["build_log"][-4000:])

        if result["verified"] is not True:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
