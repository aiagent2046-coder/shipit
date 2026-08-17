"""apply_plan_to_zip unit tests."""

from __future__ import annotations

import io
import zipfile

from app.proof import run_proof_pair
from app.proof.workspace import apply_plan_to_zip


def _zip_with(files: dict[str, str], *, wrapper: str = "repo/") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if wrapper:
            zf.writestr(wrapper, b"")
        for name, text in files.items():
            zf.writestr(f"{wrapper}{name}" if wrapper else name, text)
    return buf.getvalue()


def _read_map(zip_bytes: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("repo/"):
                name = name[len("repo/") :]
            out[name] = zf.read(info).decode()
    return out


def test_apply_replaces_and_deletes() -> None:
    original = _zip_with(
        {
            "a.py": 'SECRET = "x"\n',
            "b.py": "ok\n",
            ".env": "K=v\n",
        }
    )
    patched = apply_plan_to_zip(
        original,
        files={"a.py": 'SECRET = os.environ["K"]\n'},
        deletions=[".env"],
    )
    m = _read_map(patched)
    assert m["a.py"] == 'SECRET = os.environ["K"]\n'
    assert m["b.py"] == "ok\n"
    assert ".env" not in m


def test_apply_adds_new_file() -> None:
    original = _zip_with({"a.py": "1\n"})
    patched = apply_plan_to_zip(
        original, files={".env.example": "K=changeme\n"}
    )
    m = _read_map(patched)
    assert m[".env.example"] == "K=changeme\n"
    assert m["a.py"] == "1\n"


def test_proof_pair_over_applied_plan() -> None:
    # Stripe-shaped value assembled at runtime (no literal in source).
    fake = "sk_" + "live_" + ("B" * 24)
    original = _zip_with({"cfg.py": f'STRIPE = "{fake}"\n'})
    patched_bytes = apply_plan_to_zip(
        original,
        files={"cfg.py": 'STRIPE = os.environ["STRIPE_SECRET_KEY"]\n'},
    )
    report = run_proof_pair("secrets_leak", original, patched_bytes)
    assert report.verified is True
    assert report.informational is True
