import io
import zipfile
from dataclasses import FrozenInstanceError

import pytest

from app.fixpack.verification import (
    VerificationReport,
    VerificationStage,
    detect_verification_profile,
)


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, text in entries.items():
            archive.writestr(
                f"customer-repo-deadbeef/{name}",
                text,
            )

    return buffer.getvalue()


def test_detects_nextjs_typecheck_build_and_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "next build",
                    "test": "jest"
                  },
                  "dependencies": {
                    "next": "15.0.0"
                  },
                  "devDependencies": {
                    "typescript": "5.7.0"
                  }
                }
                """,
                "package-lock.json": "{}",
                "tsconfig.json": "{}",
                "app/page.tsx": "export default function Page() { return null }",
            }
        )
    )

    assert profile is not None
    assert profile.ecosystem == "node"
    assert profile.framework == "nextjs"
    assert profile.install_command.startswith("npm ci")

    assert [step.name for step in profile.steps] == [
        "typecheck",
        "build",
        "tests",
    ]

    assert profile.steps[0].command == "npx --no-install tsc --noEmit"
    assert profile.steps[0].required is True
    assert profile.steps[1].command == "npm run build"
    assert profile.steps[1].required is True
    assert profile.steps[2].required is False


def test_prefers_explicit_node_typecheck_script():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "typecheck": "tsc --noEmit",
                    "build": "next build"
                  },
                  "dependencies": {
                    "next": "15.0.0"
                  }
                }
                """,
                "tsconfig.json": "{}",
            }
        )
    )

    assert profile is not None
    assert profile.steps[0].command == "npm run typecheck"


def test_detects_vite_build_without_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """,
                "src/main.jsx": "console.log('ok')",
            }
        )
    )

    assert profile is not None
    assert profile.framework == "vite"
    assert [step.name for step in profile.steps] == ["build"]
    assert profile.steps[0].required is True


def test_node_default_test_stub_is_not_added():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build",
                    "test": "echo \\"Error: no test specified\\" && exit 1"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """
            }
        )
    )

    assert profile is not None
    assert [step.name for step in profile.steps] == ["build"]


def test_detects_fastapi_compile_import_and_tests():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "fastapi==0.116.0\nuvicorn==0.35.0\n",
                "app/main.py": """
from fastapi import FastAPI

app: FastAPI = FastAPI()
                """,
                "tests/test_health.py": """
def test_health():
    assert True
                """,
            }
        )
    )

    assert profile is not None
    assert profile.ecosystem == "python"
    assert profile.framework == "fastapi"

    assert [step.name for step in profile.steps] == [
        "compile",
        "import",
        "tests",
    ]

    assert "compileall" in profile.steps[0].command
    assert "from app.main import app" in profile.steps[1].command
    assert "pytest" in profile.steps[2].command

    assert profile.steps[0].required is True
    assert profile.steps[1].required is True
    assert profile.steps[2].required is False


def test_fastapi_without_detectable_app_still_gets_compile_profile():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "fastapi\n",
                "service/factory.py": """
from fastapi import FastAPI

def create_app():
    return FastAPI()
                """,
            }
        )
    )

    assert profile is not None
    assert profile.framework == "fastapi"
    assert [step.name for step in profile.steps] == ["compile"]


def test_plain_node_project_is_not_claimed_as_supported():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "test": "node --test"
                  }
                }
                """
            }
        )
    )

    assert profile is None


def test_plain_python_project_is_not_claimed_as_fastapi():
    profile = detect_verification_profile(
        make_zip(
            {
                "requirements.txt": "flask\n",
                "app.py": "print('hello')\n",
            }
        )
    )

    assert profile is None


def test_report_contract_is_immutable():
    profile = detect_verification_profile(
        make_zip(
            {
                "package.json": """
                {
                  "scripts": {
                    "build": "vite build"
                  },
                  "devDependencies": {
                    "vite": "6.0.0"
                  }
                }
                """
            }
        )
    )

    assert profile is not None

    stage = VerificationStage(
        name="build",
        status="passed",
        command="npm run build",
        exit_code=0,
        duration_ms=125,
    )

    report = VerificationReport(
        profile=profile,
        original=(stage,),
        patched=(stage,),
        regression=False,
        deliverable=True,
        detail="no build regression",
    )

    assert report.deliverable is True

    with pytest.raises(FrozenInstanceError):
        report.deliverable = False
