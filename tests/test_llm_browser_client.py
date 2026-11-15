"""Unit and corpus-mutation tests for app/scan/llm_browser_client.py."""

import io
from pathlib import Path
import zipfile

import pytest

from app.scan.llm_browser_client import RULE_ID, scan_llm_browser_client
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"

POSITIVE_TS = """import OpenAI from "openai";

export const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY,
  dangerouslyAllowBrowser: true,
});
"""

MUTATIONS: dict[str, tuple[str, str, str]] = {
    "browser-false": (
        "web/src/lib/openai_safe.ts",
        "dangerouslyAllowBrowser: false",
        "dangerouslyAllowBrowser: true",
    ),
    "omitted-option": (
        "web/src/lib/server_client.ts",
        "timeout: 5000",
        "dangerouslyAllowBrowser: true",
    ),
    "non-sdk-constructor": (
        "web/src/lib/custom_client.ts",
        "class LocalClient {\n  constructor(options: Record<string, unknown>) {\n    void options;\n  }\n}",
        'import { OpenAI as LocalClient } from "openai";',
    ),
    "shadowed-sdk-class": (
        "web/src/lib/shadowed.ts",
        "  class OpenAI {\n    constructor(options: Record<string, unknown>) {\n      void options;\n    }\n  }",
        "  const unused = 1;\n  void unused;",
    ),
    "spread-override-after": (
        "web/src/lib/spread_override.ts",
        "  ...runtimeOverrides,\n",
        "",
    ),
    "commented-out-client": (
        "web/src/lib/commented.ts",
        "// const client = new OpenAI({ dangerouslyAllowBrowser: true });",
        "export const client = new OpenAI({ dangerouslyAllowBrowser: true });",
    ),
}


def archive(files: dict[str, str] | str, path: str = "web/src/lib/ai.ts") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_browser_exposed_llm_client_is_a_high_severity_finding():
    findings = [f for f in run_static_scan(archive(POSITIVE_TS))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert f["line"] == 5
    assert f["severity"] == "high"
    assert f["confidence"] == 0.9
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "passes dangerouslyAllowBrowser=true to new OpenAI(...)" in f["explanation"]


@pytest.mark.parametrize(
    "source",
    [
        'import { Anthropic } from "@anthropic-ai/sdk";\nnew Anthropic({ dangerouslyAllowBrowser: true });\n',
        'import * as ai from "openai";\nnew ai.AzureOpenAI({ dangerouslyAllowBrowser: true });\n',
        'const { Groq } = require("groq-sdk");\nnew Groq({ dangerouslyAllowBrowser: true });\n',
        'import { Mistral as M } from "@mistralai/mistralai";\nconst flag = true;\n'
        "new M({ dangerouslyAllowBrowser: flag });\n",
        'import OpenAI from "openai";\nconst dangerouslyAllowBrowser = true;\n'
        "new OpenAI({ dangerouslyAllowBrowser });\n",
    ],
)
def test_supported_sdk_imports_requires_and_boolean_bindings_fire(source):
    findings = scan_llm_browser_client(archive(source))
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID


@pytest.mark.parametrize(
    "source",
    [
        POSITIVE_TS.replace("dangerouslyAllowBrowser: true", "dangerouslyAllowBrowser: false"),
        POSITIVE_TS.replace("dangerouslyAllowBrowser: true", 'dangerouslyAllowBrowser: "true" as any'),
        POSITIVE_TS.replace("dangerouslyAllowBrowser: true", "dangerouslyAllowBrowser: 1 as any"),
        'import type OpenAI from "openai";\n',
        'import { type OpenAI } from "openai";\n',
        'import OpenAI from "openai";\nlet opts = { dangerouslyAllowBrowser: true };\n'
        "opts = { dangerouslyAllowBrowser: false };\nnew OpenAI(opts);\n",
        "not valid typescript [;",
    ],
)
def test_safe_non_boolean_type_only_and_reassigned_shapes_stay_silent(source):
    assert scan_llm_browser_client(archive(source)) == []


def test_every_corpus_negative_has_a_mutation():
    on_disk = {p.name for p in CORPUS_NEGATIVES.iterdir() if p.is_dir()}
    assert set(MUTATIONS) == on_disk


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    case_dir = CORPUS_NEGATIVES / case
    files = {
        p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
        for p in case_dir.rglob("*.fixture")
    }
    assert scan_llm_browser_client(archive(files)) == [], "the untouched case must be silent"
    rel, old, new = MUTATIONS[case]
    assert old in files[rel], f"{case}: mutation anchor {old!r} not in {rel}"
    files[rel] = files[rel].replace(old, new, 1)
    assert scan_llm_browser_client(archive(files)), "the mutation must make the rule fire"
