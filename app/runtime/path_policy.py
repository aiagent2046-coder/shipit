"""Path policy: which file names count as production surface.

The one classification both the secret scanner, the plain-language
finding text, the SCA lockfile reader and the report layer share.
Extracted from app/scan/secrets.py during the import-cycles fix phase:
it is the bottom util everyone may import, and it imports nothing.
"""
from __future__ import annotations

# throwaway (a service container's local connection string), which is a fact
# about the value and not about the path.



_DOC_SEGMENTS = frozenset((
    "blog", "docs", "doc", "content", "posts", "articles",
    "examples", "example", "fixtures", "__fixtures__", "samples",
))

_DOC_SUFFIXES = (
    ".md", ".mdx",
    ".stories.ts", ".stories.tsx", ".stories.js", ".stories.jsx", ".stories.mdx",
)

_MIGRATION_SEGMENTS = frozenset(("migrations", "migration"))

_TEST_PATH_SEGMENTS = frozenset((
    "__tests__", "__mocks__", "__snapshots__", "test", "tests",
    # spec/ is the Ruby and Jasmine convention; e2e/, cypress/ and
    # playwright/ are where browser tests live in a JS project.
    "spec", "e2e", "cypress", "playwright",
    # msw and hand-rolled fakes; __mocks__ was already here, these are the
    # same thing without the jest-specific underscores.
    "mock", "mocks", "fixtures", "__fixtures__", "smoke",
))

_TEST_SETUP_FILENAMES = frozenset(("jest.setup.ts", "jest.setup.js"))

_TEST_FILE_SUFFIXES = (
    ".test.mjs", ".spec.mjs", ".test.cjs", ".spec.cjs",
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
    # Cypress names its specs <thing>.cy.<ext> rather than .spec.<ext>.
    ".cy.ts", ".cy.tsx", ".cy.js", ".cy.jsx",
)

_ENV_TEMPLATE_MARKERS = frozenset(("example", "sample", "template", "dist"))


NON_PRODUCTION_CONTEXTS = frozenset(("test_fixture", "test_file", "comment",
                                     "doc_example", "ci_service"))


def is_non_production_path(name: str) -> bool:
    """True for test, example and documentation files.

    Public because the report groups findings by it, and findings that did not
    come from this scanner (the LLM pass) carry no `context` field to group on
    — only a path. Migration paths are excluded: a migration is applied state,
    which is as production as it gets.

    Dependency trees are NOT non-production by this predicate on purpose: a
    credential committed inside `node_modules` is still committed bytes, and
    damping it as a test fixture would understate a real leak. Scanners that read
    source for a defect instead use `is_dependency_path`, because vendored code is
    not the repository's own code.
    """
    if _is_migration_context(name):
        return False
    return _is_test_fixture_path(name) or _is_doc_context(name)


def is_env_template_name(path: str) -> bool:
    """Whether a path names a dotenv TEMPLATE rather than a real env file.

    By NAME, deliberately, and public because two callers must agree on it:
    app/scan/checks.py decides from it whether a file should be tracked at all
    (and hence whether the Fix Pack offers to delete it), and _is_doc_context
    below decides how loudly to report a value found INSIDE one.

    The two questions stay separate. A template is still read and still
    reported on if it holds something that looks like a credential -- damped
    to the same level as a README, never dropped.
    """
    base = path.rsplit("/", 1)[-1]
    if not base.startswith(".env."):
        return False
    return bool(_ENV_TEMPLATE_MARKERS & set(base.split(".")[2:]))


def _is_migration_context(name: str) -> bool:
    return any(seg.lower() in _MIGRATION_SEGMENTS for seg in name.split("/")[:-1])


def _is_test_fixture_path(name: str) -> bool:
    lower = name.lower()
    base = lower.rsplit("/", 1)[-1]
    if base in _TEST_SETUP_FILENAMES or lower.endswith(_TEST_FILE_SUFFIXES):
        return True
    # Python's own convention, independent of the directory: pytest and
    # unittest both discover test_*.py / *_test.py. A root-level
    # test_mini_app_integration.py escaped damping before -- it was not in
    # tests/ and carried no .test.ts-style suffix, so a quoted credential
    # inside it came back at full severity. Only .py files: test_utils.js
    # is a minifier convention, not a test.
    if base.endswith(".py") and (
            base.startswith("test_") or base.endswith("_test.py")):
        return True
    return any(seg in _TEST_PATH_SEGMENTS for seg in lower.split("/")[:-1])


def _is_doc_context(name: str) -> bool:
    if name.lower().endswith(_DOC_SUFFIXES):
        return True
    # `.env.example` and its family are the canonical "here is the shape, not
    # the value" file -- the one thing in a repository whose entire purpose is
    # to show which variables exist without their contents. It matched neither
    # predicate: not a doc suffix, and `apps/web/` is not a doc segment. So a
    # DSN in `apps/web/.env.example` was reported at full weight beside real
    # code (measured on dubinc/dub, audit a5fcb681).
    #
    # Damped, not dropped, exactly like `README.md`: people do paste a live key
    # into a template by mistake, and that is still reported -- capped at
    # medium and shown in the non-production section rather than silently lost.
    if is_env_template_name(name):
        return True
    return any(seg.lower() in _DOC_SEGMENTS for seg in name.split("/")[:-1])
