"""Shared path categories; each scanner chooses which categories it reads."""

GENERATED_DIRECTORIES = (".next", "dist", "build")
_DEPENDENCY_SEGMENTS = frozenset({"node_modules", "vendor", "venv", ".venv", "site-packages",
                                 "bower_components", ".tox", ".nox"})


def is_dependency_path(name: str) -> bool:
    """True for a file inside a dependency or vendored tree."""
    return any(segment in _DEPENDENCY_SEGMENTS for segment in name.replace("\\", "/").split("/"))


def is_generated_path(name: str) -> bool:
    """Recognize build directories at any depth, without matching name substrings."""
    return any(segment in GENERATED_DIRECTORIES for segment in name.replace("\\", "/").split("/")[:-1])
