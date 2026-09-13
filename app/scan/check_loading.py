"""Optional native dependencies must disable a check, never fake its result."""
from importlib import import_module


_NATIVE_DEPENDENCIES = frozenset({
    "tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript", "pglast",
})


def is_native_import_error(exc: ImportError) -> bool:
    """Do not hide missing application modules or unrelated import bugs."""
    return (exc.name or "").split(".", 1)[0] in _NATIVE_DEPENDENCIES


def optional_native_function(module: str, name: str):
    """Keep the original callable on servers, including its inspection identity.

    A missing grammar/parser becomes an ordinary check failure at execution.
    Only dependency import failures qualify; parser initialization errors and
    application bugs still surface. No modules or native packages are stubbed.
    """
    try:
        return getattr(import_module(module), name)
    except ImportError as exc:
        if not is_native_import_error(exc):
            raise
        dependency = exc.name

    def unavailable(*args, **kwargs):
        # Normalize ModuleNotFoundError to the same stable reason as an
        # installed native package whose extension cannot be imported.
        raise ImportError("Optional native dependency unavailable", name=dependency)

    unavailable.__name__ = name
    return unavailable
