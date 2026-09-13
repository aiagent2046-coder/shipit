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


def is_excluded_handler_tree(name: str, *, extra_directories: tuple[str, ...] = ()) -> bool:
    """Path exclusions for the RLS and service-role collectors.

    These collectors historically compared category names without case. Keep
    that contract here, without changing other scanners' path policies.

    A conventional handler can have a URL segment named build, dist, vendor or
    coverage. Those names after its routing root do not establish a generated
    tree. The same names before that root still exclude compiled/package copies;
    unambiguous markers such as .next or node_modules exclude at any depth.
    Custom routing roots and build-directory configuration are not resolved.
    """
    parts = name.replace("\\", "/").lower().split("/")
    directories, filename = parts[:-1], parts[-1]
    route_start = len(directories)
    if filename in {"route.ts", "route.tsx", "route.js", "route.jsx", "route.mts", "route.mjs"}:
        if "app" in directories:
            route_start = directories.index("app") + 1
    elif filename in {"+server.ts", "+server.js"}:
        for index in range(len(directories) - 1):
            if directories[index:index + 2] == ["src", "routes"]:
                route_start = index + 2
                break
    # Pages Router and Nuxt handlers need no special basename.
    if filename.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs", ".py")):
        for index in range(len(directories) - 1):
            if directories[index:index + 2] in (["pages", "api"], ["server", "api"]):
                route_start = min(route_start, index + 2)
                break

    for index, segment in enumerate(directories):
        if index >= route_start and segment in {"build", "dist", "vendor", "coverage"}:
            continue
        # Reuse the shared categories; do not give the collectors another copy
        # of either list. The sentinel makes this a directory, not a filename.
        directory_path = segment + "/_"
        if (is_dependency_path(directory_path) or is_generated_path(directory_path)
                or segment in extra_directories):
            return True
    return False
