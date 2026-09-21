"""Bounded, offline inventory of Bun text lockfile v1 registry resolutions.

Bun's package keys describe a hoisted tree; the first tuple element is the
actual package identity (also for aliases). Never infer a pin from a range or
run Bun. All locked platform/dev variants are included, with scope unknown.
"""
from __future__ import annotations

from app.sca.lockfiles import Dependency, MAX_LOCKFILE_BYTES, _load_json, _NPM_NAME, _NPM_VERSION

MAX_JSON_DEPTH = 64
MAX_JSON_TOKENS = 100_000
MAX_REFERENCE_CHECKS = 100_000


class _ParserLimit(ValueError):
    pass


def _jsonc(text: str):
    """Remove JSONC comments/trailing commas outside strings, preserving lines.

    Bound lexical work before JSON construction. The strict shared decoder
    rejects duplicate keys and non-finite constants after normalization.
    """
    if len(text.encode("utf-8")) > MAX_LOCKFILE_BYTES:
        raise _ParserLimit
    chars = list(text)
    i = depth = tokens = 0
    previous = before_previous = None
    while i < len(chars):
        char = chars[i]
        if char in " \t\r\n":
            i += 1
            continue
        if char == '/' and text[i:i + 2] in {'//', '/*'}:
            end = (text.find('\n', i + 2) if text[i + 1] == '/'
                   else text.find('*/', i + 2))
            if end < 0:
                if text[i + 1] == '*':
                    raise ValueError("Unterminated JSONC comment")
                end = len(text)
            elif text[i + 1] == '*':
                end += 2
            for j in range(i, end):
                if chars[j] not in '\r\n':
                    chars[j] = ' '
            i = end
            continue
        tokens += 1
        if tokens > MAX_JSON_TOKENS:
            raise _ParserLimit
        start = i
        if char == '"':
            i += 1
            while i < len(chars):
                if chars[i] == '\\':
                    i += 2
                elif chars[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("Unterminated JSON string")
        else:
            if char in '{[':
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise _ParserLimit
            elif char in '}]':
                depth -= 1
                if (previous is not None and chars[previous] == ','
                        and before_previous is not None
                        and chars[before_previous] not in '{[,'):
                    chars[previous] = ' '
            i += 1
        before_previous, previous = previous, start
    return _load_json(''.join(chars))


def _segments(key: str) -> tuple[str, ...] | None:
    """Split hoisted paths without mistaking a scope slash for a parent."""
    if len(key) > 4096:
        raise _ParserLimit
    parts = key.split('/')
    result = []
    i = 0
    while i < len(parts):
        name = parts[i]
        if name.startswith('@') and i + 1 < len(parts):
            i += 1
            name += '/' + parts[i]
        if name in {'.', '..'} or not _npm_name(name):
            return None
        result.append(name)
        i += 1
        if len(result) > MAX_JSON_DEPTH:
            raise _ParserLimit
    return tuple(result)


def _npm_name(name: object) -> bool:
    # Bound the strings copied by each reference lookup as well as its count.
    return isinstance(name, str) and len(name) <= 214 and bool(_NPM_NAME.fullmatch(name))


def _workspace_path(path: str) -> bool:
    """Accept only canonical, archive-relative workspace directories."""
    return (bool(path) and '\\' not in path and '\x00' not in path
            and not (len(path) >= 2 and path[0].isalpha() and path[1] == ':')
            and all(part not in {'', '.', '..'} for part in path.split('/')))


def bun_packages(manifest: str, text: str, out: list[Dependency], *,
                 workspace_paths: dict[str, str] | None = None) -> str | None:
    """Collect public pins and optionally export fully validated workspace paths.

    The caller may use the exported directory/name pairs to verify companion
    manifests. A partial lockfile never contributes that coverage evidence.
    """
    try:
        data = _jsonc(text)
    except (_ParserLimit, RecursionError):
        return "parser_limit"
    except (ValueError, UnicodeError):
        return "malformed"
    if not isinstance(data, dict):
        return "malformed"
    if type(data.get('lockfileVersion')) is not int or data['lockfileVersion'] != 1:
        return "unsupported"
    packages, workspaces = data.get('packages'), data.get('workspaces')
    if (not isinstance(packages, dict) or not isinstance(workspaces, dict)
            or not isinstance(workspaces.get(''), dict)):
        return "malformed"
    reason = None
    resolved = {}
    metadata = {}
    paths = {}

    def unresolved():
        nonlocal reason
        if reason != "parser_limit":
            reason = "unresolved"

    # Bun v1 registers workspace names before reading packages. The matching
    # workspace tuple may be absent, so it is not the source of this binding.
    workspace_names = {}
    ambiguous_names = set()
    for path, workspace in workspaces.items():
        if not path:
            continue
        if (not isinstance(workspace, dict) or not _workspace_path(path)
                or not _npm_name(workspace.get('name'))
                or workspace['name'] in {'.', '..'}):
            unresolved()
            continue
        name = workspace['name']
        if name in workspace_names:
            ambiguous_names.add(name)
            unresolved()
        else:
            workspace_names[name] = path
    declared_workspace_names = set(workspace_names)
    for name in ambiguous_names:
        del workspace_names[name]
    validated_workspace_paths = {path: name for name, path in workspace_names.items()}
    workspace_links = set(workspace_names)

    for key, row in packages.items():
        try:
            segments = _segments(key)
        except _ParserLimit:
            # A pathological path must not discard independent public pins
            # later in the same lockfile. Keep the coverage gap sticky.
            reason = "parser_limit"
            continue
        if not segments or not isinstance(row, list) or not row or not isinstance(row[0], str):
            unresolved()
            workspace_links.discard(key)
            continue
        paths[key] = segments
        # A workspace itself is local project code, not an npm release.
        name, sep, version = row[0].partition('@workspace:')
        if (sep and len(row) == 1 and workspace_names.get(name) == version
                and (key not in declared_workspace_names or key == name)):
            workspace_links.add(key)
            continue
        if key in declared_workspace_names:
            # Conflicting root bindings cannot establish which local/public
            # package is installed. Nested npm copies remain independent.
            workspace_links.discard(key)
            unresolved()
            continue
        name, sep, version = row[0].rpartition('@')
        if (len(row) != 4 or not sep or not _npm_name(name)
                or not _NPM_VERSION.fullmatch(version) or row[1] != ''
                or not isinstance(row[2], dict) or not isinstance(row[3], str) or not row[3]
                or row[2].get('bundled')):
            # A custom registry, git/file/link/tarball or bundled source
            # does not establish the public npm package's identity.
            unresolved()
            continue
        resolved[key] = (name, version)
        metadata[key] = row[2]

    direct = set()
    resolved_names = {identity[0] for identity in resolved.values()}
    checks = 0

    def lookup(parent: tuple[str, ...], name: str) -> str | None:
        nonlocal checks
        for depth in range(len(parent), -1, -1):
            checks += 1
            if checks > MAX_REFERENCE_CHECKS:
                raise _ParserLimit
            key = '/'.join((*parent[:depth], name))
            if key in packages or key in workspace_links:
                return key
        return None

    def references(parent: tuple[str, ...], block: dict, *, workspace: bool = False):
        nonlocal reason
        fields = ('dependencies', 'optionalDependencies', 'peerDependencies')
        if workspace:
            fields += ('devDependencies',)
        optional_peers = block.get('optionalPeers', [])
        if (not isinstance(optional_peers, list)
                or any(not isinstance(name, str) for name in optional_peers)):
            optional_peers = []
            unresolved()
        optional_peers = set(optional_peers)
        for field in fields:
            entries = block.get(field, {})
            if not isinstance(entries, dict):
                unresolved()
                continue
            for name, spec in entries.items():
                if not _npm_name(name) or not isinstance(spec, str) or not spec:
                    unresolved()
                    continue
                key = lookup(parent, name)
                # Bun may bind peers by version across the package tree. All
                # public pins are already inventoried; do not invent a peer
                # version or demand installation of an absent optional peer.
                if field == 'peerDependencies' and (name in optional_peers or name in resolved_names):
                    continue
                if key not in resolved and key not in workspace_links:
                    unresolved()
                elif workspace and key in resolved:
                    direct.add(key)

    try:
        for path, workspace in workspaces.items():
            if path and path not in validated_workspace_paths:
                continue
            parent = (workspace['name'],) if path else ()
            references(parent, workspace, workspace=True)
        for key, info in metadata.items():
            references(paths[key], info)
    except _ParserLimit:
        reason = "parser_limit"
        direct.clear()
    for key, (name, version) in resolved.items():
        out.append(Dependency('npm', name, version, manifest, direct=key in direct))
    if reason is None and workspace_paths is not None:
        workspace_paths.update(validated_workspace_paths)
    return reason
