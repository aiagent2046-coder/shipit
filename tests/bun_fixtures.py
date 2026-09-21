"""Small, inert Bun inputs shared by native and WASM regression checks."""
import io
import json
import zipfile


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        for path, body in files.items():
            z.writestr(path, body)
    return data.getvalue()


def registry(name, version, **metadata):
    return [f'{name}@{version}', '', metadata, 'sha512-fixture']


def bun(packages=None, workspaces=None):
    return json.dumps({'lockfileVersion': 1,
                       'workspaces': workspaces if workspaces is not None else {'': {}},
                       'packages': packages if packages is not None else {
                           'lodash': registry('lodash', '4.17.23')}}, indent=2)


GSTACK_ADVISORIES = {
    'CVE-2026-84292', 'CVE-2026-84394', 'CVE-2026-86472',
    'CVE-2026-90711', 'GHSA-p7fg-763f-g4gf',
}

FAST_URI_ADVISORIES = {
    'CVE-2026-84292', 'CVE-2026-84394', 'CVE-2026-86472',
}


def bun_workspace_project():
    """An implicit workspace is resolved from workspaces, without a tuple."""
    root = {'name': 'workspace-fixture', 'workspaces': ['apps/web'],
            'dependencies': {'@project/web': 'workspace:*'}}
    workspace = {'name': '@project/web', 'dependencies': {'fast-uri': '3.1.6'}}
    text = bun({'@project/web/fast-uri': registry('fast-uri', '3.1.6')},
               {'': root, 'apps/web': workspace})
    return archive({'project/bun.lock': text,
                    'project/package.json': json.dumps(root),
                    'project/apps/web/package.json': json.dumps(workspace)})


def bun_deep_path_project(independent_first=False):
    """A 129-byte path reaches the parser's 65th segment, below Bun's limit.

    Each a version requires the next one, forcing separate nested resolutions.
    A limit on that chain must retain the independent vulnerable root pin,
    regardless of the order of package keys in JSON.
    """
    packages = {}
    for depth in range(1, 66):
        metadata = {'dependencies': {'a': f'{depth + 1}.0.0'}} if depth < 65 else {}
        packages['/'.join(['a'] * depth)] = registry('a', f'{depth}.0.0', **metadata)
    independent = {'fast-uri': registry('fast-uri', '3.1.6')}
    packages = ({**independent, **packages} if independent_first else {**packages, **independent})
    root = {'name': 'deep-path-fixture', 'dependencies': {'a': '1.0.0', 'fast-uri': '3.1.6'}}
    return archive({'project/bun.lock': bun(packages, {'': root}),
                    'project/package.json': json.dumps(root)})


def gstack_project(fixed=False):
    """Selected pins from the supplied gstack 1.87.4 archive, no project code.

    Keep its two SDK versions and nested resolution. The three fast-uri CVEs,
    proxy-addr CVE and nested SDK GHSA were missed before Bun inventory support.
    Integrity strings are inert test placeholders; never install this fixture.
    """
    packages = {
        '@anthropic-ai/claude-agent-sdk': registry(
            '@anthropic-ai/claude-agent-sdk', '0.2.117',
            dependencies={'@anthropic-ai/sdk': '^0.91.1' if fixed else '^0.81.0'}),
        '@anthropic-ai/sdk': registry('@anthropic-ai/sdk', '0.78.0'),
        '@anthropic-ai/claude-agent-sdk/@anthropic-ai/sdk': registry(
            '@anthropic-ai/sdk', '0.91.1' if fixed else '0.81.0'),
        'fast-uri': registry('fast-uri', '3.1.8' if fixed else '3.1.6'),
        'proxy-addr': registry('proxy-addr', '2.0.8' if fixed else '2.0.7'),
    }
    workspaces = {'': {'devDependencies': {
        '@anthropic-ai/claude-agent-sdk': '0.2.117', '@anthropic-ai/sdk': '^0.78.0'}}}
    text = bun(packages, workspaces).replace('\n}', ',\n}')
    return archive({'project/bun.lock': '// Bun JSONC fixture\n' + text,
                    'project/package.json': '{"name":"gstack-fixture"}'})
