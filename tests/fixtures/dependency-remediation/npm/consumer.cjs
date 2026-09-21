// Execute this trusted probe from the disposable fixture's working directory.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const path = require('node:path');

const root = process.cwd();
const use = createRequire(path.resolve(root, 'package.json'));
const pluginEntry = use.resolve('@rollup/pluginutils');
const pluginUse = createRequire(pluginEntry);
const { createFilter } = use('@rollup/pluginutils');
// Version 4.1.2 exposes dist/cjs/index.js but does not export package.json.
const consumerVersion = JSON.parse(readFileSync(
  path.resolve(path.dirname(pluginEntry), '../../package.json'), 'utf8',
)).version;
assert.equal(consumerVersion, '4.1.2', 'the consumer must remain pinned');

const filter = createFilter(
  ['**/*.svelte', '**/*.{js,ts}'],
  ['**/node_modules/**', '**/*.test.*'],
  { resolve: root },
);
const cases = [
  ['src/routes/index.svelte', true],
  ['src/lib/client.ts', true],
  ['src/lib/client.js', true],
  ['src/lib/client.test.ts', false],
  ['node_modules/x/index.js', false],
  ['README.md', false],
  ['src/picture.svg', false],
];
for (const [file, expected] of cases) {
  assert.equal(filter(path.resolve(root, file)), expected, file);
}
assert.equal(filter('\0virtual-module.js'), false, 'virtual modules are excluded');
assert.equal(filter(null), false, 'non-string module IDs are excluded');

console.log(JSON.stringify({
  package: 'picomatch',
  installed_version: pluginUse('picomatch/package.json').version,
  installed_path: pluginUse.resolve('picomatch'),
  consumer: '@rollup/pluginutils',
  consumer_version: consumerVersion,
  functional_checks: cases.length + 2,
  functional_passed: true,
  regression: null,
}));
