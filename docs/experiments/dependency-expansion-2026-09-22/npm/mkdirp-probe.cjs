'use strict';
const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const lock = require(path.resolve('package-lock.json'));
const installations = [];
for (const [relative, entry] of Object.entries(lock.packages)) {
  if (!relative.endsWith('/minimist')) continue;
  const location = path.resolve(relative);
  const parse = require(location);
  const version = require(path.join(location, 'package.json')).version;
  assert.equal(version, entry.version);
  const marker = 'drydockLocalRegressionMarker';
  assert.equal(Object.hasOwn(Function.prototype, marker), false);
  let polluted;
  try {
    parse(['--_.constructor.constructor.prototype.' + marker, 'local-probe']);
    polluted = (function () {})[marker] === 'local-probe';
  } finally { delete Function.prototype[marker]; }
  installations.push({path: relative, version, regression_passed: !polluted});
}
// Consumer CLI checks exercise the dependency's actual argument parsing path.
const tmp = fs.mkdtempSync(path.join(process.cwd(), '.cli-check-'));
try {
  const a = path.join(tmp, 'a', 'b');
  const b = path.join(tmp, 'c', 'd');
  cp.execFileSync(process.execPath, ['bin/cmd.js', '--mode', '700', a, b], {timeout: 10000});
  assert.ok(fs.statSync(a).isDirectory());
  assert.ok(fs.statSync(b).isDirectory());
  assert.equal(fs.statSync(a).mode & 0o777, 0o700);
  assert.equal(fs.statSync(b).mode & 0o777, 0o700);
  assert.match(cp.execFileSync(process.execPath, ['bin/cmd.js', '--help'], {encoding:'utf8', timeout:10000}), /mkdirp/);
} finally { fs.rmSync(tmp, {recursive:true,force:true}); }
console.log(JSON.stringify({installations, cli_checks:5, cli_passed:true,
  regression:'minimist-constructor-function-prototype-pollution'}));
