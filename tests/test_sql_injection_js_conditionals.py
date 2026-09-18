"""Conditional SQL fragments need fixed values on every reachable local arm.

The examples are synthetic reductions of the independently reviewed Cumora
pattern. SQL parameters do not sanitize text interpolated into the query.
Only source parsing runs; the JavaScript/TypeScript is never executed.
"""

from __future__ import annotations

import io
import textwrap
import zipfile

import pytest

from app.scan.sql_injection_js import RULE_ID, scan_sql_injection_js


CASES = [
    pytest.param(
        """
        function load(db, req) {
          db.query(req.lock ? 'SELECT id FROM items FOR UPDATE' : 'SELECT id FROM items');
        }
        """,
        False, id='whole-query-fixed-arms',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query(req.lock ? `SELECT id FROM items WHERE id = ${req.id}` : 'SELECT id FROM items');
        }
        """,
        True, id='whole-query-preserves-assembled-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query(req.lock ? `SELECT id FROM items ${predicate(1)}` : `DELETE FROM items ${predicate(1)}`,
                   [req.id]);
        }
        """,
        True, id='whole-query-helper-remains-unverified',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? ' FOR UPDATE' : '';
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        False, id='fixed-ternary-fragment',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? req.fragment : '';
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='untrusted-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query(`SELECT id FROM items WHERE id = $1${req.lock ? ' FOR UPDATE' : ''}`, [req.id]);
        }
        """,
        False, id='fixed-inline-ternary',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query(`SELECT id FROM items WHERE id = $1${req.lock ? ' FOR UPDATE' : req.fragment}`, [req.id]);
        }
        """,
        True, id='untrusted-inline-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment;
          if (req.lock) { fragment = ' FOR UPDATE'; } else { fragment = ''; }
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        False, id='fixed-if-else-control',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment;
          if (req.lock) { fragment = req.fragment; } else { fragment = ''; }
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='untrusted-if-else-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          const arbitraryName = req.lock ? ' FOR UPDATE' : '';
          db.query(`SELECT id FROM items WHERE id = $1${arbitraryName}`, [req.id]);
        }
        """,
        False, id='fixed-renamed-binding',
    ),
    pytest.param(
        """
        function load(db, req) {
          const safeFragment = req.lock ? req.fragment : '';
          db.query(`SELECT id FROM items WHERE id = $1${safeFragment}`, [req.id]);
        }
        """,
        True, id='misleading-safe-name',
    ),
    pytest.param(
        """
        function load(db, req) {
          const yes = ' FOR UPDATE';
          const no = '';
          const fragment = req.lock ? yes : no;
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        False, id='known-literal-arms',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? sanitizeSql(req.fragment) : '';
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='unknown-helper-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.lock ? ' FOR UPDATE' : '';
          fragment = req.fragment;
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='later-untrusted-reassignment',
    ),
    pytest.param(
        """
        const fragment = ' FOR UPDATE';
        function load(db, req, fragment) {
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='shadowed-fragment-parameter',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? ' FOR UPDATE' : (req.share ? ' FOR SHARE' : '');
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        False, id='nested-fixed-choices',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? (req.share ? req.fragment : ' FOR SHARE') : '';
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='nested-untrusted-consequence',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? ' FOR UPDATE' : (req.share ? ' FOR SHARE' : req.fragment);
          db.query(`SELECT id FROM items WHERE id = $1${fragment}`, [req.id]);
        }
        """,
        True, id='nested-untrusted-alternative',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query('SELECT id FROM items WHERE id = $1' + (req.lock ? ' FOR UPDATE' : ''), [req.id]);
        }
        """,
        False, id='fixed-choice-concatenated',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query('SELECT id FROM items WHERE id = $1' + (req.lock ? req.fragment : ''), [req.id]);
        }
        """,
        True, id='untrusted-choice-concatenated',
    ),
    pytest.param(
        """
        const fragment = ' FOR UPDATE';
        function load(db, req, fragment) {
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
        }
        """,
        True, id='shadowed-literal-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = ' FOR UPDATE';
          {
            const fragment = req.fragment;
            db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
          }
        }
        """,
        True, id='block-shadowed-literal-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = ' FOR UPDATE';
          db.query(`SELECT id FROM items${(fragment = req.fragment) ? fragment : ''}`);
        }
        """,
        True, id='condition-invalidates-literal-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = ' FOR UPDATE';
          db.query(`SELECT id FROM items${((fragment = req.fragment) ? req.lock : req.share) ? '' : fragment}`);
        }
        """,
        True, id='nested-condition-invalidates-outer-alternative',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = '';
          db.query(`SELECT id FROM items${req.lock ? (fragment = req.fragment) : ''}`);
        }
        """,
        True, id='branch-assignment-is-untrusted-value',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          const marker = req.lock ? '' : (fragment = ' FOR UPDATE');
          db.query(`SELECT id FROM items${req.share ? fragment : ''}`);
        }
        """,
        True, id='branch-merge-preserves-untrusted-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`, [fragment = '']);
        }
        """,
        True, id='later-call-argument-cannot-sanitize-query',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query(`SELECT id FROM items${fragment}${(fragment = '') ? '' : ''}`);
        }
        """,
        True, id='later-interpolation-cannot-sanitize-earlier-value',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query('SELECT id FROM items' + fragment + ((fragment = '') ? '' : ''));
        }
        """,
        True, id='later-concat-operand-cannot-sanitize-earlier-value',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query('SELECT id FROM items'.concat(fragment, (fragment = '') ? '' : ''));
        }
        """,
        True, id='later-concat-argument-cannot-sanitize-receiver',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query(['SELECT id FROM items', fragment, (fragment = '') ? '' : ''].join(''));
        }
        """,
        True, id='later-array-item-cannot-sanitize-earlier-value',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          db.query('SELECT id FROM items SUFFIX'.replace('SUFFIX', req.lock ? fragment : ''), [fragment = '']);
        }
        """,
        True, id='later-replace-argument-cannot-sanitize-replacement',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query('SELECT id FROM items'.concat(req.lock ? ' FOR UPDATE' : ''));
        }
        """,
        False, id='fixed-concat-choice',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query(['SELECT id FROM items', req.lock ? ' FOR UPDATE' : ''].join(''));
        }
        """,
        False, id='fixed-join-choice',
    ),
    pytest.param(
        """
        function load(db, req) {
          db.query('SELECT id FROM items SUFFIX'.replace('SUFFIX', req.lock ? ' FOR UPDATE' : ''));
        }
        """,
        False, id='fixed-replace-choice',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          fragment = req.lock ? ' FOR UPDATE' : '';
          db.query(`SELECT id FROM items${fragment}`);
        }
        """,
        False, id='fixed-choice-after-safe-reassignment',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = req.lock ? (req.share ? sanitizeSql(req.fragment) : ' FOR SHARE') : '';
          db.query(`SELECT id FROM items${fragment}`);
        }
        """,
        True, id='unknown-helper-nested-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          req.lock && (fragment = '');
          db.query(`SELECT id FROM items${req.share ? fragment : ''}`);
        }
        """,
        True, id='short-circuit-and-cannot-prove-literal',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          req.lock || (fragment = '');
          db.query(`SELECT id FROM items${req.share ? fragment : ''}`);
        }
        """,
        True, id='short-circuit-or-cannot-prove-literal',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          req.lock ?? (fragment = '');
          db.query(`SELECT id FROM items${req.share ? fragment : ''}`);
        }
        """,
        True, id='short-circuit-nullish-cannot-prove-literal',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = '';
          switch (req.kind) {
            case 'raw': fragment = req.fragment; break;
            default: fragment = '';
          }
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
        }
        """,
        True, id='switch-unsafe-case-is-not-erased-by-default',
    ),
    pytest.param(
        """
        function load(db, req, optional) {
          let fragment = req.fragment;
          optional?.method(fragment = '');
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
        }
        """,
        True, id='optional-method-call-may-skip-assignment',
    ),
    pytest.param(
        """
        function load(db, req, optional) {
          let fragment = req.fragment;
          optional?.(fragment = '');
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
        }
        """,
        True, id='optional-function-call-may-skip-assignment',
    ),
    pytest.param(
        """
        function load(db, req, optional) {
          let fragment = req.fragment;
          optional?.[fragment = ''];
          db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
        }
        """,
        True, id='optional-subscript-may-skip-assignment',
    ),
    pytest.param(
        """
        function load(db, req, obj) {
          let fragment = '';
          db.query(`SELECT id FROM items${(obj[fragment = req.fragment] = 1) ? fragment : ''}`);
        }
        """,
        True, id='assignment-target-effects-reach-conditional-arm',
    ),
    pytest.param(
        """
        function load(db, req, obj) {
          let fragment = '';
          db.query(`SELECT id FROM items${(obj[fragment = req.fragment]++) ? fragment : ''}`);
        }
        """,
        True, id='update-target-effects-reach-conditional-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragments = ['id'];
          const alias = fragments;
          alias[0] = req.fragment;
          db.query(`SELECT ${req.pick ? fragments : []} FROM items`);
        }
        """,
        True, id='mutable-array-alias-is-not-fixed-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragments = ['id'];
          const alias = fragments;
          alias[0] = req.fragment;
          db.query(`SELECT ${req.pick ? fragments.join('') : ''} FROM items`);
        }
        """,
        True, id='mutable-array-join-is-not-fixed-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          const fragment = /id/;
          const alias = fragment;
          alias.toString = () => req.fragment;
          db.query(`SELECT ${req.pick ? fragment : ''} FROM items`);
        }
        """,
        True, id='mutable-regexp-alias-is-not-fixed-ternary-arm',
    ),
    pytest.param(
        """
        function load(db, req) {
          let fragment = req.fragment;
          switch (req.kind) {
            case 'fixed': fragment = ''; break;
            case 'query': db.query(`SELECT id FROM items${req.lock ? fragment : ''}`);
          }
        }
        """,
        True, id='switch-later-case-starts-from-entry-state',
    ),
]


@pytest.mark.parametrize("extension", ["js", "ts"])
@pytest.mark.parametrize("source, expected_finding", CASES)
def test_conditional_sql_fragments(source, expected_finding, extension):
    source = textwrap.dedent(source).strip()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(f"src/queries.{extension}", source)
    coverage = {}
    findings = scan_sql_injection_js(archive, coverage=coverage)
    assert len(findings) == int(expected_finding)
    assert all(finding.rule_id == RULE_ID for finding in findings)
    if findings:
        expected_line = next(index for index, line in enumerate(source.splitlines(), 1)
                             if "db.query(" in line)
        assert findings[0].line == expected_line
    assert coverage["analyzed_files"] == 1
    assert not coverage["skip_reasons"]
