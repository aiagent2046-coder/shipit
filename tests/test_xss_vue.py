"""Vue sink and coverage regressions; synthetic code is parsed, never run."""
import io
import zipfile

import pytest

from app.scan.xss import scan_xss


def archive(source, path="repo/src/View.vue"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(path, source)
    buf.seek(0)
    return buf


def scan(source):
    coverage = {}
    findings = scan_xss(archive(source), coverage=coverage)
    return findings, coverage


@pytest.mark.parametrize("value", ["message", "marked.parse(props.content)", "result.msg",
                                   "DOMPurify.sanitize(message)", "`<b>${message}</b>`"])
def test_vue_html_values_report_local_observation_without_claiming_reachability(value):
    source = f'<template>\n  <div\n    v-html="{value}"></div>\n</template>'
    findings, coverage = scan(source)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.line == 3
    assert "Vue v-html" in finding.explanation
    assert "NOT been verified" in finding.explanation
    assert "Vue interpolation" in finding.fix_hint
    assert coverage["analyzed_files"] == 1
    assert not coverage["partial"]


@pytest.mark.parametrize("source, old, new", [
    ('<template><p>{{ message }}</p></template>', '{{ message }}', '<span v-html="message" />'),
    ('<template><p v-text="message" /></template>', 'v-text', 'v-html'),
    ('<template><p v-html="\'&lt;b&gt;fixed&lt;/b&gt;\'" /></template>', "'&lt;b&gt;fixed&lt;/b&gt;'", 'message'),
    ('<template><p v-html="`fixed`" /></template>', '`fixed`', '`fixed ${message}`'),
    ('<template><p v-html="(\'fixed\')" /></template>', "('fixed')", '(message)'),
    ('<template><div v-pre><p v-html="message" /></div></template>', ' v-pre', ''),
    ('<template><p v-pre v-html="message" /></template>', ' v-pre', ''),
    ('<template><!-- <p v-html="message" /> --></template>',
     '<!-- <p v-html="message" /> -->', '<p v-html="message" />'),
])
def test_silent_vue_shapes_have_a_load_bearing_mutation(source, old, new):
    findings, coverage = scan(source)
    assert findings == []
    assert coverage["analyzed_files"] == 1
    assert len(scan(source.replace(old, new, 1))[0]) == 1


def test_script_strings_comments_custom_blocks_and_interpolation_are_not_directives():
    source = '''<script setup lang="ts">
const example = '<div v-html="message"></div>';
// el.innerHTML = message;
const regex = /v-html="message"/;
</script>
<template>
  {{ '<div v-html="message"></div>' }}
  <p title='v-html="message"'>&lt;div v-html="message"&gt;</p>
</template>
<style>/* <div v-html="message"></div> */</style>
<docs><div v-html="message"></div></docs>'''
    findings, coverage = scan(source)
    assert findings == []
    assert coverage["analyzed_files"] == 1


def test_dom_sink_in_script_block_uses_original_line_and_native_scope_resolution():
    source = '''<template><p>{{ message }}</p></template>
<script setup lang="ts">
const fixed = "fixed";
el.innerHTML = fixed;
el.innerHTML = message;
</script>'''
    findings, coverage = scan(source)
    assert [f.line for f in findings] == [5]
    assert "innerHTML" in findings[0].explanation
    assert coverage["analyzed_files"] == 1


def test_script_setup_and_regular_script_do_not_share_literal_suppression():
    findings, _ = scan('''<script>const html = "fixed";</script>
<script setup>el.innerHTML = html;</script>
<template><div v-html="html" /></template>''')
    assert [f.line for f in findings] == [2, 3]


@pytest.mark.parametrize("directive", ['v-html.trim', 'v-html:argument'])
def test_directive_modifiers_do_not_hide_html_sink(directive):
    assert len(scan(f'<template><p {directive}="message" /></template>')[0]) == 1


@pytest.mark.parametrize("source, reason", [
    ('<template lang="pug">p(v-html="message")</template>', 'unsupported_vue_template'),
    ('<template src="./view.html" />', 'unsupported_vue_template'),
    ('<script lang="coffee">x = 1</script><template><p /></template>', 'unsupported_vue_script'),
    ('<script src="./view.js" /><template><p /></template>', 'unsupported_vue_script'),
    ('<template><p v-html="message"></template>', 'parse_error'),
    ('<template><p v-html="message" /></template><template />', 'parse_error'),
    ('<template><p v-html="message"', 'parse_error'),
    ('<template><p v-html="" /></template>', 'parse_error'),
    ('<template><p v-html="fn(" /></template>', 'parse_error'),
    ('<template><p v-html="x); other(x); (y" /></template>', 'parse_error'),
    ('<template><p v-html="message" /></template><script>broken(</script>', 'parse_error'),
    ('<template><!-- <p v-html="message" /></template>', 'parse_error'),
    ('<template><p v-html="message" v-html="other" /></template>', 'parse_error'),
])
def test_unsupported_or_malformed_vue_is_never_counted_as_analyzed(source, reason):
    findings, coverage = scan(source)
    assert findings == []
    assert coverage["eligible_files"] == 1
    assert coverage["attempted_files"] == 1
    assert coverage["analyzed_files"] == 0
    assert coverage["skip_reasons"] == {reason: 1}
    assert coverage["partial"]


def test_vue_depth_budget_is_enforced_before_reporting():
    findings, coverage = scan('<template>' + '<div>' * 101 + '<p v-html="message" />' + '</div>' * 101 + '</template>')
    assert findings == []
    assert coverage["skip_reasons"] == {"ast_limit": 1}


def test_expression_node_budget_is_cumulative_across_directives(monkeypatch):
    import app.scan.xss as xss
    monkeypatch.setattr(xss, "_MAX_NODES", 80)
    findings, coverage = scan('<template>' + '<p v-html="message.x.y.z" />' * 8 + '</template>')
    assert findings == []
    assert coverage["skip_reasons"] == {"ast_limit": 1}


def test_vue_finding_limit_does_not_claim_the_whole_file_was_analyzed():
    findings, coverage = scan('<template>' + '<p v-html="message" />' * 33 + '</template>')
    assert len(findings) == 32
    assert coverage["skip_reasons"] == {"finding_limit": 1}
    assert coverage["analyzed_files"] == 0


def test_vue_exclusions_keep_tests_and_dependency_trees_out():
    for path in ['repo/tests/View.vue', 'repo/node_modules/pkg/View.vue']:
        coverage = {}
        assert scan_xss(archive('<template><p v-html="message" /></template>', path), coverage=coverage) == []
        assert coverage["eligible_files"] == 0
        assert coverage["excluded_files"] == 1


def test_unicode_before_directive_and_multiline_script_preserve_source_lines():
    source = '''<template>
  <p>中文</p><div v-html="message" />
</template>
<script setup lang="ts">
const 文 = "文字";
el.innerHTML = 文 + message;
</script>'''
    assert [f.line for f in scan(source)[0]] == [2, 6]


def test_capitalized_component_named_input_is_not_an_html_void_element():
    findings, coverage = scan('<template><Input><p v-html="message" /></Input><input /></template>')
    assert len(findings) == 1
    assert coverage["analyzed_files"] == 1
