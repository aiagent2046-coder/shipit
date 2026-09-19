"""Build test inputs and native expectations; never included in public assets."""
import base64
import hashlib
import io
import zipfile
import json
import importlib.abc
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# A fresh process supplies the partial profile for the asset-failure test.
# Normal WASM corpus comparisons use the fully installed native profile.
if "--portable" in sys.argv:
    class NoNative(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {
                "tree_sitter", "tree_sitter_typescript", "tree_sitter_javascript", "pglast",
            }:
                raise ModuleNotFoundError("Unavailable in browser profile", name=fullname)

    sys.meta_path.insert(0, NoNative())

from app.scan.browser import ScanSession, scan_archive as _scan_archive  # noqa: E402
from tests.test_browser_cve import LOCK_GAPS, REAL_CASES, lock_gap_project, project  # noqa: E402
from tests.detectors.conftest import build_archive, discover_cases, load_expected  # noqa: E402
from tests.bun_fixtures import (  # noqa: E402
    FAST_URI_ADVISORIES, GSTACK_ADVISORIES, archive, bun_deep_path_project,
    bun_workspace_project, gstack_project,
)
from parser_probes import probe_parsers  # noqa: E402

CATALOG = json.loads((ROOT / "app/data/cve-catalog.json").read_text())


def scan_archive(data):
    return _scan_archive(data, CATALOG)


def dependency_cases():
    for ecosystem, name, version, cve, affected in REAL_CASES:
        for modern_lock in (False, True):
            profile = 'modern-lock' if modern_lock else 'original-lock'
            yield (f'dependency-cve-match/{cve}/{version}/{profile}',
                   project(ecosystem, name, version, modern_lock=modern_lock),
                   {'expect': [{'rule_id': 'dependency-cve-match', 'cve_id': cve}]} if affected
                   else {'forbid_cves': [cve]}, affected)
    for name, manifest, body, _ in LOCK_GAPS:
        yield (f'dependency-cve-match/{name}', lock_gap_project(manifest, body),
               {'forbid_cves': ['CVE-2026-2950', 'CVE-2024-7297']}, False)
    for fixed in (False, True):
        yield (f'dependency-cve-match/bun-gstack/{"fixed" if fixed else "affected"}',
               gstack_project(fixed), {'forbid_advisories': sorted(GSTACK_ADVISORIES)} if fixed else {
                   'expect': [{'rule_id': 'dependency-cve-match', 'advisory_id': advisory}
                              for advisory in sorted(GSTACK_ADVISORIES)]}, not fixed)
    yield ('dependency-cve-match/bun-binary', archive({'bun.lockb': b'\x00binary', 'package.json': '{}'}),
           {'forbid': ['dependency-cve-match']}, False)
    for name, data in (
        ('bun-implicit-workspace', bun_workspace_project()),
        ('bun-deep-path/independent-first', bun_deep_path_project(True)),
        ('bun-deep-path/independent-last', bun_deep_path_project(False)),
    ):
        yield (f'dependency-cve-match/{name}', data, {
            'expect': [{'rule_id': 'dependency-cve-match', 'advisory_id': advisory}
                       for advisory in sorted(FAST_URI_ADVISORIES)]}, True)


def provenance_cases():
    prefix = 'import psycopg as pg\nc = pg.connect(dsn)\ncur = c.cursor()\n'
    sink = 'cur.execute(f"SELECT {user_id}")\n'
    for name, source, resolved in (
        ('resolved', prefix + sink, True),
        ('escaped', prefix + 'customize(cur)\n' + sink, False),
        ('custom-method', 'import psycopg\n' + sink, False),
        ('with', 'from psycopg import connect\nwith connect(dsn) as c:\n'
         '    with c.cursor() as cur:\n        ' + sink, True),
        ('annotation-rebinding', prefix + 'marker: (cur := CustomCursor())\n' + sink, False),
        ('default-escape', prefix + 'def configure(connection=c):\n'
         '    customize(connection)\nconfigure()\n' + sink, False),
        ('bound-setter', 'import psycopg\nc = psycopg.connect(dsn)\n'
         'change = c.__setattr__\nchange("cursor_factory", CustomCursor)\n'
         'cur = c.cursor()\n' + sink, False),
        ('chained-store', 'import psycopg\nregistry["driver"] = pg = psycopg\n'
         'c = pg.connect(dsn)\ncur = c.cursor()\n' + sink, False),
        ('match-binding', 'import psycopg\ndef load(value):\n'
         '    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + sink
         + '    match value:\n        case psycopg:\n            pass\n', False),
    ):
        data = archive({'src/query.py': source})
        result = scan_archive(data)
        decision, = result['report']['security_agent']['observations']
        assert decision['evidence']['sql_observation']['driver_status'] == (
            'source_resolved' if resolved else 'unknown')
        assert ('psycopg3_cursor_provenance' not in decision['missing_evidence']) == resolved
        assert decision['state'] == 'needs_evidence' and decision['recipe']['automatic_apply'] is False
        yield {'id': f'psycopg-provenance/{name}', 'rule': 'sql-injection-string-built-query',
               'polarity': 'positive', 'archive': base64.b64encode(data).decode(),
               'expected': {'expect': [{'rule_id': 'sql-injection-string-built-query', 'count': 1}]},
               'native': result}


def acquisition_cases():
    source = ('from fastapi import FastAPI\nimport psycopg\napp = FastAPI()\n'
              '@app.get("/users")\ndef load(name: str):\n'
              '    conn = psycopg.connect(dsn)\n    cur = conn.cursor()\n'
              '    cur.execute(f"SELECT id FROM users WHERE name = \'{name}\'")\n')
    for name, body, established, skipped in (
        ('source-goal', source, True, set()),
        ('unknown-driver', source.replace('connect(dsn)', 'connect(dsn, cursor_factory=CustomCursor)'),
         False, {'inspect_sql_slots'}),
        ('unknown-wrapper', source.replace("'{name}'", "'{normalize(name)}'"),
         False, {'collect_value_constraints'}),
        ('dynamic-identifier', source.replace("SELECT id FROM users WHERE name = '{name}'",
                                            'SELECT id FROM {name} WHERE id = 1'), False, set()),
        ('bound-input', source.replace("'{name}'", "'{value}'").replace(
            '    cur.execute', '    value = name\n    name = "constant"\n    cur.execute'), True, set()),
    ):
        data = archive({'src/query.py': body})
        result = scan_archive(data)
        decision, = result['report']['security_agent']['observations']
        acquisition = decision['acquisition']
        assert (decision['state'] == 'source_evidence_collected') == established
        assert (acquisition['status'] == 'completed') == established
        assert not skipped.intersection(step['action'] for step in acquisition['attempts'])
        assert {'caller_authorization', 'route_reachability', 'intended_value_type',
                'runtime_behavior_contract'} <= set(decision['missing_evidence'])
        assert not result['report']['security_agent']['runtime_verified']
        assert not decision['recipe']['automatic_apply']
        yield {'id': f'sql-evidence-agent/{name}', 'rule': 'sql-injection-string-built-query',
               'polarity': 'positive', 'archive': base64.b64encode(data).decode(),
               'expected': {'expect': [{'rule_id': 'sql-injection-string-built-query', 'count': 1}]},
               'native': result}


def main():
    if "--portable" in sys.argv:
        # Reuse the exact uploaded bytes: independently rebuilt ZIP timestamps
        # would describe a different source snapshot despite equal file text.
        print(json.dumps([scan_archive(base64.b64decode(encoded)) for encoded in json.load(sys.stdin)]))
        return
    cases = []
    for rule, polarity, directory in discover_cases():
        data = build_archive(directory).getvalue()
        result = scan_archive(data)
        cases.append({"id": f"{rule}/{polarity}/{directory.name}", "rule": rule,
                      "polarity": polarity, "archive": base64.b64encode(data).decode(),
                      "expected": load_expected(directory), "native": result})
    for case_id, data, expected, affected in dependency_cases():
        cases.append({'id': case_id, 'rule': 'dependency-cve-match',
                      'polarity': 'positive' if affected else 'negative',
                      'archive': base64.b64encode(data).decode(), 'expected': expected,
                      'native': scan_archive(data)})
    cases.extend(provenance_cases())
    cases.extend(acquisition_cases())
    portable = json.loads(subprocess.run(
        [sys.executable, __file__, "--portable"], check=True, capture_output=True, text=True,
        input=json.dumps([case['archive'] for case in cases]),
    ).stdout)
    for case, result in zip(cases, portable, strict=True):
        case['portable'] = result
        digest = hashlib.sha256(base64.b64decode(case['archive'])).hexdigest()
        assert case['native']['report']['security_agent']['source']['archive_sha256'] == digest
        assert result['report']['security_agent']['source']['archive_sha256'] == digest
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cases))
    (out.parent / 'parser-probes.json').write_text(json.dumps(probe_parsers()))
    (out.parent / 'parser-probes.py').write_text((Path(__file__).parent / 'parser_probes.py').read_text())
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for index in range(400):
            z.writestr(f'src/module{index}.js', 'export const value = true;')
        z.writestr('src/tail.js', 'element.innerHTML = untrusted;')
        z.writestr('src/tail.vue', '<template><div v-html="message"></div></template>')
        z.writestr('src/broken.js', 'const broken = [;')
        xml_call = 'etree.fromstring(xml, parser=etree.XMLParser(resolve_entities=True))\n'
        z.writestr('src/first.py', 'from lxml import etree\n' + xml_call * 31)
        for index in range(399):
            z.writestr(f'src/module{index}.py', 'pass\n')
        z.writestr('src/tail.py', 'from lxml import etree\n' + xml_call * 2
                   + 'query = "SELECT id FROM users WHERE id = " + user_id\n'
                     'cursor.execute(query)\n')
    session = ScanSession(archive.getvalue(), CATALOG)
    continuation = {"archive": base64.b64encode(archive.getvalue()).decode(),
                    "initial": session.result()}
    # Mixed-language rules need three batches for this mixed-source archive.
    continuation['continuations'] = [session.continue_scan() for _ in range(2)]
    continuation['final'] = continuation['continuations'][-1]
    # Parity alone could preserve the same continuation bug in both runtimes.
    # Require tail discovery, a shared cap and an honest remaining coverage gap.
    assert continuation['initial']['can_continue']
    assert continuation['initial']['report']['security_agent']['status'] == 'partial'
    assert not continuation['initial']['report']['security_agent']['observations']
    final = continuation['final']
    agent = final['report']['security_agent']
    assert agent['status'] == 'completed'
    assert len(agent['observations']) == 1
    decision = agent['observations'][0]
    assert decision['file'] == 'src/tail.py' and decision['weaknesses'] == ['CWE-89']
    trace = decision['evidence']['sql_observation']
    assert (trace['assembly_line'], trace['sink_line']) == (4, 5)
    assert 'psycopg3_cursor_provenance' in decision['missing_evidence']
    assert not agent['automatic_patch'] and not agent['runtime_verified']
    xml_findings = [f for f in final['report']['findings'] if f['rule_id'] == 'unsafe-xml-parse']
    assert len(xml_findings) == 32
    assert sum(f['file'] == 'src/tail.py' for f in xml_findings) == 1
    xml_coverage = final['report']['rule_coverage']['unsafe_xml_parse']
    assert xml_coverage['partial'] and xml_coverage['skip_reasons'] == {'finding_limit': 1}
    vue_findings = [f for f in final['report']['findings'] if f['file'] == 'src/tail.vue']
    assert len(vue_findings) == 1 and vue_findings[0]['rule_id'] == 'xss-unsafe-html-injection'
    assert not any(f['file'] == 'src/tail.vue' for f in continuation['initial']['report']['findings'])
    assert not final['can_continue']
    (out.parent / 'continuation.json').write_text(json.dumps(continuation))
    print(f"Wrote {len(cases)} native corpus expectations to {out}")


if __name__ == "__main__":
    main()
