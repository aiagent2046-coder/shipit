"""Import consistency never promotes static findings or runs project code."""
import hashlib

import pytest

from app.llm.client import LLMClient
from app.scan.client_runtime_chain import attach_client_runtime
from app.scan.client_runtime_record import ARCHIVE_SHA256, SCENARIO_SHA256
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.security_agent import agent_record
from tests.test_client_runtime_record import runtime_evidence
from tests.test_security_agent import archive


def base():
    return {'version':1,'mode':'deterministic_static','status':'completed',
            'automatic_patch':False,'runtime_verified':False,'plan':[], 'observations':[],
            'budget':{},'source':{'archive_sha256':ARCHIVE_SHA256,'engine_version':'test'}}


def test_bound_import_chain_and_saved_roundtrip():
    evidence=runtime_evidence(); agent=base()
    assert attach_client_runtime(agent,evidence,run_id=evidence['run_id'])
    chain=agent['client_runtime_chain']; previous=None
    assert chain['project_code_executed'] is False
    assert [t['agent'] for t in chain['tasks']]==['detector','researcher','experimenter','verifier']
    for task in chain['tasks']:
        assert task['depends_on']==([previous['id']] if previous else [])
        if previous: assert task['input_sha256']==previous['output_sha256']
        previous=task
    assert agent_record(agent)==agent
    evidence['checks'].clear()
    assert len(agent['client_runtime']['checks'])==12
    assert agent['runtime_verified'] is agent['automatic_patch'] is False


@pytest.mark.parametrize('field,value',[('input_sha256','0'*64),('attempts',True),('reason','executed_customer_code')])
def test_corrupt_receipts_drop_only_import(field,value):
    agent=base(); evidence=runtime_evidence()
    attach_client_runtime(agent,evidence,run_id=evidence['run_id'])
    agent['client_runtime_chain']['tasks'][1][field]=value
    normalized=agent_record(agent)
    assert normalized['client_runtime_status']=='rejected'
    assert 'client_runtime' not in normalized and normalized['observations']==[]
    assert normalized['status']=='completed'


def test_pipeline_import_is_no_llm_and_does_not_change_findings(monkeypatch):
    import app.scan.client_runtime_record as contract
    from tests.test_evidence_acquisition import HTTP_SQL
    raw=archive({'app/query.py':HTTP_SQL})
    baseline=run_scan(raw,LLMClient(providers=[]),depth=BASIS_PREVIEW)
    # An isolated test pin permits a tiny archive instead of shipping customer code.
    pin=hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(contract,'ARCHIVE_SHA256',pin)
    evidence=runtime_evidence(); evidence['archive_sha256']=pin
    monkeypatch.setattr(LLMClient,'complete',lambda *a,**k: pytest.fail('No LLM allowed'))
    result=run_scan(raw,LLMClient(providers=[]),depth=BASIS_PREVIEW,
                    client_runtime_evidence=evidence,client_runtime_run_id=evidence['run_id'])
    manifest=result['score']['scan_manifest']; agent=manifest['security_agent']
    assert manifest['model_calls']==0
    assert agent['client_runtime_status']=='accepted'
    assert result['findings']==baseline['findings']
    assert result['score']['total']==baseline['score']['total']
    assert agent['observations']==baseline['score']['scan_manifest']['security_agent']['observations']
    rejected=run_scan(raw,LLMClient(providers=[]),depth=BASIS_PREVIEW,
                      client_runtime_evidence=evidence,client_runtime_run_id='wrong-run')
    assert rejected['score']['scan_manifest']['security_agent']['client_runtime_status']=='rejected'
    assert rejected['findings']==baseline['findings']


def test_tracked_scenario_matches_pin():
    from pathlib import Path
    script=Path(__file__).resolve().parents[1]/'scripts/runtime_contracts/cumora_project_tenant_isolation_v1.mjs'
    assert hashlib.sha256(script.read_bytes()).hexdigest()==SCENARIO_SHA256


def test_cli_rejects_duplicate_keys_and_existing_output(tmp_path):
    from scripts.import_client_runtime import main
    zip_path=tmp_path/'project.zip';zip_path.write_bytes(archive({'README.md':'hello'}))
    evidence=tmp_path/'scenario.json';evidence.write_text('{"status":"failed","status":"passed"}')
    out=tmp_path/'report.json'
    args=[str(zip_path),'--evidence',str(evidence),'--run-id','test','--output',str(out)]
    assert main(args)==2
    assert not out.exists()
    evidence.write_text('{}')
    assert main(args)==1
    assert out.exists()
    out.write_text('preserve me')
    assert main(args)==2
    assert out.read_text()=='preserve me'
