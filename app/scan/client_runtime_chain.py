"""Receipts for importing operator evidence, never for executing project code."""
import hashlib
import json

from app.scan.client_runtime_record import normalize_client_runtime_record, validate_client_runtime_evidence

ROLES = ('detector', 'researcher', 'experimenter', 'verifier')
REASONS = ('archive_binding_checked', 'pinned_scenario_selected',
           'operator_evidence_received', 'evidence_consistency_validated')

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()

def runtime_chain(record, engine_version):
    """Deterministic import receipts; hashes provide consistency, not authenticity."""
    binding = {k: record[k] for k in ('archive_sha256', 'run_id', 'scenario_id', 'scenario_sha256', 'evidence_sha256')}
    binding['engine_version'] = engine_version
    accepted = {'source': binding}
    tasks = []
    for role, reason in zip(ROLES, REASONS):
        before = digest(accepted)
        accepted = {**accepted, role: reason}
        tasks.append({'id': digest([binding, role]), 'agent': role, 'reason': reason,
                      'source': dict(binding), 'depends_on': [tasks[-1]['id']] if tasks else [],
                      'input_sha256': before, 'output_sha256': digest(accepted),
                      'status': 'completed', 'attempts': 1, 'max_attempts': 1})
    return {'version': 1, 'mode': 'operator_evidence_import', 'scope': record['scope'],
            'status': 'completed', 'tasks': tasks, 'project_code_executed': False}

def attach_client_runtime(agent, evidence, *, run_id):
    """Reject separately; static findings and their proof status are untouched."""
    source = agent.get('source')
    source = source if isinstance(source, dict) else {}
    record = validate_client_runtime_evidence(evidence, archive_sha256=source.get('archive_sha256'), run_id=run_id)
    agent['client_runtime_status'] = 'rejected'
    agent.pop('client_runtime', None)
    agent.pop('client_runtime_chain', None)
    if record is not None:
        agent['client_runtime'] = record
        agent['client_runtime_chain'] = runtime_chain(record, source.get('engine_version'))
        agent['client_runtime_status'] = 'accepted'
    return record is not None

def normalize_client_runtime_attachment(agent):
    """Called on copied saved reports; discard any edited/inconsistent attachment."""
    if not any(k in agent for k in ('client_runtime', 'client_runtime_chain', 'client_runtime_status')):
        return
    source = agent.get('source')
    source = source if isinstance(source, dict) else {}
    record = normalize_client_runtime_record(agent.get('client_runtime'), archive_sha256=source.get('archive_sha256'))
    try:
        matches = (record is not None and agent.get('client_runtime_status') == 'accepted'
                   and digest(agent.get('client_runtime_chain')) == digest(runtime_chain(record, source.get('engine_version'))))
    except (TypeError, ValueError, RecursionError):
        matches = False
    if matches:
        agent['client_runtime'] = record
        return
    agent.pop('client_runtime', None)
    agent.pop('client_runtime_chain', None)
    agent['client_runtime_status'] = 'rejected'
