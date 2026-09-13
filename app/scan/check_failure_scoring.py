"""Categories whose static evidence is incomplete after a check failure."""

from app.scan.check_failures import normalize_check_failures
from app.scan.scoring import CATEGORIES


CHECK_CATEGORIES = {
    'secrets': {'Security'}, 'rls': {'Security'}, 'schema_drift': {'Security'},
    'sql_injection': {'Security'}, 'sql_injection_js': {'Security'},
    'outbound_url': {'Security'}, 'tls_verification': {'Security'},
    'unsafe_deserialization': {'Security'}, 'path_traversal': {'Security'},
    'session_cookie': {'Security'}, 'project_files': {'Security', 'Testing', 'Deploy'},
    'ci_deploy_source': {'Deploy'}, 'service_role': {'Auth'},
    'auth_read_consistency': {'Auth'}, 'auth_write_consistency': {'Auth'},
    'error_boundary': {'Frontend'}, 'http_success': {'Frontend'},
}


def failed_check_categories(failures):
    categories = set()
    for failure in normalize_check_failures(failures):
        categories.update(CHECK_CATEGORIES.get(failure['check'], CATEGORIES))
    return frozenset(categories)
