"""Offline VTEX consumer checks and bounded CVE-2024-47081 regression."""

import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests import Response
from requests.adapters import BaseAdapter

sys.path.insert(0, sys.argv[1])
from vtex import Vtex


# All HTTP responses come from an adapter; accidental network use fails closed.
def forbidden(*args, **kwargs):
    raise AssertionError("unexpected network call")


socket.socket = forbidden
socket.create_connection = forbidden


class OfflineAdapter(BaseAdapter):
    def __init__(self):
        self.seen = []
        self.status = 200
        self.raise_timeout = False

    def send(self, request, **kwargs):
        self.seen.append((request, kwargs))
        if self.raise_timeout:
            raise requests.Timeout("synthetic timeout")
        response = Response()
        response.status_code = self.status
        response._content = b'{"Id":42,"Name":"demo"}'
        response.headers["x-vtex-md-token"] = "synthetic-scroll-token"
        response.request = request
        return response

    def close(self):
        pass


checks = []
session = requests.Session()
session.trust_env = False
adapter = OfflineAdapter()
session.mount("https://", adapter)
client = Vtex("test-account", "test-environment", "dummy-key", "dummy-token", session, 7.5)
result = client.catalog.get_product(42)
request, options = adapter.seen[-1]
assert request.method == "GET"
assert request.url == "https://test-account.test-environment.com.br/api/catalog_system/pvt/products/ProductGet/42"
checks.append("product GET URL")
assert request.headers["X-VTEX-API-AppKey"] == "dummy-key"
assert request.headers["X-VTEX-API-AppToken"] == "dummy-token"
assert request.headers["Accept"] == "application/vnd.vtex.ds.v10+json"
assert request.headers["Content-Type"] == "application/json"
checks.append("request authentication and content headers")
assert options["timeout"] == 7.5
checks.append("configured timeout forwarded")
assert result.json == {"Id": 42, "Name": "demo"} and result.status_code == 200
assert result.token == "synthetic-scroll-token"
checks.append("success JSON and pagination token")
client.catalog.get_list_all_skus(page=2, page_size=25)
assert adapter.seen[-1][0].url.endswith("?page=2&pagesize=25")
checks.append("pagination query parameters")
adapter.status = 404
result = client.catalog.get_product(999)
assert result.status_code == 404 and result.json is None and result.token is None
checks.append("404 response mapping")
adapter.raise_timeout = True
try:
    client.catalog.get_product(42)
except requests.Timeout:
    checks.append("timeout exception preserved")
else:
    raise AssertionError("timeout suppressed")

# Independent probe of the upstream advisory. Only synthetic netrc credentials.
# No request is sent: prepare_request exercises Requests' auth selection.
with tempfile.TemporaryDirectory() as directory:
    netrc = Path(directory) / "synthetic.netrc"
    netrc.write_text("machine trusted.invalid login demo-user password synthetic-password\n")
    netrc.chmod(0o600)
    os.environ["NETRC"] = str(netrc)
    auth_session = requests.Session()
    normal = auth_session.prepare_request(requests.Request("GET", "https://trusted.invalid/resource"))
    crafted = auth_session.prepare_request(
        requests.Request("GET", "https://trusted.invalid:443@other.invalid/resource")
    )
    assert urlparse(crafted.url).hostname == "other.invalid"
    assert normal.headers.get("Authorization") == requests.auth._basic_auth_str("demo-user", "synthetic-password")
    leaked = crafted.headers.get("Authorization") == normal.headers["Authorization"]

print(
    json.dumps(
        {
            "installed_version": requests.__version__,
            "consumer_checks_passed": checks,
            "consumer_checks_count": len(checks),
            "upstream_regression": {
                "id": "CVE-2024-47081",
                "credential_misbinding_observed": leaked,
                "method": "prepare_request_only",
                "requests_sent": 0,
                "application_reachability": "not_established",
            },
        }
    )
)
