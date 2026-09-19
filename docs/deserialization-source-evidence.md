# Deserialization input evidence

The existing deterministic researcher can establish two source facts for the
Python deserialization card: `request_input_source` and `local_input_flow`.
The first supported case is a FastAPI route with one explicit `bytes` Body
parameter reaching an import-resolved `pickle.loads` call in the same file.

```python
from fastapi import Body, FastAPI
import pickle

app = FastAPI()

@app.post("/restore")
def restore(payload: bytes = Body(...)):
    encoded = payload
    return pickle.loads(encoded)
```

This example is a finding, not a recommended implementation. The researcher
records the parameter declaration, local assignments and exact loader call.
It supports ordinary Body defaults and `Annotated[bytes, Body(...)]`, resolved
import aliases, and synchronous or asynchronous handlers. It does not import
or execute the uploaded project, deserialize data, call an LLM or use a network.

## Evidence and remaining work

The detector emits `deserialization_observation` version 1 with the file hash
and complete AST call span. The researcher locates that exact call in the
original archive snapshot, then records acquisition version 2 with at most two
actions: `locate_source` and `trace_request_input`. Multiple calls on the same
line cannot share an acquisition. SQL acquisitions retain version 1.

Successful acquisition changes the review to `source_evidence_collected`.
The card still requires `input_trust_boundary` and `loader_runtime_contract`:
the HTTP source does not establish producer authentication, permission to call
the route, byte integrity, deployed reachability, installed loader behavior or
expected object types. No synthetic deserialization recipe is registered.
The experimenter and verifier explicitly report missing evidence;
`automatic_apply`, `automatic_patch` and `runtime_verified` remain false.

Ambiguous bindings, local modules shadowing supported imports, unsupported
control flow, wrappers and cross-file flows retain the detector finding without
establishing input provenance. Shared work/action budgets and per-source limits
apply; budget exhaustion or collector failure remains incomplete, with a bounded
reason and no exception text or source values in the report.

## Saved reports

JSON/SARIF, HTML, the web report and the standalone browser report retain the
same source facts. Normalizers bind acquisition version, file hash, call span,
fact endpoints and action journal before displaying evidence. The task chain
also binds the archive, engine, catalog and observation identities. These checks
establish internal consistency, not authenticity of externally edited JSON.
Python, web and standalone browser replay all revoke the acquisition when that
chain is missing or inconsistent: the report becomes `partial`, the candidate
returns to `needs_evidence`, and all four source/runtime prerequisites are restored.
Reading a report never runs the collector or a project command. Historical
reports without this evidence remain readable.

The change uses engine version `2026-09-19-6`, catalog `2026-09-19.3` and
deserialization card revision 2, invalidating results cached before this analysis.
