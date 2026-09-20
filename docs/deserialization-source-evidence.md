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

## File input

Engine `2026-09-20-1`, catalog `2026-09-20.1` and deserialization card revision 3
also support a bounded file binding. An import-resolved `pickle.load` observation
starts the same task chain, with acquisition version 3 and the actions
`locate_source` and `trace_file_input`. Earlier Body acquisitions retain version 2.

```python
import pickle

def read_checkpoint(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)
```

The file researcher records `file_input_source` and `local_input_flow`: the
function and parameter, the binary read operation, its handle binding and the
exact loader span. Every fact is bound to the original source hash and task
receipts. It does not open the named project file or load a checkpoint.

Supported source shapes are deliberately narrow. In particular, an earlier
branch ending in `return` may precede the file operation, as in Needle's format
dispatch. The branch condition is not interpreted. The trace does not establish
the selected format, caller, file producer, file integrity, reachability or the
runtime behavior of a function called in that condition. Rebinding, unsupported
file operations and visible loader/builtin shadowing leave the source goal open.

Completed file collection leaves `request_input_source`, `input_trust_boundary`
and `loader_runtime_contract` unresolved. For file observations, reports label
the first legacy prerequisite as **Calling code and origin of the file (not
checked)**: an HTTP source is not inferred from a filesystem operation. The next
step is to inspect callers and producers and decide which serialization formats
the application should accept. This does not certify Safetensors or any
application-specific migration.

Related file-loader findings in one file are grouped for display, with every
original location and its evidence retained. Every member retains its own
confidence and verification status; no group-wide verification is inferred.
JSON/SARIF findings and scoring retain the individual observations.

The version changes invalidate results cached before file-input analysis.
