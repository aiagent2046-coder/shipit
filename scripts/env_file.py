"""Read a deployment's own env file, the way the deployment reads it.

WHY THIS EXISTS AT ALL. Several operator commands need values that live in
/opt/shipit/.env and nowhere else. The obvious way to give a command those
values is the one an operator reaches for:

    set -a; . /opt/shipit/.env; set +a

On this deployment that silently truncated a 14-character SMTP password at a
`$` and cost an afternoon spent debugging a mail server that was working
correctly. bash expands `$` inside an unquoted value, and `.env` also holds a
bank name containing «», an address containing spaces, and a payment
provider's secret key. A step that needs a dangerous incantation to work is a
step that will get one, so the steps read the file themselves instead.

THE READER IS BORROWED, NOT REWRITTEN. read_env_file lives in
deploy/scripts/validate-production-env.py and already handles this file's
quoting. A second parser here would be a second set of quoting rules to keep
in step, and the failure mode of getting that wrong is a value silently
truncated at the first special character -- the same failure in a new place.
That script is not importable by name (it has a hyphen and a .py suffix it
does not wear as a module), hence importlib.

NOTHING FROM THE FILE IS EVER PRINTED OR RAISED. Everything these callers
print lands in a deploy log or the journal, and a parse failure is exactly the
moment a naive implementation would include the offending line. Failure
returns an empty mapping and lets the caller's own message stand.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

DEFAULT_ENV_FILE = "/opt/shipit/.env"

# Same default and same override as deploy/scripts/deploy-production.sh, so
# every command on a host agrees about which file is in charge.
ENV_FILE_VARIABLE = "SHIPIT_ENV_FILE"

_VALIDATOR = (
    Path(__file__).resolve().parent.parent
    / "deploy" / "scripts" / "validate-production-env.py"
)


def env_file_path() -> Path:
    """Where this deployment keeps its environment."""
    return Path(os.environ.get(ENV_FILE_VARIABLE, DEFAULT_ENV_FILE))


def read_values(path: Path) -> dict[str, str]:
    """Everything in `path`, or an empty mapping when there is nothing to read.

    Returns {} rather than raising for anything unreadable: a missing env file
    is the ordinary case on a developer's machine, and the caller's error
    message is more useful than this one's.
    """
    if not path.is_file() or not _VALIDATOR.is_file():
        return {}

    spec = importlib.util.spec_from_file_location(
        "shipit_env_file_reader", _VALIDATOR)
    if spec is None or spec.loader is None:
        return {}
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        reader = getattr(module, "read_env_file", None)
        if not callable(reader):
            return {}
        values = reader(path)
    except Exception:  # noqa: BLE001
        # Never explain: an exception raised while parsing an env file has a
        # good chance of quoting a line of it.
        return {}

    if not isinstance(values, dict):
        return {}
    return {str(k): str(v) for k, v in values.items()}


def fill_environment(prefix: str, path: Path | None = None) -> Path:
    """Put the file's `prefix`* values into os.environ, and say which file.

    THE ENVIRONMENT WINS. A variable already set is left alone, which is
    deliberately the opposite of deploy/scripts/check_release_migrations.py.
    That gate runs only on the production host, where the file IS the
    authority. These commands run anywhere -- a laptop, CI, a production
    shell -- and if the file won, an engineer who had deliberately pointed a
    variable somewhere else would silently act on production instead.

    Returns the path consulted so the caller can name it, which is the one
    piece of information an operator staring at unexpected settings needs.
    """
    path = env_file_path() if path is None else path
    for key, value in read_values(path).items():
        if key.startswith(prefix) and not os.environ.get(key):
            os.environ[key] = value
    return path
