"""`python -m app.worker` -- the ExecStart of shipit-audit-worker.service."""

import sys

from app.worker.main import main

sys.exit(main())
