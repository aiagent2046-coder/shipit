#!/usr/bin/env python3
"""Run the pinned Cumora restoration experiment in disposable Docker services."""

import sys
from pathlib import Path

# Support execution by absolute path from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.contracts.cumora_experiment.run import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
