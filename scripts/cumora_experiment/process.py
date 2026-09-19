"""Bound subprocess groups and propagate cancellation through the experiment."""

from contextlib import ExitStack, contextmanager
import os
import signal
import subprocess


class Cancelled(KeyboardInterrupt):
    """The operator requested cancellation, rather than a stage timing out."""


@contextmanager
def cancellation_signals(ignore=False):
    def cancel(signum, frame):
        raise Cancelled(f"cancelled by signal {signum}")

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, signal.SIG_IGN if ignore else cancel)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def stop_group(process, grace):
    """Always kill surviving descendants, even when their parent exits first."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def bounded(args, seconds, path, stderr_path=None, *, cwd=None, grace=3):
    with ExitStack() as stack:
        log = stack.enter_context(path.open("wb"))
        errors = stack.enter_context(stderr_path.open("wb")) if stderr_path else subprocess.STDOUT
        process = subprocess.Popen(args, stdout=log, stderr=errors, start_new_session=True, cwd=cwd)
        try:
            return process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            with cancellation_signals(ignore=True):
                stop_group(process, grace)
            return 124
        except KeyboardInterrupt:
            with cancellation_signals(ignore=True):
                stop_group(process, grace)
            raise
