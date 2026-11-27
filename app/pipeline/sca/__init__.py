"""Software composition analysis: what the dependencies themselves are known for.

Modules:

    lockfiles   resolve (ecosystem, name, version) from the archive's own
                lockfiles -- offline, deterministic, no policy
    osv         ask the OSV database about those versions
    stage       turn the answers into findings, and never let an unreachable
                database fail an audit

Nothing here is wired into run_static_scan on purpose: that stage is offline
and cached by archive digest, and these findings depend on when they were
asked. See app/sca/stage.py.
"""
