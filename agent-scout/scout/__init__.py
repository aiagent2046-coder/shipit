"""agent-scout: autonomous external security scout.

Modes:
  passive (default)  OSINT + public artifacts only. GET/HEAD only. No exploitation.
  active  (manual)   Full engine + DB access against a target. Contract required.

The drydock (shipit) audit engine is consumed as a library: scout never
reimplements vulnerability matching, it feeds public artifacts into it.
"""
__version__ = "0.1.0"
