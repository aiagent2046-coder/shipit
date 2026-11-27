"""Bounded archive-local Git ignore evaluation, with no Git runtime dependency.

Global excludes are unobservable. Ignored parent directories cannot be restored
by rules for their children. Glob matching uses dynamic programming rather than
backtracking regexes, so hostile patterns do not stall the browser worker.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

_MAX_BYTES = 256 * 1024
_MAX_RULES = 2048
_MAX_PATTERN = 1024
_MAX_PATH = 4096
_MAX_WORK = 2_000_000


@lru_cache(maxsize=2048)
def _tokens(pattern: str) -> tuple:
    tokens, i = [], 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            i += 1
            tokens.append(("literal", pattern[i]))
        elif char == "*":
            if not tokens or tokens[-1][0] != "star":
                tokens.append(("star", None))
        elif char == "?":
            tokens.append(("any", None))
        elif char == "[":
            end = i + 1
            if end < len(pattern) and pattern[end] in "!^":
                end += 1
            if end < len(pattern) and pattern[end] == "]":
                end += 1
            while end < len(pattern) and pattern[end] != "]":
                end += 1
            if end < len(pattern):
                body = pattern[i + 1:end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                elif body.startswith("^"):
                    body = "\\" + body
                try:
                    tokens.append(("class", re.compile("[" + body + "]")))
                except re.error:
                    tokens.append(("literal", "["))
                else:
                    i = end
            else:
                tokens.append(("literal", "["))
        else:
            tokens.append(("literal", char))
        i += 1
    return tuple(tokens)


def _segment(pattern: str, value: str) -> bool:
    if not any(char in pattern for char in "*?[\\"):
        return pattern == value
    positions = {0}
    for kind, data in _tokens(pattern):
        if kind == "star":
            positions = set(range(min(positions), len(value) + 1)) if positions else set()
        else:
            positions = {p + 1 for p in positions if p < len(value) and (
                kind == "any" or (kind == "literal" and value[p] == data)
                or (kind == "class" and data.fullmatch(value[p])))}
        if not positions:
            return False
    return len(value) in positions


def _match(pattern: str, value: str, anchored: bool) -> bool:
    if not anchored:
        return _segment(pattern, value.rsplit("/", 1)[-1])
    parts = value.split("/")
    patterns = pattern.split("/")
    positions = {0}
    for index, part in enumerate(patterns):
        if len(part) >= 2 and set(part) == {"*"}:
            # A terminal /** matches descendants, not the named directory itself.
            start = min(positions) + (index == len(patterns) - 1) if positions else len(parts) + 1
            positions = set(range(start, len(parts) + 1))
        else:
            positions = {p + 1 for p in positions if p < len(parts) and _segment(part, parts[p])}
        if not positions:
            return False
    return len(parts) in positions


@dataclass(frozen=True)
class _Rule:
    pattern: str
    anchored: bool
    negated: bool
    directory: bool


def _rules(body: str) -> tuple[list[_Rule], bool]:
    rules = []
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if len(line) > _MAX_PATTERN or "[:" in line:
            return rules, False
        while line.endswith(" "):
            slash_count = len(line[:-1]) - len(line[:-1].rstrip("\\"))
            if slash_count % 2:
                break
            line = line[:-1]
        if not line or line.startswith("#"):
            continue
        if len(line) > _MAX_PATTERN or len(rules) >= _MAX_RULES:
            return rules, False
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        directory = line.endswith("/")
        if directory:
            line = line[:-1]
        anchored = "/" in line
        line = line.removeprefix("/")
        if line:
            rules.append(_Rule(line, anchored, negated, directory))
    return rules, True


class ArchiveGitIgnore:
    def __init__(self, files: dict[str, str]):
        self.rules = {}
        self.complete = True
        self.remaining_work = _MAX_WORK
        total_bytes, total_rules = 0, 0
        for path, body in files.items():
            if path.rsplit("/", 1)[-1] != ".gitignore":
                continue
            total_bytes += len(body.encode("utf-8"))
            if total_bytes > _MAX_BYTES:
                self.complete = False
                break
            rules, complete = _rules(body)
            total_rules += len(rules)
            self.complete &= complete
            if total_rules > _MAX_RULES:
                self.complete = False
                break
            self.rules[path.rpartition("/")[0]] = rules

    def ignores(self, path: str) -> bool:
        """Whether repository rules establish protection for an untracked file.

        Incomplete input cannot prove protection: a skipped negation could
        overturn any earlier match. Callers must surface ``complete=False``.
        """
        if not self.complete or len(path) > _MAX_PATH:
            return False
        parts = path.split("/")
        for index in range(len(parts)):
            candidate = "/".join(parts[:index + 1])
            directory = index < len(parts) - 1
            ignored = False
            for depth in range(index + 1):
                base = "/".join(parts[:depth])
                relative = candidate[len(base) + 1:] if base else candidate
                for rule in self.rules.get(base, ()):
                    self.remaining_work -= max(1, len(rule.pattern)) * max(1, len(relative))
                    if self.remaining_work < 0:
                        self.complete = False
                        return False
                    if (not rule.directory or directory) and _match(rule.pattern, relative, rule.anchored):
                        ignored = not rule.negated
            if ignored:
                return True
        return False
