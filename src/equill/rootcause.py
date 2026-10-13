"""Group findings into sites: one place to fix in one code base.

quill's ``docs/PHASE2_IDEAS.md`` 5.1b found that one defect can produce many findings
(one unchecked ``malloc`` before its ``if (buf)`` gave seven CWE-476 reports),
so a per-characteristic finding count overstates the burden. This is the
*site* level of the Phase 2 root-cause analysis, ported so ``equill.score``
can report sites next to findings; its clone-family level, which needs the
source text of every flagged line, is not ported.

Findings are merged with a union-find, one rule at a time:

* ``same-line``: same file, line and checker family;
* ``shared-anchor``: for the null-check family only, a shared secondary
  location, because Cppcheck points every such report at the one redundant
  condition they share. Other checkers' secondary locations are parent
  declarations, which independent sites can share, so they are not used;
* ``same-entity``: for class-scoped checkers, the same family and the same
  class or member named in the message (a header declaration and its
  definition; ``noCopyConstructor`` with ``noOperatorEq`` on one class).

Semgrep findings have one location and no checker family, so for them only
``same-line`` can fire: two rules on one line stay two sites, as before.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable

from equill.schema import Finding

FAMILY: dict[str, str] = {
    "cppcheck.nullPointerRedundantCheck": "null-check",
    "cppcheck.nullPointerArithmeticRedundantCheck": "null-check",
    "cppcheck.noCopyConstructor": "rule-of-three",
    "cppcheck.noOperatorEq": "rule-of-three",
}
# Families whose secondary location is the statement at fault.
ANCHOR_IS_CAUSE: frozenset[str] = frozenset({"null-check"})
# Checkers whose message names the class or member the finding is about.
CLASS_SCOPED: frozenset[str] = frozenset(
    {
        "cppcheck.duplInheritedMember",
        "cppcheck.noCopyConstructor",
        "cppcheck.noOperatorEq",
        "cppcheck.noExplicitConstructor",
        "cppcheck.uninitMemberVar",
    }
)
_QUOTED = re.compile(r"'([^']+)'")
_TEMPLATE_ARGS = re.compile(r"\s*<[^<>]*>")


def family(rule_id: str) -> str:
    return FAMILY.get(rule_id, rule_id)


def entity(message: str) -> tuple[str, ...]:
    """Quoted names in a message, template arguments dropped."""
    return tuple(_TEMPLATE_ARGS.sub("", q).strip() for q in _QUOTED.findall(message))


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[max(ra, rb)] = min(ra, rb)
        return True


def _same_line_keys(f: Finding) -> Iterable[tuple]:
    yield ("same-line", f.file, f.line, family(f.rule_id))


def _anchor_keys(f: Finding) -> Iterable[tuple]:
    fam = family(f.rule_id)
    if fam in ANCHOR_IS_CAUSE:
        for anchor in f.related_locations:
            yield ("shared-anchor", fam, anchor)


def _entity_keys(f: Finding) -> Iterable[tuple]:
    if f.rule_id in CLASS_SCOPED:
        ent = entity(f.message)
        if f.rule_id in ("cppcheck.noCopyConstructor", "cppcheck.noOperatorEq"):
            ent = ent[:1]  # the class; the rest of the message differs between the two
        if ent:
            yield ("same-entity", family(f.rule_id), ent)


_RULES: tuple[tuple[str, Callable[[Finding], Iterable[tuple]]], ...] = (
    ("same-line", _same_line_keys),
    ("shared-anchor", _anchor_keys),
    ("same-entity", _entity_keys),
)


def group_sites(findings: list[Finding]) -> tuple[list[int], Counter]:
    """Return a site id per finding (the index of the site's first finding)
    and the number of merges each rule made."""
    uf = _UnionFind(len(findings))
    log: Counter = Counter()
    for rule, keyfn in _RULES:
        first: dict[tuple, int] = {}
        for i, f in enumerate(findings):
            for key in keyfn(f):
                if key in first:
                    if uf.union(first[key], i):
                        log[rule] += 1
                else:
                    first[key] = i
    return [uf.find(i) for i in range(len(findings))], log


def count_sites(findings: list[Finding], indices: Iterable[int] | None = None) -> int:
    """Number of distinct sites among ``findings`` (or among ``indices`` of it)."""
    sites, _ = group_sites(findings)
    chosen = range(len(findings)) if indices is None else indices
    return len({sites[i] for i in chosen})


__all__ = ["ANCHOR_IS_CAUSE", "CLASS_SCOPED", "FAMILY", "count_sites", "entity", "family", "group_sites"]
