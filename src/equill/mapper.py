"""Deterministic mappers: a finding's CWE or checker id -> ISO/IEC 25010.

These are quill's lookup mappers without its LLM/RAG mapper. A finding the
table does not cover produces no mapping, so coverage stays honest: an
unmapped finding is reported as such, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from equill.checker_table import CheckerEntry
from equill.cppcheck import checker_id
from equill.reference import ReferenceEntry
from equill.schema import RATIONALE_MAX_LENGTH, Finding, Mapping


@dataclass(frozen=True)
class MappingOutcome:
    finding: Finding
    mapping: Mapping | None


@dataclass(frozen=True)
class MappingSummary:
    total: int
    covered: int
    coverage: float
    mean_confidence: float

    @classmethod
    def from_outcomes(cls, outcomes: list[MappingOutcome]) -> MappingSummary:
        total = len(outcomes)
        valid = [o.mapping for o in outcomes if o.mapping is not None]
        covered = len(valid)
        return cls(
            total=total,
            covered=covered,
            coverage=(covered / total) if total else 0.0,
            mean_confidence=(sum(m.confidence for m in valid) / covered) if covered else 0.0,
        )


def _mapping(finding: Finding, iso_char: str, iso_sub: str, rationale: str,
             model: str) -> Mapping | None:
    try:
        return Mapping(
            finding_id=model,
            owasp=finding.owasp,
            cwe=finding.cwe,
            iso_char=iso_char,  # type: ignore[arg-type]
            iso_sub=iso_sub,
            confidence=1.0,
            rationale=rationale[:RATIONALE_MAX_LENGTH],
            model=model,
            retrieved_ctx_ids=[],
        )
    except ValidationError:
        # A table row that violates the ISO 25010 char/sub schema maps nothing.
        return None


class LookupMapper:
    """Map by the finding's primary CWE through the CWE -> ISO table."""

    def __init__(self, reference: dict[str, ReferenceEntry]) -> None:
        self._reference = reference

    def map_finding(self, finding: Finding) -> MappingOutcome:
        cwe = finding.cwe[0] if finding.cwe else None
        entry = self._reference.get(cwe) if cwe else None
        if entry is None:
            return MappingOutcome(finding=finding, mapping=None)
        rationale = entry.rationale or f"Deterministic CWE->ISO 25010 lookup for {cwe}."
        return MappingOutcome(
            finding=finding,
            mapping=_mapping(finding, entry.iso_char, entry.iso_sub, rationale, "lookup"),
        )

    def map_findings(self, findings: list[Finding]) -> list[MappingOutcome]:
        return [self.map_finding(f) for f in findings]


class CheckerLookupMapper:
    """Map a Cppcheck finding by its checker id through the checker table.

    Every class is mapped, NOISE and GATE included: the class rides on the
    finding (``evidence_class``) and the scorer decides what counts.
    """

    def __init__(self, table: dict[str, CheckerEntry]) -> None:
        self._table = table

    def map_finding(self, finding: Finding) -> MappingOutcome:
        cid = checker_id(finding)
        entry = self._table.get(cid) if cid else None
        if entry is None:
            return MappingOutcome(finding=finding, mapping=None)
        rationale = entry.rationale or f"Deterministic checker-id->ISO 25010 lookup for {cid}."
        return MappingOutcome(
            finding=finding,
            mapping=_mapping(finding, entry.iso_char, entry.iso_sub, rationale,
                             "checker-lookup"),
        )

    def map_findings(self, findings: list[Finding]) -> list[MappingOutcome]:
        return [self.map_finding(f) for f in findings]


__all__ = ["CheckerLookupMapper", "LookupMapper", "MappingOutcome", "MappingSummary"]
