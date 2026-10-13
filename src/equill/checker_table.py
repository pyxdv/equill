"""Loader for the Cppcheck checker-id -> ISO/IEC 25010 table.

quill's ``docs/PHASE2_IDEAS.md`` 5.1c found that Cppcheck's quality signal sits in the
checker id, not the CWE: 76 % of its findings carry CWE-398, a category the
CWE List itself marks prohibited for mapping, and CISQ (CWE view 1305) labels
5.3 % of them. ``data/cppcheck_checker_iso.csv`` therefore keys on the
checker id: one ISO characteristic/sub-characteristic per id, a prior class
(BUG / QUALITY / NOISE / GATE, ``equill.schema.EvidenceClass``) and a
one-sentence rationale. This module loads and validates that table for the
pipeline (``equill scan --scanner cppcheck``).

The table was drafted by one reader from five code bases (5.1d) and its priors
checked against the source (5.1b, 5.1d) but not yet labelled by a second
annotator; a report built on it inherits that status.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from equill.schema import EVIDENCE_CLASSES, ISO_SUBCHARACTERISTICS

DEFAULT_CHECKER_CSV = (
    Path(__file__).resolve().parent / "data" / "cppcheck_checker_iso.csv"
)
# Where the default resolves when the working directory is not the repository
# root: the table shipped two levels above this package, so a user can scan
# their own project from its directory without passing --checker-table.
_SHIPPED_CHECKER_CSV = Path(__file__).resolve().parents[2] / DEFAULT_CHECKER_CSV


def resolve_checker_csv(csv_path: Path = DEFAULT_CHECKER_CSV) -> Path:
    """``csv_path`` as given, unless it is the (relative) default and absent
    from the working directory, in which case the shipped copy."""
    csv_path = Path(csv_path)
    if csv_path == DEFAULT_CHECKER_CSV and not csv_path.exists() and _SHIPPED_CHECKER_CSV.exists():
        return _SHIPPED_CHECKER_CSV
    return csv_path


@dataclass(frozen=True)
class CheckerEntry:
    checker_id: str
    iso_char: str
    iso_sub: str
    evidence_class: str
    cwe: str | None = None
    rationale: str = ""


def _check_pair(char: str, sub: str, where: str) -> None:
    if sub not in ISO_SUBCHARACTERISTICS.get(char, ()):
        raise ValueError(f"{where}: {char}/{sub} is not an ISO/IEC 25010:2011 pair")


def load_checker_table(csv_path: Path = DEFAULT_CHECKER_CSV) -> dict[str, CheckerEntry]:
    """Load the checker-id table keyed by checker id.

    Every row must name a valid ISO/IEC 25010:2011 pair and a known class, and
    no checker id may appear twice: a malformed table raises ValueError rather
    than silently mapping a finding to a label the schema would later reject.
    """
    out: dict[str, CheckerEntry] = {}
    with resolve_checker_csv(csv_path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cid = (row.get("checker_id") or "").strip()
            if not cid:
                continue
            if cid in out:
                raise ValueError(f"{cid}: duplicate row")
            char = (row.get("iso_char") or "").strip()
            sub = (row.get("iso_sub") or "").strip()
            _check_pair(char, sub, cid)
            cls = (row.get("class_prior") or "").strip()
            if cls not in EVIDENCE_CLASSES:
                raise ValueError(f"{cid}: class_prior {cls!r} is not one of {EVIDENCE_CLASSES}")
            cwe = (row.get("cwe") or "").strip()
            out[cid] = CheckerEntry(
                checker_id=cid,
                iso_char=char,
                iso_sub=sub,
                evidence_class=cls,
                cwe=f"CWE-{cwe}" if cwe else None,
                rationale=(row.get("rationale") or "").strip(),
            )
    return out


__all__ = ["DEFAULT_CHECKER_CSV", "CheckerEntry", "load_checker_table", "resolve_checker_csv"]
