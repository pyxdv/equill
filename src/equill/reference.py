"""Loader for the curated CWE -> ISO/IEC 25010 reference table.

``data/cwe_to_iso25010.csv`` is quill's curated reference table, the ground
truth of its evaluation and the deterministic "lookup" arm of its ablation.
equill maps with it directly: one CWE, one characteristic and
sub-characteristic, confidence 1.0, the table's rationale. It ships inside the
package, so the default path works from any working directory.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REFERENCE_CSV = Path(__file__).resolve().parent / "data" / "cwe_to_iso25010.csv"


@dataclass(frozen=True)
class ReferenceEntry:
    cwe_id: str
    iso_char: str
    iso_sub: str
    rationale: str = ""


def load_reference_table(csv_path: Path = DEFAULT_REFERENCE_CSV) -> dict[str, ReferenceEntry]:
    """Load the CWE -> ISO 25010 reference table keyed by CWE id.

    Tolerates the absence of the optional ``rationale`` column. Rows whose
    ``cwe_id`` is blank are skipped. Later rows override earlier duplicates.
    """
    out: dict[str, ReferenceEntry] = {}
    with Path(csv_path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cwe = (row.get("cwe_id") or "").strip()
            if not cwe:
                continue
            out[cwe] = ReferenceEntry(
                cwe_id=cwe,
                iso_char=(row.get("iso_char") or "").strip(),
                iso_sub=(row.get("iso_sub") or "").strip(),
                rationale=(row.get("rationale") or "").strip(),
            )
    return out


__all__ = ["DEFAULT_REFERENCE_CSV", "ReferenceEntry", "load_reference_table"]
