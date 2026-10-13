from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from equill.rootcause import group_sites
from equill.schema import ACTIONABLE_CLASSES, ISO_SUBCHARACTERISTICS, Report, Severity

# Severity weights for the burden aggregate. Ordinal, not interval-scaled:
# the 1/2/3 ladder encodes only Semgrep's INFO < WARNING < ERROR ordering.
SEVERITY_WEIGHT: dict[Severity, float] = {"INFO": 1.0, "WARNING": 2.0, "ERROR": 3.0}

# One-line construct statement embedded in every scores artifact so the JSON
# cannot be read as a validated ISO 25040 quality measurement.
CONSTRUCT_NOTE = (
    "Descriptive aggregate of mapped SAST findings, not an ISO/IEC 25040 quality "
    "measurement. burden = sum(severity_weight * confidence) over actionable "
    "findings mapped to the characteristic; quality_index = 1 / (1 + burden). "
    "A finding is actionable when its checker class is BUG, QUALITY or unknown; "
    "NOISE (true but stylistic) and GATE (known-false pattern) findings are "
    "counted in n_noise / n_gated and excluded from burden. n_sites is the number "
    "of distinct places to fix among the actionable findings (same rule or checker "
    "family on the same line, shared null-check anchor, or same named class merge "
    "into one site). Not normalized by "
    "repository size: comparable across runs of the same repository, not across "
    "repositories. A characteristic with no actionable mapped findings has "
    "quality_index null (absence of evidence, not evidence of quality)."
)


class CharacteristicScore(BaseModel):
    characteristic: str
    n_findings: int = Field(ge=0)
    severity_counts: dict[Severity, int]
    sub_counts: dict[str, int]
    mean_confidence: float = Field(ge=0.0, le=1.0)
    burden: float = Field(ge=0.0)
    # None when no actionable finding maps here: unmeasured, not clean.
    quality_index: float | None = Field(default=None, ge=0.0, le=1.0)
    # The class split (equill.schema.EvidenceClass). For a Semgrep report every
    # finding is unclassified, so n_actionable == n_findings and the other two
    # are 0: the values every scores artifact before these fields carried.
    n_actionable: int = Field(default=0, ge=0)
    n_noise: int = Field(default=0, ge=0)
    n_gated: int = Field(default=0, ge=0)
    # Distinct sites (equill.rootcause) among the actionable findings.
    n_sites: int = Field(default=0, ge=0)


class ProductQualityScores(BaseModel):
    benchmark: str
    commit_sha: str
    total_findings: int = Field(ge=0)
    mapped_findings: int = Field(ge=0)
    uncovered_findings: int = Field(ge=0)
    # The funnel over mapped findings: actionable + noise + gated == mapped.
    # actionable_sites is the number of distinct places to fix among the
    # actionable findings, across all characteristics.
    actionable_findings: int = Field(default=0, ge=0)
    noise_findings: int = Field(default=0, ge=0)
    gated_findings: int = Field(default=0, ge=0)
    actionable_sites: int = Field(default=0, ge=0)
    characteristics: list[CharacteristicScore]
    construct_note: str = CONSTRUCT_NOTE


def score_report(report: Report) -> ProductQualityScores:
    """Aggregate per-finding mappings into per-characteristic quality evidence.

    The aggregation step PIQUE-style consumers expect: each ISO/IEC 25010
    characteristic gets a finding count, severity breakdown, sub-characteristic
    distribution, a confidence-weighted severity burden, and a monotone
    quality_index in (0, 1]. All eight characteristics are always emitted so a
    reader sees which ones the finding set leaves unmeasured.
    """
    sites, _merges = group_sites(report.findings)

    # (finding index or None, severity, confidence, sub, evidence class)
    per_char: dict[str, list[tuple[int | None, Severity, float, str, str | None]]] = {
        char: [] for char in ISO_SUBCHARACTERISTICS
    }
    for mapping in report.mappings:
        index: int | None = None
        if mapping.finding_id.startswith("f-"):
            try:
                index = int(mapping.finding_id[2:])
            except ValueError:
                index = None
        finding = (
            report.findings[index] if index is not None and 0 <= index < len(report.findings)
            else None
        )
        severity: Severity = finding.severity if finding is not None else "WARNING"
        cls = finding.evidence_class if finding is not None else None
        per_char[mapping.iso_char].append(
            (index if finding is not None else None, severity, mapping.confidence,
             mapping.iso_sub, cls)
        )

    characteristics: list[CharacteristicScore] = []
    all_sites: set[int] = set()
    all_unsited = 0
    for char in ISO_SUBCHARACTERISTICS:
        entries = per_char[char]
        n = len(entries)
        severity_counts: dict[Severity, int] = {"INFO": 0, "WARNING": 0, "ERROR": 0}
        sub_counts: dict[str, int] = {}
        burden = 0.0
        n_actionable = n_noise = n_gated = 0
        site_ids: set[int] = set()
        unsited = 0  # actionable mappings with no resolvable finding: one site each
        for index, severity, confidence, sub, cls in entries:
            severity_counts[severity] += 1
            sub_counts[sub] = sub_counts.get(sub, 0) + 1
            if cls == "NOISE":
                n_noise += 1
                continue
            if cls == "GATE":
                n_gated += 1
                continue
            # BUG, QUALITY, or unclassified (every Semgrep finding): counted.
            assert cls is None or cls in ACTIONABLE_CLASSES
            n_actionable += 1
            burden += SEVERITY_WEIGHT[severity] * confidence
            if index is None:
                unsited += 1
            else:
                site_ids.add(sites[index])
        characteristics.append(
            CharacteristicScore(
                characteristic=char,
                n_findings=n,
                severity_counts=severity_counts,
                sub_counts=sub_counts,
                mean_confidence=(sum(e[2] for e in entries) / n) if n else 0.0,
                burden=burden,
                quality_index=(1.0 / (1.0 + burden)) if n_actionable else None,
                n_actionable=n_actionable,
                n_noise=n_noise,
                n_gated=n_gated,
                n_sites=len(site_ids) + unsited,
            )
        )
        all_sites |= site_ids
        all_unsited += unsited

    return ProductQualityScores(
        benchmark=report.benchmark,
        commit_sha=report.commit_sha,
        total_findings=len(report.findings),
        mapped_findings=len(report.mappings),
        uncovered_findings=len(report.findings) - len(report.mappings),
        actionable_findings=sum(c.n_actionable for c in characteristics),
        noise_findings=sum(c.n_noise for c in characteristics),
        gated_findings=sum(c.n_gated for c in characteristics),
        actionable_sites=len(all_sites) + all_unsited,
        characteristics=characteristics,
    )


def write_scores(report: Report, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    scores = score_report(report)
    output_path.write_text(
        json.dumps(scores.model_dump(), indent=2), encoding="utf-8"
    )
    return output_path


__all__ = [
    "CONSTRUCT_NOTE",
    "SEVERITY_WEIGHT",
    "CharacteristicScore",
    "ProductQualityScores",
    "score_report",
    "write_scores",
]
