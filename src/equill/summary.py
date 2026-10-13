"""Markdown summary of a report, and an optional quality gate over it.

``report.json`` and ``scores.json`` are written for machines and for the
research tables. A team adopting equill in CI reads neither: it reads the job
summary page, a pull-request comment, or the line that says why the build went
red. This module renders the same evidence ``equill.score`` computes as one
Markdown page (GitHub-flavoured, so it pastes into ``$GITHUB_STEP_SUMMARY`` or a
PR comment unchanged) and evaluates a gate over it.

Nothing here computes a new number. Every count comes from ``score_report``, so
the page and ``scores.json`` cannot disagree, and the construct note travels
with the page: the aggregate is descriptive evidence, not an ISO/IEC 25040
quality measurement.

The gate fails on *actionable* findings only (``equill.score``'s funnel), so a
Cppcheck report's NOISE and GATE classes never break a build, and every
Semgrep finding, which carries no class, counts. An unmapped finding cannot
fail it either: equill has no characteristic to blame it on, and the page lists
those findings' keys (CWE, or checker id for Cppcheck) instead so the table
can be extended.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from equill.cppcheck import checker_id
from equill.schema import ACTIONABLE_CLASSES, ISO_SUBCHARACTERISTICS, Report
from equill.score import CONSTRUCT_NOTE, ProductQualityScores, score_report

CHARACTERISTIC_LABELS: dict[str, str] = {
    "functional_suitability": "Functional suitability",
    "performance_efficiency": "Performance efficiency",
    "compatibility": "Compatibility",
    "usability": "Usability",
    "reliability": "Reliability",
    "security": "Security",
    "maintainability": "Maintainability",
    "portability": "Portability",
}


@dataclass(frozen=True)
class GateResult:
    """Outcome of the quality gate. ``passed`` is True when nothing tripped it,
    which includes the case where no condition was configured."""

    failures: list[str] = field(default_factory=list)
    configured: bool = False

    @property
    def passed(self) -> bool:
        return not self.failures


def parse_characteristics(value: str | None) -> list[str]:
    """Parse a comma-separated characteristic list (``security,reliability``).

    Accepts the labels as written in the report (``functional_suitability``)
    and their spaced or hyphenated forms, case-insensitively. ``all`` expands
    to every characteristic. Raises ValueError naming any unknown entry, so a
    typo cannot silently disable a gate.
    """
    if not value:
        return []
    out: list[str] = []
    unknown: list[str] = []
    for raw in value.split(","):
        name = raw.strip().lower().replace(" ", "_").replace("-", "_")
        if not name:
            continue
        if name == "all":
            return list(ISO_SUBCHARACTERISTICS)
        if name in ISO_SUBCHARACTERISTICS:
            if name not in out:
                out.append(name)
        else:
            unknown.append(raw.strip())
    if unknown:
        raise ValueError(
            f"unknown ISO/IEC 25010 characteristic(s): {', '.join(unknown)}; "
            f"expected any of {', '.join(ISO_SUBCHARACTERISTICS)} or 'all'"
        )
    return out


def evaluate_gate(
    scores: ProductQualityScores,
    fail_on: list[str] | None = None,
    max_actionable: int | None = None,
) -> GateResult:
    """Apply the gate to a scored report.

    ``fail_on``: fail when any listed characteristic has an actionable finding.
    ``max_actionable``: fail when the report's actionable findings, across all
    characteristics, exceed this number (0 means "none allowed").
    Both may be given; every condition that trips is reported.
    """
    fail_on = fail_on or []
    failures: list[str] = []
    by_char = {c.characteristic: c for c in scores.characteristics}
    for char in fail_on:
        c = by_char[char]
        if c.n_actionable:
            failures.append(
                f"{CHARACTERISTIC_LABELS[char]}: {c.n_actionable} actionable "
                f"finding{'s' if c.n_actionable != 1 else ''} "
                f"({c.n_sites} site{'s' if c.n_sites != 1 else ''})"
            )
    if max_actionable is not None and scores.actionable_findings > max_actionable:
        failures.append(
            f"{scores.actionable_findings} actionable findings exceed the limit "
            f"of {max_actionable}"
        )
    return GateResult(
        failures=failures, configured=bool(fail_on) or max_actionable is not None
    )


def _cell(text: str) -> str:
    """Make arbitrary text safe inside a Markdown table cell."""
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").strip()


def _label_sub(sub: str) -> str:
    return sub.replace("_", " ")


def _finding_index(finding_id: str) -> int | None:
    if finding_id.startswith("f-"):
        try:
            return int(finding_id[2:])
        except ValueError:
            return None
    return None


def render_summary(
    report: Report,
    gate: GateResult | None = None,
    top: int = 10,
    title: str = "equill — ISO/IEC 25010 quality evidence",
) -> str:
    """Render ``report`` as one GitHub-flavoured Markdown page."""
    scores = score_report(report)
    lines: list[str] = [f"## {title}", ""]

    meta = [f"**{_cell(report.benchmark)}**"]
    if report.commit_sha:
        meta.append(f"commit `{report.commit_sha[:12]}`")
    meta.append(f"scanner `{report.scanner}`")
    if report.rules:
        meta.append(f"rules {_cell(report.rules)}")
    models = sorted({m.model for m in report.mappings})
    if models:
        meta.append("mapper " + ", ".join(f"`{_cell(m)}`" for m in models))
    lines += [" · ".join(meta), ""]

    if gate is not None and gate.configured:
        if gate.passed:
            lines += ["**Quality gate: passed** ✅", ""]
        else:
            lines += ["**Quality gate: failed** ❌", ""]
            lines += [f"- {_cell(f)}" for f in gate.failures]
            lines.append("")

    total = scores.total_findings
    coverage = f"{scores.mapped_findings / total:.0%}" if total else "n/a"
    lines += [
        f"{total} scanner finding{'s' if total != 1 else ''} · "
        f"{scores.mapped_findings} mapped to ISO/IEC 25010 ({coverage}) · "
        f"**{scores.actionable_findings} actionable** at "
        f"**{scores.actionable_sites} site{'s' if scores.actionable_sites != 1 else ''}**"
        + (
            f" · {scores.noise_findings} noise · {scores.gated_findings} gated"
            if scores.noise_findings or scores.gated_findings
            else ""
        ),
        "",
    ]

    if total == 0:
        lines += ["No findings. Nothing to map.", ""]
    else:
        lines += [
            (
                "| Characteristic | Actionable | Sites | Error / Warning / Info | "
                "Most frequent sub-characteristic | Quality index |"
            ),
            "|---|---:|---:|:---:|---|---:|",
        ]
        ordered = sorted(
            scores.characteristics,
            key=lambda c: (-c.n_actionable, -c.n_findings, c.characteristic),
        )
        unmeasured = [
            CHARACTERISTIC_LABELS[c.characteristic] for c in ordered if c.n_findings == 0
        ]
        for c in ordered:
            if c.n_findings == 0:
                continue
            label = CHARACTERISTIC_LABELS[c.characteristic]
            sev = c.severity_counts
            top_sub = max(c.sub_counts.items(), key=lambda kv: (kv[1], kv[0]))
            qi = f"{c.quality_index:.3f}" if c.quality_index is not None else "—"
            lines.append(
                f"| {label} | {c.n_actionable} | {c.n_sites} | "
                f"{sev['ERROR']} / {sev['WARNING']} / {sev['INFO']} | "
                f"{_label_sub(top_sub[0])} ({top_sub[1]}) | {qi} |"
            )
        if not scores.mapped_findings:
            lines.append("| *(no finding mapped)* | | | | | |")
        lines.append("")
        if unmeasured:
            lines += [f"No evidence for: {', '.join(sorted(unmeasured))}.", ""]
        lines += [
            (
                "Quality index is `1 / (1 + burden)`, where burden sums severity weight × "
                "confidence over actionable findings; — means no actionable evidence "
                "(unmeasured, not clean)."
            ),
            "",
        ]

    lines += _hotspots(report, top)
    lines += _unmapped(report, top)

    lines += [
        "<details><summary>What these numbers are (and are not)</summary>",
        "",
        CONSTRUCT_NOTE,
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def _hotspots(report: Report, top: int) -> list[str]:
    """Files ranked by actionable mapped findings, with their characteristics."""
    per_file: dict[str, Counter[str]] = {}
    for mapping in report.mappings:
        index = _finding_index(mapping.finding_id)
        if index is None or not 0 <= index < len(report.findings):
            continue
        finding = report.findings[index]
        cls = finding.evidence_class
        if cls is not None and cls not in ACTIONABLE_CLASSES:
            continue
        per_file.setdefault(finding.file, Counter())[mapping.iso_char] += 1
    if not per_file or top <= 0:
        return []
    ranked = sorted(per_file.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    heading = (
        f"top {top} of {len(ranked)} files" if len(ranked) > top
        else f"{len(ranked)} file{'s' if len(ranked) != 1 else ''}"
    )
    out = [
        f"### Hotspots ({heading})",
        "",
        "| File | Actionable | Characteristics |",
        "|---|---:|---|",
    ]
    for path, chars in ranked[:top]:
        detail = ", ".join(
            f"{CHARACTERISTIC_LABELS[c].lower()} {n}" for c, n in chars.most_common()
        )
        out.append(f"| `{_cell(path)}` | {sum(chars.values())} | {detail} |")
    out.append("")
    return out


def _unmapped(report: Report, top: int) -> list[str]:
    """The keys of the findings no mapping covers: where the table needs a row.

    Semgrep/Opengrep findings are mapped by primary CWE, Cppcheck findings by
    checker id, so the page lists whichever key the user would have to add.
    """
    mapped = {
        i for m in report.mappings if (i := _finding_index(m.finding_id)) is not None
    }
    missing = [f for i, f in enumerate(report.findings) if i not in mapped]
    if not missing:
        return []
    cppcheck = report.scanner == "cppcheck"
    by_key: Counter[str] = Counter()
    for f in missing:
        if cppcheck:
            by_key[checker_id(f) or f.rule_id] += 1
        else:
            by_key[f.cwe[0] if f.cwe else f"no CWE ({f.rule_id})"] += 1
    shown = by_key.most_common(top if top > 0 else None)
    if cppcheck:
        note = (
            "No ISO/IEC 25010 mapping was produced for these: the checker id has no row "
            "in the checker table (`--checker-table`); such findings never trip the gate."
        )
        header = "| Checker id | Findings |"
    else:
        note = (
            "No ISO/IEC 25010 mapping was produced for these: the finding's primary CWE "
            "has no row in the CWE table (`--reference`); such findings never trip the gate."
        )
        header = "| CWE | Findings |"
    out = [
        f"### Unmapped findings ({len(missing)})",
        "",
        note,
        "",
        header,
        "|---|---:|",
    ]
    out += [f"| {_cell(k)} | {n} |" for k, n in shown]
    if len(by_key) > len(shown):
        out.append(f"| … {len(by_key) - len(shown)} more | |")
    out.append("")
    return out


__all__ = [
    "CHARACTERISTIC_LABELS",
    "GateResult",
    "evaluate_gate",
    "parse_characteristics",
    "render_summary",
]
