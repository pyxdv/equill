"""`equill summary`: the Markdown page and the quality gate CI acts on.

Every number on the page comes from ``equill.score``; these tests pin that the
page shows it, that the gate counts actionable findings only, and that the gate
exits 1 only after the page is written.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from equill.cli import app
from equill.schema import Finding, Mapping, Report
from equill.score import score_report
from equill.summary import evaluate_gate, parse_characteristics, render_summary

runner = CliRunner()


def _finding(file: str, cwe: str, severity: str = "WARNING", cls: str | None = None) -> Finding:
    return Finding(
        rule_id=f"rule.{cwe}",
        file=file,
        line=1,
        cwe=[cwe],
        severity=severity,  # type: ignore[arg-type]
        message="m",
        snippet="s",
        evidence_class=cls,  # type: ignore[arg-type]
    )


def _mapping(i: int, char: str, sub: str) -> Mapping:
    return Mapping(
        finding_id=f"f-{i}",
        owasp=[],
        cwe=[],
        iso_char=char,  # type: ignore[arg-type]
        iso_sub=sub,
        confidence=1.0,
        rationale="r",
        model="lookup",
    )


def _report() -> Report:
    findings = [
        _finding("app/a.py", "CWE-89", "ERROR"),
        _finding("app/a.py", "CWE-79"),
        _finding("app/b|c.py", "CWE-400"),
        _finding("lib/x.c", "CWE-398", cls="NOISE"),
        _finding("app/d.py", "CWE-601"),  # unmapped
    ]
    mappings = [
        _mapping(0, "security", "integrity"),
        _mapping(1, "security", "integrity"),
        _mapping(2, "reliability", "availability"),
        _mapping(3, "maintainability", "analysability"),
    ]
    return Report(
        benchmark="demo",
        commit_sha="0123456789abcdef",
        findings=findings,
        mappings=mappings,
        coverage=0.8,
        mean_confidence=1.0,
    )


def test_page_carries_the_scores_numbers():
    report = _report()
    page = render_summary(report)
    scores = score_report(report)
    assert scores.actionable_findings == 3
    assert "5 scanner findings · 4 mapped to ISO/IEC 25010 (80%)" in page
    assert "**3 actionable**" in page
    assert "1 noise · 0 gated" in page
    assert "commit `0123456789ab`" in page
    assert "| Security | 2 | 2 | 1 / 1 / 0 | integrity (2) |" in page
    assert "| Reliability | 1 | 1 |" in page
    # NOISE-only characteristic: listed, but with no quality index.
    assert "| Maintainability | 0 | 0 | 0 / 1 / 0 | analysability (1) | — |" in page
    assert (
        "No evidence for: Compatibility, Functional suitability, Performance efficiency, "
        "Portability, Usability." in page
    )
    # The construct note travels with the page.
    assert "not an ISO/IEC 25040 quality" in page


def test_hotspots_rank_files_and_skip_noise():
    page = render_summary(_report())
    hot = page.split("### Hotspots", 1)[1].split("###", 1)[0]
    rows = [ln for ln in hot.splitlines() if ln.startswith("| `")]
    assert rows[0] == "| `app/a.py` | 2 | security 2 |"
    # A pipe in a path must not break the table.
    assert "| `app/b\\|c.py` | 1 | reliability 1 |" in rows
    assert not any("lib/x.c" in r for r in rows)


def test_unmapped_findings_are_listed_by_cwe():
    page = render_summary(_report())
    assert "### Unmapped findings (1)" in page
    assert "| CWE-601 | 1 |" in page


def test_unmapped_cppcheck_findings_are_listed_by_checker_id():
    finding = Finding(
        rule_id="someNewChecker", file="a.c", line=3, cwe=["CWE-398"],
        severity="WARNING", message="m", snippet="",
    )
    report = Report(benchmark="c", commit_sha="", findings=[finding], mappings=[],
                    coverage=0.0, mean_confidence=0.0, scanner="cppcheck")
    page = render_summary(report)
    assert "| Checker id | Findings |" in page
    assert "| someNewChecker | 1 |" in page
    assert "`--checker-table`" in page
    assert "CWE-398" not in page and "--mapper-mode" not in page


def test_unmapped_note_names_the_cwe_table_for_semgrep():
    page = render_summary(_report())
    assert "primary CWE has no row in the CWE table (`--reference`)" in page
    assert "--mapper-mode" not in page


def test_empty_report_renders():
    report = Report(benchmark="e", commit_sha="", findings=[], mappings=[],
                    coverage=0.0, mean_confidence=0.0)
    page = render_summary(report)
    assert "No findings." in page
    assert "Hotspots" not in page and "Unmapped" not in page


def test_gate_counts_actionable_findings_only():
    scores = score_report(_report())
    assert evaluate_gate(scores).passed
    assert not evaluate_gate(scores).configured
    # Maintainability holds only a NOISE finding: it cannot fail the gate.
    assert evaluate_gate(scores, fail_on=["maintainability"]).passed
    failed = evaluate_gate(scores, fail_on=["security", "reliability"])
    assert failed.failures == [
        "Security: 2 actionable findings (2 sites)",
        "Reliability: 1 actionable finding (1 site)",
    ]
    assert evaluate_gate(scores, max_actionable=3).passed
    over = evaluate_gate(scores, max_actionable=2)
    assert over.failures == ["3 actionable findings exceed the limit of 2"]


def test_parse_characteristics():
    assert parse_characteristics("") == []
    assert parse_characteristics("Security, functional-suitability,security") == [
        "security", "functional_suitability",
    ]
    assert len(parse_characteristics("all")) == 8
    with pytest.raises(ValueError, match="secruity"):
        parse_characteristics("secruity")


def test_cli_writes_page_then_exits_1_on_failed_gate(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(_report().model_dump_json(), encoding="utf-8")
    out = tmp_path / "summary.md"

    ok = runner.invoke(app, ["summary", str(report_path), "-o", str(out),
                             "--fail-on", "usability"])
    assert ok.exit_code == 0, ok.output
    assert "Quality gate: passed" in out.read_text(encoding="utf-8")

    out.unlink()
    bad = runner.invoke(app, ["summary", str(report_path), "-o", str(out),
                              "--fail-on", "security"])
    assert bad.exit_code == 1
    assert "Quality gate: failed" in out.read_text(encoding="utf-8")
    assert "quality gate failed: Security" in bad.output


def test_cli_prints_to_stdout_and_rejects_typos(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(_report().model_dump_json(), encoding="utf-8")
    shown = runner.invoke(app, ["summary", str(report_path)])
    assert shown.exit_code == 0
    assert shown.output.startswith("## equill")
    assert "Quality gate" not in shown.output

    typo = runner.invoke(app, ["summary", str(report_path), "--fail-on", "secruity"])
    assert typo.exit_code == 2
