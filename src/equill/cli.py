from __future__ import annotations

from pathlib import Path

import typer

from equill.checker_table import DEFAULT_CHECKER_CSV
from equill.reference import DEFAULT_REFERENCE_CSV

app = typer.Typer(
    help="equill — ISO/IEC 25010 quality evidence from Semgrep/Cppcheck findings, for CI",
    no_args_is_help=True,
)


def _load(report_json: Path):
    from equill.schema import Report

    return Report.model_validate_json(report_json.read_text(encoding="utf-8"))


@app.command()
def scan(
    target: Path = typer.Argument(Path("."), help="Directory to scan"),
    output: Path = typer.Option(Path("equill-report"), "--output", "-o", help="Output dir"),
    scanner: str = typer.Option(
        "semgrep", "--scanner", envvar="EQUILL_SCANNER",
        help="semgrep | opengrep | cppcheck (the CLI must be on PATH)",
    ),
    semgrep_config: str = typer.Option(
        "p/default", "--config", help="Semgrep/Opengrep --config (registry pack or rules path)"
    ),
    scanner_output: Path | None = typer.Option(
        None, "--scanner-output",
        help="Map this recorded Semgrep JSON or Cppcheck XML instead of running the scanner.",
    ),
    name: str = typer.Option("", "--name", help="Name recorded in report.json"),
    reference: Path = typer.Option(
        DEFAULT_REFERENCE_CSV, "--reference", help="CWE -> ISO/IEC 25010 table"
    ),
    checker_table: Path = typer.Option(
        DEFAULT_CHECKER_CSV, "--checker-table", help="Cppcheck checker id -> ISO/IEC 25010 table"
    ),
    snippet_fallback: bool = typer.Option(
        False, "--snippet-fallback/--no-snippet-fallback",
        help="Fill missing snippets with the flagged source lines from the checkout.",
    ),
    exclude_tests: bool = typer.Option(
        True, "--exclude-tests/--no-exclude-tests",
        help="Cppcheck only: drop findings under test, fuzz and example paths.",
    ),
    path_exclude: str | None = typer.Option(
        None, "--path-exclude", help="Cppcheck only: regex replacing the default exclusion."
    ),
) -> None:
    """Scan, map every finding to ISO/IEC 25010, write report.json, report.sarif, scores.json."""
    from equill.pipeline import PipelineConfig, run_pipeline, write_report
    from equill.sarif import write_sarif
    from equill.schema import SCANNERS
    from equill.score import write_scores

    if scanner not in SCANNERS:
        raise typer.BadParameter(f"must be one of {', '.join(SCANNERS)}", param_hint="--scanner")
    config = PipelineConfig(
        repo_path=target,
        semgrep_config=semgrep_config,
        name=name,
        scanner=scanner,  # type: ignore[arg-type]
        scanner_output=scanner_output,
        reference_csv=reference,
        checker_table=checker_table,
        snippet_fallback=snippet_fallback,
        cppcheck_exclude_tests=exclude_tests,
        path_exclude=path_exclude,
    )
    try:
        report = run_pipeline(config)
    except (ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(code=2) from e
    typer.echo(
        f"wrote {write_report(report, output)} "
        f"({len(report.mappings)}/{len(report.findings)} mapped)"
    )
    typer.echo(f"wrote {write_sarif(report, output / 'report.sarif')}")
    typer.echo(f"wrote {write_scores(report, output / 'scores.json')}")


@app.command()
def summary(
    report_json: Path = typer.Argument(..., help="report.json from `equill scan`"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the Markdown here (default: stdout)"
    ),
    top: int = typer.Option(10, "--top", help="Rows in the hotspot and unmapped tables"),
    fail_on: str = typer.Option(
        "", "--fail-on",
        help="Comma-separated characteristics (or all): exit 1 on any actionable finding in them.",
    ),
    max_actionable: int | None = typer.Option(
        None, "--max-actionable", help="Exit 1 above this many actionable findings."
    ),
) -> None:
    """Render report.json as a Markdown quality summary, with an optional gate.

    With --fail-on or --max-actionable the command exits 1 when the gate
    fails, after writing the page, so CI can show why it went red.
    """
    from equill.score import score_report
    from equill.summary import evaluate_gate, parse_characteristics, render_summary

    try:
        chars = parse_characteristics(fail_on)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint="--fail-on") from e
    if max_actionable is not None and max_actionable < 0:
        raise typer.BadParameter("must be >= 0", param_hint="--max-actionable")

    report = _load(report_json)
    gate = evaluate_gate(score_report(report), fail_on=chars, max_actionable=max_actionable)
    page = render_summary(report, gate=gate, top=top)
    if output is None:
        typer.echo(page)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(page, encoding="utf-8")
        typer.echo(f"wrote {output}")
    if not gate.passed:
        for failure in gate.failures:
            typer.echo(f"quality gate failed: {failure}", err=True)
        raise typer.Exit(code=1)


@app.command()
def score(
    report_json: Path = typer.Argument(..., help="report.json from `equill scan`"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """(Re)write scores.json: per-characteristic aggregate of a report."""
    from equill.score import write_scores

    out = output or report_json.with_name("scores.json")
    typer.echo(f"wrote {write_scores(_load(report_json), out)}")


@app.command()
def sarif(
    report_json: Path = typer.Argument(..., help="report.json from `equill scan`"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """(Re)write report.sarif: SARIF 2.1.0 for GitHub code scanning."""
    from equill.sarif import write_sarif

    out = output or report_json.with_name("report.sarif")
    typer.echo(f"wrote {write_sarif(_load(report_json), out)}")


@app.command()
def version() -> None:
    """Print the equill version."""
    from equill import __version__

    typer.echo(__version__)


if __name__ == "__main__":
    app()
