"""scan -> normalize -> map -> report, with the deterministic mappers only."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from equill import rules as open_rules
from equill.checker_table import DEFAULT_CHECKER_CSV, load_checker_table
from equill.cppcheck import (
    DEFAULT_PATH_EXCLUDE,
    classify,
    exclude_paths,
    parse_cppcheck_xml,
    run_cppcheck,
)
from equill.mapper import CheckerLookupMapper, LookupMapper, MappingSummary
from equill.normalize import normalize_semgrep_output
from equill.reference import DEFAULT_REFERENCE_CSV, load_reference_table
from equill.rules import RULES_COMMIT, RULES_REPO
from equill.scan import CommandRunner, SubprocessRunner, run_semgrep
from equill.schema import Mapping, Report, Scanner


@dataclass(frozen=True)
class PipelineConfig:
    repo_path: Path
    # "auto": the open opengrep-rules for the languages present (Opengrep), or
    # Semgrep's p/default registry pack (Semgrep). Anything else is passed to
    # the scanner as --config, comma-separated values as several.
    semgrep_config: str = "auto"
    name: str = ""
    commit_sha: str = ""
    scanner: Scanner = "opengrep"
    # A recorded Semgrep JSON or Cppcheck XML to map instead of running the
    # scanner; None runs it.
    scanner_output: Path | None = None
    reference_csv: Path = DEFAULT_REFERENCE_CSV
    checker_table: Path = DEFAULT_CHECKER_CSV
    # Replace Semgrep's "requires login" placeholder (and Cppcheck's missing
    # snippet) with the flagged source lines read from the checkout.
    snippet_fallback: bool = False
    # Cppcheck only: drop findings under test, fuzz and example paths.
    cppcheck_exclude_tests: bool = True
    path_exclude: str | None = None


def detect_commit_sha(repo_path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def resolve_config(config: PipelineConfig) -> tuple[list[str], str]:
    """The --config values for a Semgrep-family scan, and their provenance."""
    if config.semgrep_config != "auto":
        configs = [c.strip() for c in config.semgrep_config.split(",") if c.strip()]
        return configs, ", ".join(configs)
    if config.scanner == "semgrep":
        return ["p/default"], "p/default"
    root = open_rules.fetch()
    paths = open_rules.select(root, config.repo_path)
    folders = ", ".join(path.relative_to(root).as_posix() for path in paths)
    return [str(path) for path in paths], f"{RULES_REPO}@{RULES_COMMIT[:12]} ({folders})"


def stable_rule_id(rule_id: str) -> str:
    """Drop the cache-path prefix Opengrep puts on a rule id from a local folder.

    Opengrep names a rule loaded from a path after that path, so a default scan
    reports ids like ``home.runner..cache.equill.opengrep-rules.<commit>.rules.
    python.flask...``: different on every machine, and renamed on every rules
    update, which would make code scanning close and reopen every alert. The
    part after the pinned commit's ``rules`` folder is the id the rule has in its
    own repository.
    """
    marker = f"{RULES_COMMIT}.rules."
    return rule_id.split(marker, 1)[1] if marker in rule_id else rule_id


def run_pipeline(config: PipelineConfig, runner: CommandRunner | None = None) -> Report:
    runner = runner or SubprocessRunner()
    cppcheck = config.scanner == "cppcheck"
    exclude_pattern: str | None = None
    if cppcheck and config.cppcheck_exclude_tests:
        exclude_pattern = config.path_exclude or DEFAULT_PATH_EXCLUDE

    rules_used: str | None = None
    if config.scanner_output is not None:
        text = Path(config.scanner_output).read_text(encoding="utf-8")
        if not cppcheck and text.lstrip().startswith("<"):
            raise ValueError(
                f"{config.scanner_output} looks like Cppcheck XML; pass --scanner cppcheck"
            )
        raw = text if cppcheck else json.loads(text)
    elif cppcheck:
        raw = run_cppcheck(repo_path=config.repo_path, runner=runner)
    else:
        configs, rules_used = resolve_config(config)
        raw = run_semgrep(
            repo_path=config.repo_path, config=configs,
            runner=runner, scanner=config.scanner,
        )

    source_root = Path.cwd() if config.snippet_fallback else None
    if cppcheck:
        findings = parse_cppcheck_xml(raw, source_root=source_root)
        findings = exclude_paths(findings, exclude_pattern, base=config.repo_path)
        table = load_checker_table(config.checker_table)
        findings = classify(findings, table)
        mapper: LookupMapper | CheckerLookupMapper = CheckerLookupMapper(table=table)
    else:
        findings = normalize_semgrep_output(raw, source_root=source_root)
        if rules_used is not None and rules_used.startswith(RULES_REPO):
            findings = [
                f.model_copy(update={"rule_id": stable_rule_id(f.rule_id)}) for f in findings
            ]
        mapper = LookupMapper(reference=load_reference_table(config.reference_csv))

    outcomes = mapper.map_findings(findings)
    mappings: list[Mapping] = [
        o.mapping.model_copy(update={"finding_id": f"f-{i}"})
        for i, o in enumerate(outcomes)
        if o.mapping is not None
    ]
    summary = MappingSummary.from_outcomes(outcomes)
    return Report(
        benchmark=config.name or config.repo_path.resolve().name,
        commit_sha=config.commit_sha or detect_commit_sha(config.repo_path),
        findings=findings,
        mappings=mappings,
        coverage=summary.coverage,
        mean_confidence=summary.mean_confidence,
        snippet_fallback=config.snippet_fallback,
        scanner=config.scanner,
        path_exclude=exclude_pattern,
        rules=rules_used,
    )


def write_report(report: Report, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


__all__ = [
    "PipelineConfig",
    "detect_commit_sha",
    "resolve_config",
    "stable_rule_id",
    "run_pipeline",
    "write_report",
]
