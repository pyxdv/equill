from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from equill.schema import Finding, Mapping, Report, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Semgrep severities -> SARIF result levels (§3.27.10 of the SARIF spec).
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    "INFO": "note",
    "WARNING": "warning",
    "ERROR": "error",
}


def _mapping_by_finding_index(report: Report) -> dict[int, Mapping]:
    """Index mappings by the positional finding id the pipeline assigns (f-<i>)."""
    by_index: dict[int, Mapping] = {}
    for mapping in report.mappings:
        if mapping.finding_id.startswith("f-"):
            try:
                by_index[int(mapping.finding_id[2:])] = mapping
            except ValueError:
                continue
    return by_index


def _result_message(finding: Finding, mapping: Mapping | None) -> str:
    if mapping is None:
        return f"{finding.message} [ISO/IEC 25010: no schema-valid mapping produced]"
    return (
        f"{finding.message} [ISO/IEC 25010: {mapping.iso_char}/{mapping.iso_sub}, "
        f"confidence {mapping.confidence:.2f}] {mapping.rationale}"
    )


def _result(finding: Finding, index: int, mapping: Mapping | None, rule_index: int) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "owasp": finding.owasp,
        "cwe": finding.cwe,
        "quillFindingId": f"f-{index}",
        "quillMapped": mapping is not None,
    }
    if mapping is not None:
        properties["quillMapping"] = {
            "iso_char": mapping.iso_char,
            "iso_sub": mapping.iso_sub,
            "confidence": mapping.confidence,
            "rationale": mapping.rationale,
            "model": mapping.model,
            "retrieved_ctx_ids": mapping.retrieved_ctx_ids,
        }
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": _result_message(finding, mapping)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    # SARIF regions are 1-based; normalized findings allow line 0.
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "properties": properties,
    }


def report_to_sarif(report: Report) -> dict[str, Any]:
    """Convert an equill Report into a SARIF 2.1.0 log.

    Every finding becomes a result — including uncovered ones, so SARIF
    consumers see the same population the coverage metric is computed over.
    The ISO/IEC 25010 mapping rides in each result's property bag under
    ``quillMapping`` and is summarized in the result message.
    """
    rule_ids: list[str] = []
    rule_index: dict[str, int] = {}
    for finding in report.findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rule_ids)
            rule_ids.append(finding.rule_id)

    by_index = _mapping_by_finding_index(report)
    results = [
        _result(finding, i, by_index.get(i), rule_index[finding.rule_id])
        for i, finding in enumerate(report.findings)
    ]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "equill",
                "informationUri": "https://github.com/pyxdv/equill",
                "rules": [{"id": rid} for rid in rule_ids],
            }
        },
        "results": results,
        "properties": {
            "benchmark": report.benchmark,
            "coverage": report.coverage,
            # commit_sha always rides here, so the scanned revision survives even
            # when we cannot emit a spec-valid versionControlProvenance below.
            "commitSha": report.commit_sha,
        },
    }
    # SARIF versionControlDetails REQUIRES repositoryUri (§3.14.24 / schema
    # "required": ["repositoryUri"]); revisionId alone is invalid. Emitting
    # revisionId by itself whenever commit_sha is set would make every report
    # from a real run produce a SARIF log that a validating consumer rejects,
    # which breaks the export's integration with existing static-analysis
    # tooling. Emit the block only when we can emit it correctly.
    if report.commit_sha and report.repository_uri:
        run["versionControlProvenance"] = [{
            "repositoryUri": report.repository_uri,
            "revisionId": report.commit_sha,
        }]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(report: Report, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_to_sarif(report), indent=2), encoding="utf-8"
    )
    return output_path


__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "report_to_sarif",
    "write_sarif",
]
