from __future__ import annotations

import json

from equill.sarif import SARIF_SCHEMA, SARIF_VERSION, report_to_sarif, write_sarif
from equill.schema import Finding, Mapping, Report


def _finding(**overrides) -> Finding:
    base = dict(
        rule_id="javascript.express.security.audit.xss.template-string",
        file="src/index.js",
        line=42,
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        severity="WARNING",
        message="Possible XSS",
        snippet="res.send(`<div>${x}</div>`)",
    )
    base.update(overrides)
    return Finding(**base)


def _mapping(finding_id: str, **overrides) -> Mapping:
    base = dict(
        finding_id=finding_id,
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        iso_char="security",
        iso_sub="integrity",
        confidence=0.9,
        rationale="XSS undermines integrity.",
        model="phi4-mini",
        retrieved_ctx_ids=["iso::c1"],
    )
    base.update(overrides)
    return Mapping(**base)


def _report(findings, mappings) -> Report:
    covered = len(mappings) / len(findings) if findings else 0.0
    mean_conf = sum(m.confidence for m in mappings) / len(mappings) if mappings else 0.0
    return Report(
        benchmark="bench-1",
        commit_sha="abc123",
        findings=findings,
        mappings=mappings,
        coverage=covered,
        mean_confidence=mean_conf,
    )


def test_sarif_envelope_and_run_metadata():
    report = _report([_finding()], [_mapping("f-0")])
    sarif = report_to_sarif(report)

    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == SARIF_VERSION
    (run,) = sarif["runs"]
    assert run["tool"]["driver"]["name"] == "equill"
    assert run["properties"] == {
        "benchmark": "bench-1", "coverage": 1.0, "commitSha": "abc123",
    }
    # A block of the form
    #     run["versionControlProvenance"] == [{"revisionId": "abc123"}]
    # is not valid SARIF — versionControlDetails requires repositoryUri, so
    # any validating consumer would reject the export. With no repository_uri
    # on the report the block is omitted and the revision rides in properties;
    # see tests/test_sarif_schema_valid.py for validation against the real
    # schema.
    assert "versionControlProvenance" not in run


def test_version_control_provenance_needs_a_repository_uri():
    report = _report([_finding()], [_mapping("f-0")])
    report.repository_uri = "https://github.com/pyxdv/equill.git"
    (run,) = report_to_sarif(report)["runs"]
    assert run["versionControlProvenance"] == [
        {"repositoryUri": "https://github.com/pyxdv/equill.git", "revisionId": "abc123"}
    ]


def test_sarif_result_carries_mapping_in_properties():
    report = _report([_finding()], [_mapping("f-0")])
    (result,) = report_to_sarif(report)["runs"][0]["results"]

    assert result["ruleId"] == "javascript.express.security.audit.xss.template-string"
    assert result["level"] == "warning"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/index.js"
    assert loc["region"]["startLine"] == 42
    quill_props = result["properties"]["quillMapping"]
    assert quill_props["iso_char"] == "security"
    assert quill_props["iso_sub"] == "integrity"
    assert "security/integrity" in result["message"]["text"]
    assert result["properties"]["quillMapped"] is True


def test_sarif_includes_uncovered_findings():
    findings = [_finding(), _finding(file="src/dyn.js", severity="ERROR", cwe=["CWE-94"])]
    report = _report(findings, [_mapping("f-0")])
    results = report_to_sarif(report)["runs"][0]["results"]

    assert len(results) == 2
    uncovered = results[1]
    assert uncovered["level"] == "error"
    assert uncovered["properties"]["quillMapped"] is False
    assert "quillMapping" not in uncovered["properties"]
    assert "no schema-valid mapping" in uncovered["message"]["text"]


def test_sarif_severity_levels_and_line_clamping():
    findings = [
        _finding(severity="INFO", line=0),
        _finding(severity="WARNING"),
        _finding(severity="ERROR"),
    ]
    report = _report(findings, [])
    results = report_to_sarif(report)["runs"][0]["results"]

    assert [r["level"] for r in results] == ["note", "warning", "error"]
    # SARIF regions are 1-based: line 0 must clamp to 1
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_rules_deduplicated_and_indexed():
    findings = [
        _finding(),
        _finding(rule_id="other.rule", file="b.js"),
        _finding(file="c.js"),
    ]
    report = _report(findings, [])
    run = report_to_sarif(report)["runs"][0]

    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [
        "javascript.express.security.audit.xss.template-string",
        "other.rule",
    ]
    assert [r["ruleIndex"] for r in run["results"]] == [0, 1, 0]


def test_sarif_omits_provenance_without_commit_sha():
    report = _report([_finding()], [])
    report = report.model_copy(update={"commit_sha": ""})
    run = report_to_sarif(report)["runs"][0]
    assert "versionControlProvenance" not in run


def test_write_sarif_round_trips_valid_json(tmp_path):
    report = _report([_finding()], [_mapping("f-0")])
    out = write_sarif(report, tmp_path / "nested" / "report.sarif")
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["version"] == "2.1.0"
