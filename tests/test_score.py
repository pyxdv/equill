from __future__ import annotations

import json

import pytest

from equill.schema import Finding, Mapping, Report
from equill.score import CONSTRUCT_NOTE, score_report, write_scores


def _finding(severity="WARNING", **overrides) -> Finding:
    base = dict(
        rule_id="rule.x",
        file="src/index.js",
        line=1,
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        severity=severity,
        message="msg",
        snippet="code",
    )
    base.update(overrides)
    return Finding(**base)


def _mapping(finding_id: str, iso_char="security", iso_sub="integrity", confidence=0.9) -> Mapping:
    return Mapping(
        finding_id=finding_id,
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        iso_char=iso_char,
        iso_sub=iso_sub,
        confidence=confidence,
        rationale="r",
        model="m",
        retrieved_ctx_ids=[],
    )


def _report(findings, mappings) -> Report:
    return Report(
        benchmark="bench-1",
        commit_sha="abc123",
        findings=findings,
        mappings=mappings,
        coverage=(len(mappings) / len(findings)) if findings else 0.0,
        mean_confidence=0.9,
    )


def test_all_eight_characteristics_always_emitted():
    scores = score_report(_report([_finding()], [_mapping("f-0")]))
    assert len(scores.characteristics) == 8
    names = {c.characteristic for c in scores.characteristics}
    assert {"security", "compatibility", "portability"} <= names


def test_unmeasured_characteristic_has_null_index_not_perfect_score():
    scores = score_report(_report([_finding()], [_mapping("f-0")]))
    by_name = {c.characteristic: c for c in scores.characteristics}
    assert by_name["security"].quality_index is not None
    # absence of findings is absence of evidence, never a perfect score
    assert by_name["portability"].quality_index is None
    assert by_name["portability"].n_findings == 0


def test_burden_weights_severity_and_confidence():
    findings = [_finding(severity="ERROR"), _finding(severity="INFO")]
    mappings = [
        _mapping("f-0", confidence=1.0),  # ERROR x 1.0 -> 3.0
        _mapping("f-1", confidence=0.5),  # INFO  x 0.5 -> 0.5
    ]
    scores = score_report(_report(findings, mappings))
    security = next(c for c in scores.characteristics if c.characteristic == "security")
    assert security.burden == pytest.approx(3.5)
    assert security.quality_index == pytest.approx(1.0 / 4.5)
    assert security.severity_counts == {"INFO": 1, "WARNING": 0, "ERROR": 1}
    assert security.n_findings == 2
    assert security.mean_confidence == pytest.approx(0.75)


def test_sub_characteristic_counts_accumulate():
    findings = [_finding(), _finding(), _finding()]
    mappings = [
        _mapping("f-0", iso_sub="integrity"),
        _mapping("f-1", iso_sub="integrity"),
        _mapping("f-2", iso_sub="confidentiality"),
    ]
    scores = score_report(_report(findings, mappings))
    security = next(c for c in scores.characteristics if c.characteristic == "security")
    assert security.sub_counts == {"integrity": 2, "confidentiality": 1}


def test_mappings_split_across_characteristics():
    findings = [_finding(), _finding(cwe=["CWE-400"])]
    mappings = [
        _mapping("f-0"),
        _mapping("f-1", iso_char="reliability", iso_sub="availability"),
    ]
    scores = score_report(_report(findings, mappings))
    by_name = {c.characteristic: c for c in scores.characteristics}
    assert by_name["security"].n_findings == 1
    assert by_name["reliability"].n_findings == 1


def test_totals_track_coverage():
    findings = [_finding(), _finding(), _finding()]
    scores = score_report(_report(findings, [_mapping("f-0")]))
    assert scores.total_findings == 3
    assert scores.mapped_findings == 1
    assert scores.uncovered_findings == 2


def test_unparseable_finding_id_defaults_to_warning_weight():
    # LookupMapper historically used non-positional ids; aggregation must not crash
    scores = score_report(_report([_finding(severity="ERROR")], [_mapping("f-x", confidence=1.0)]))
    security = next(c for c in scores.characteristics if c.characteristic == "security")
    assert security.burden == pytest.approx(2.0)  # WARNING fallback weight


def test_construct_note_embedded_in_artifact(tmp_path):
    report = _report([_finding()], [_mapping("f-0")])
    out = write_scores(report, tmp_path / "scores.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["construct_note"] == CONSTRUCT_NOTE
    assert loaded["benchmark"] == "bench-1"
    assert len(loaded["characteristics"]) == 8
