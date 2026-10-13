import pytest
from pydantic import ValidationError

from equill.schema import (
    ALL_SUBCHARACTERISTICS,
    ISO_SUBCHARACTERISTICS,
    Finding,
    Mapping,
    Report,
)


def test_iso_taxonomy_counts():
    assert len(ISO_SUBCHARACTERISTICS) == 8
    assert len(ALL_SUBCHARACTERISTICS) == 31


def test_finding_minimal():
    f = Finding(
        rule_id="javascript.express.security.audit.xss.template-string",
        file="src/index.js",
        line=42,
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        severity="WARNING",
        message="Possible XSS via template string in HTML response",
        snippet="res.send(`<div>${userInput}</div>`)",
    )
    assert f.line == 42
    assert f.cwe == ["CWE-79"]


def test_mapping_valid():
    m = Mapping(
        finding_id="f-001",
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        iso_char="security",
        iso_sub="integrity",
        confidence=0.82,
        rationale="XSS undermines integrity of rendered content.",
        model="phi4-mini:3.8b-q4_K_M",
        retrieved_ctx_ids=["iso:security:integrity", "owasp:A03:2021", "cwe:79"],
    )
    assert m.iso_sub == "integrity"


def test_mapping_rejects_sub_mismatch():
    with pytest.raises(ValidationError):
        Mapping(
            finding_id="f-002",
            owasp=["A03:2021"],
            cwe=["CWE-79"],
            iso_char="security",
            iso_sub="learnability",  # belongs to usability, not security
            confidence=0.5,
            rationale="bad",
            model="phi4-mini:3.8b-q4_K_M",
        )


def test_mapping_rejects_unknown_sub():
    with pytest.raises(ValidationError):
        Mapping(
            finding_id="f-003",
            owasp=["A03:2021"],
            cwe=["CWE-79"],
            iso_char="security",
            iso_sub="not_a_real_thing",
            confidence=0.5,
            rationale="bad",
            model="phi4-mini:3.8b-q4_K_M",
        )


def test_mapping_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        Mapping(
            finding_id="f-004",
            owasp=["A03:2021"],
            cwe=["CWE-79"],
            iso_char="security",
            iso_sub="integrity",
            confidence=1.5,
            rationale="bad",
            model="phi4-mini:3.8b-q4_K_M",
        )


def _mapping(**overrides):
    base = dict(
        finding_id="f-1", owasp=["A03:2021"], cwe=["CWE-89"],
        iso_char="security", iso_sub="integrity", confidence=0.9,
        rationale="SQLi violates integrity.", model="phi4-mini:3.8b-q4_K_M",
    )
    base.update(overrides)
    return Mapping(**base)


def test_mapping_splits_combined_iso_char():
    # phi4-mini echoes the prompt's "security/integrity" shorthand into iso_char.
    m = _mapping(iso_char="security/integrity", iso_sub="integrity")
    assert m.iso_char == "security"
    assert m.iso_sub == "integrity"


def test_mapping_backfills_iso_sub_from_slash_when_missing():
    m = _mapping(iso_char="security/integrity", iso_sub="")
    assert m.iso_char == "security"
    assert m.iso_sub == "integrity"


def test_mapping_backfills_iso_sub_from_slash_when_invalid():
    m = _mapping(iso_char="security/integrity", iso_sub="cross-site request forgery (CSRF)")
    assert m.iso_char == "security"
    assert m.iso_sub == "integrity"


def test_mapping_normalises_case_and_separators():
    m = _mapping(iso_char="Performance Efficiency", iso_sub="Time-Behaviour")
    assert m.iso_char == "performance_efficiency"
    assert m.iso_sub == "time_behaviour"


def test_mapping_split_still_enforces_char_sub_membership():
    # security/learnability is still a genuine mismatch -> must reject (fall back).
    with pytest.raises(ValidationError):
        _mapping(iso_char="security/learnability", iso_sub="learnability")


def test_mapping_coalesces_slash_list_iso_sub():
    # phi4-mini sometimes lists several candidate subs joined by slashes; take
    # the first that belongs to the declared char ("security") instead of
    # discarding the mapping and paying for a fallback call.
    m = _mapping(iso_char="security", iso_sub="integrity/security/confidentiality")
    assert m.iso_sub == "integrity"


def test_mapping_slash_list_prefers_char_membership_over_order():
    # "learnability" is a real sub but belongs to usability, not security; skip
    # it and pick "confidentiality", which is consistent with the chosen char.
    m = _mapping(iso_char="security", iso_sub="learnability/confidentiality")
    assert m.iso_sub == "confidentiality"


def test_mapping_slash_list_all_invalid_still_rejected():
    # A list of pure garbage names is not masked — it must still fail so the
    # caller falls back rather than silently inventing a sub.
    with pytest.raises(ValidationError):
        _mapping(iso_char="security", iso_sub="foo/bar/baz")


def test_mapping_clips_overlong_rationale():
    # phi4-mini sometimes overruns the single-sentence cap; clip to the limit
    # instead of rejecting an otherwise-correct mapping (avoids a fallback).
    m = _mapping(rationale="x" * 500)
    assert len(m.rationale) == 400
    assert m.rationale == "x" * 400


def test_mapping_keeps_rationale_at_limit_unchanged():
    exact = "y" * 400
    assert _mapping(rationale=exact).rationale == exact


def test_report_aggregates():
    f = Finding(
        rule_id="r1", file="a.js", line=1, owasp=["A03:2021"], cwe=["CWE-89"],
        severity="ERROR", message="SQL injection", snippet="db.query(`SELECT ${x}`)",
    )
    m = Mapping(
        finding_id="f-1", owasp=["A03:2021"], cwe=["CWE-89"],
        iso_char="security", iso_sub="integrity", confidence=0.9,
        rationale="SQLi violates integrity.", model="phi4-mini:3.8b-q4_K_M",
    )
    r = Report(
        benchmark="juice-shop", commit_sha="deadbeef",
        findings=[f], mappings=[m], coverage=1.0, mean_confidence=0.9,
    )
    assert r.coverage == 1.0
    assert len(r.mappings) == 1
