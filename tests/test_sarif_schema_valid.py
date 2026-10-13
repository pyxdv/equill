"""Validate equill's SARIF export against the official SARIF 2.1.0 JSON Schema.

The export is unit-tested for *shape* in ``tests/test_sarif.py``, but shape
alone does not establish that it is valid SARIF. Schema validity is what every
SARIF consumer requires, and it is checkable offline and deterministically. It
is **not** a demonstration that any particular tool ingests the file.

The schema is vendored (``tests/data/sarif-2.1.0.schema.json``) rather than
fetched, with provenance and a sha256 in the sidecar, so this test cannot
silently change meaning when schemastore updates.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from equill.sarif import SARIF_SCHEMA, SARIF_VERSION, report_to_sarif
from equill.schema import Finding, Mapping, Report

jsonschema = pytest.importorskip("jsonschema", reason="pinned in the dev extra")

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "tests" / "data" / "sarif-2.1.0.schema.json"
PROVENANCE = REPO / "tests" / "data" / "sarif-2.1.0.schema.provenance.json"


def _report() -> Report:
    """A report exercising the paths a consumer trips over: mapped, unmapped,
    line 0 (normalized findings allow it, SARIF regions are 1-based), every
    severity, and a rule id repeated so ruleIndex de-duplication is covered."""
    findings = [
        Finding(rule_id="php.lang.security.file-inclusion.file-inclusion",
                file="dvwa/vulnerabilities/fi/source/low.php", line=4, severity="WARNING",
                owasp=["A01:2021"], cwe=["CWE-22"], message="path traversal",
                snippet="include($_GET['page']);"),
        Finding(rule_id="php.lang.security.file-inclusion.file-inclusion",
                file="dvwa/other.php", line=0, severity="ERROR",
                owasp=["A03:2021"], cwe=["CWE-89"], message="sqli", snippet="q"),
        Finding(rule_id="java.lang.security.audit.crypto.weak-hash",
                file="webgoat/A.java", line=17, severity="INFO",
                owasp=[], cwe=["CWE-328"], message="weak hash", snippet="md5()"),
    ]
    mappings = [
        Mapping(finding_id="f-0", owasp=["A01:2021"], cwe=["CWE-22"],
                iso_char="security", iso_sub="integrity", confidence=0.82,
                rationale="documented dual impact", model="phi4-mini:3.8b-q4_K_M",
                retrieved_ctx_ids=["cwe_top25/top25.md::cwe_22"]),
        # f-1 deliberately absent: an unmapped finding must still validate.
        Mapping(finding_id="f-2", owasp=[], cwe=["CWE-328"],
                iso_char="security", iso_sub="confidentiality", confidence=0.4,
                rationale="weak hash exposes secrets", model="phi4-mini:3.8b-q4_K_M",
                retrieved_ctx_ids=[]),
    ]
    return Report(
        benchmark="dvwa",
        commit_sha="3cd38c444249e3a016fc203c79ecb68052283f54",
        findings=findings,
        mappings=mappings,
        coverage=2 / 3,
        mean_confidence=0.61,
    )


def _validator():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def test_vendored_schema_matches_its_recorded_digest():
    """Provenance discipline: the sidecar must describe the file it sits next to."""
    prov = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    raw = SCHEMA.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == prov["sha256"]
    assert len(raw) == prov["bytes"]
    assert prov["source_url"].endswith("sarif-2.1.0.json")


def test_export_is_valid_sarif_2_1_0():
    """The claim the paper makes: the export validates against the schema."""
    errors = sorted(_validator().iter_errors(report_to_sarif(_report())),
                    key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors[:5]
    )


def test_export_declares_the_version_and_schema_a_consumer_dispatches_on():
    log = report_to_sarif(_report())
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert log["$schema"] == SARIF_SCHEMA


def test_empty_report_is_still_valid():
    """A scan with no findings must not emit something a consumer rejects."""
    log = report_to_sarif(Report(
        benchmark="empty", commit_sha="0" * 40, findings=[], mappings=[],
        coverage=0.0, mean_confidence=0.0,
    ))
    assert not list(_validator().iter_errors(log))


def test_line_zero_is_lifted_into_a_valid_sarif_region():
    """Normalized findings allow line 0; SARIF requires startLine >= 1."""
    log = report_to_sarif(_report())
    region = log["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1


def test_version_control_provenance_is_valid_when_the_uri_is_known():
    """revisionId alone is invalid; with the repository URI the block validates.

    Emitting this block with revisionId only, whenever commit_sha is set, would
    make every SARIF log from a real run fail a validating consumer, so the
    block is emitted only when the repository URI is known.
    """
    rep = _report()
    rep.repository_uri = "https://github.com/digininja/DVWA.git"
    log = report_to_sarif(rep)
    assert not list(_validator().iter_errors(log))
    vcp = log["runs"][0]["versionControlProvenance"][0]
    assert vcp["repositoryUri"] == "https://github.com/digininja/DVWA.git"
    assert vcp["revisionId"] == rep.commit_sha


def test_revision_survives_even_without_a_repository_uri():
    """Omitting the invalid block must not lose the scanned revision."""
    log = report_to_sarif(_report())
    assert "versionControlProvenance" not in log["runs"][0]
    assert log["runs"][0]["properties"]["commitSha"] == _report().commit_sha


