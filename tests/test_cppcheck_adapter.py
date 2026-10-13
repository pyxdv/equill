"""Cppcheck as an equill scanner: equill.cppcheck, equill.checker_table,
equill.rootcause, CheckerLookupMapper, class-aware scores, the pipeline branch
and the CLI. Cppcheck itself is not needed: the XML is a fixture and the runner
is a fake.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from equill.checker_table import DEFAULT_CHECKER_CSV, load_checker_table
from equill.cppcheck import (
    DEFAULT_PATH_EXCLUDE,
    CppcheckError,
    build_cppcheck_command,
    checker_id,
    classify,
    exclude_paths,
    parse_cppcheck_xml,
    path_is_excluded,
    run_cppcheck,
)
from equill.mapper import CheckerLookupMapper
from equill.pipeline import PipelineConfig, run_pipeline
from equill.rootcause import count_sites, group_sites
from equill.scan import SubprocessResult, build_semgrep_command
from equill.schema import Finding, Mapping, Report
from equill.score import score_report

XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
<cppcheck version="2.13.0"/>
<errors>
<error id="memleak" severity="error" msg="Memory leak: buf" verbose="Memory leak: buf" cwe="401">
  <location file="gw/libloragw/src/loragw_spi.c" line="84" column="9"/>
</error>
<error id="nullPointerRedundantCheck" severity="warning" msg="Either the condition 'buf' is redundant or there is possible null pointer dereference: buf." cwe="476">
  <location file="gw/src/LGwProxy.cpp" line="490" column="5" info="Null pointer dereference"/>
  <location file="gw/src/LGwProxy.cpp" line="495" column="9" info="Assuming that condition 'buf' is not redundant"/>
</error>
<error id="nullPointerRedundantCheck" severity="warning" msg="Either the condition 'buf' is redundant or there is possible null pointer dereference: buf." cwe="476">
  <location file="gw/src/LGwProxy.cpp" line="492" column="5" info="Null pointer dereference"/>
  <location file="gw/src/LGwProxy.cpp" line="495" column="9" info="Assuming that condition 'buf' is not redundant"/>
</error>
<error id="variableScope" severity="style" msg="The scope of the variable 'i' can be reduced." cwe="398">
  <location file="gw/src/net.c" line="10" column="3"/>
</error>
<error id="uninitvar" severity="error" msg="Uninitialized variable: el" cwe="457">
  <location file="gw/src/list.c" line="7" column="3"/>
</error>
<error id="memleak" severity="error" msg="Memory leak: t" cwe="401">
  <location file="gw/test/test_spi.c" line="12" column="3"/>
</error>
<error id="someNewChecker" severity="style" msg="new" cwe="398">
  <location file="gw/src/new.c" line="1" column="1"/>
</error>
<error id="missingIncludeSystem" severity="information" msg="Include file not found"/>
<error id="noLocation" severity="style" msg="dropped"/>
</errors>
</results>
"""


def test_shipped_table_loads_and_is_keyed_by_checker_id():
    table = load_checker_table(DEFAULT_CHECKER_CSV)
    assert len(table) == 44
    assert table["memleak"].iso_char == "reliability"
    assert table["memleak"].evidence_class == "BUG"
    assert table["memleak"].cwe == "CWE-401"
    assert table["variableScope"].evidence_class == "NOISE"
    assert table["uninitvar"].evidence_class == "GATE"
    assert table["missingOverride"].cwe is None


@pytest.mark.parametrize(
    "row, msg",
    [
        ("x,style,398,security,maturity,,,NOISE,drafted,r", "not an ISO"),
        ("x,style,398,reliability,maturity,,,MAYBE,drafted,r", "class_prior"),
    ],
)
def test_malformed_table_rows_raise(tmp_path, row, msg):
    header = "checker_id,cppcheck_severity,cwe,iso_char,iso_sub,alt_label,alt_when,class_prior,prior_source,rationale"
    csv = tmp_path / "t.csv"
    csv.write_text(f"{header}\n{row}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=msg):
        load_checker_table(csv)


def test_duplicate_checker_row_raises(tmp_path):
    header = "checker_id,cppcheck_severity,cwe,iso_char,iso_sub,alt_label,alt_when,class_prior,prior_source,rationale"
    row = "x,style,398,reliability,maturity,,,BUG,drafted,r"
    csv = tmp_path / "t.csv"
    csv.write_text(f"{header}\n{row}\n{row}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_checker_table(csv)


def test_default_table_resolves_from_another_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # The table ships inside the package, so the default is found from anywhere.
    assert DEFAULT_CHECKER_CSV.is_absolute() and DEFAULT_CHECKER_CSV.exists()
    assert len(load_checker_table()) == 44
    # An explicit path that does not exist is still an error, not a silent fallback.
    with pytest.raises(FileNotFoundError):
        load_checker_table(tmp_path / "missing.csv")


def test_parse_drops_status_records_and_errors_without_location():
    findings = parse_cppcheck_xml(XML)
    ids = [checker_id(f) for f in findings]
    assert "missingIncludeSystem" not in ids
    assert "noLocation" not in ids
    assert len(findings) == 7


def test_parse_maps_fields():
    leak = parse_cppcheck_xml(XML)[0]
    assert leak.rule_id == "cppcheck.memleak"
    assert leak.file == "gw/libloragw/src/loragw_spi.c"
    assert leak.line == 84
    assert leak.cwe == ["CWE-401"]
    assert leak.owasp == []
    assert leak.severity == "ERROR"
    assert leak.message == "Memory leak: buf"
    assert leak.snippet == ""
    assert leak.related_locations == []
    assert leak.evidence_class is None  # classify() sets it, not the parser


def test_parse_severity_scale_and_related_locations():
    findings = parse_cppcheck_xml(XML)
    by_id = {}
    for f in findings:
        by_id.setdefault(checker_id(f), f)
    assert by_id["nullPointerRedundantCheck"].severity == "WARNING"
    assert by_id["nullPointerRedundantCheck"].related_locations == ["gw/src/LGwProxy.cpp:495"]
    assert by_id["variableScope"].severity == "INFO"


def test_parse_rejects_non_xml():
    with pytest.raises(CppcheckError, match="well-formed"):
        parse_cppcheck_xml("not xml")


def test_parse_reads_snippet_from_source_root(tmp_path):
    src = tmp_path / "gw" / "src" / "net.c"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join(f"line {i}" for i in range(1, 30)), encoding="utf-8")
    findings = parse_cppcheck_xml(XML, source_root=tmp_path)
    scope = next(f for f in findings if checker_id(f) == "variableScope")
    assert "line 10" in scope.snippet
    leak = findings[0]  # file absent under source_root: empty, not an error
    assert leak.snippet == ""


@pytest.mark.parametrize(
    "path, excluded",
    [
        ("src/net.c", False),
        ("test/net.c", True),
        ("lib/tests/x.c", True),
        ("src/x_test.c", True),
        ("src/test_x.c", True),
        ("util_spi_test.c", True),
        ("examples/demo.c", True),
        ("src/testing.c", True),  # the stem is matched too: conservative, and recorded
        ("GatewayTester/src/LGwProxy.cpp", False),  # the 5.1b miss, kept as recorded
        ("src/latest.c", False),
    ],
)
def test_default_path_exclusion(path, excluded):
    assert path_is_excluded(path, DEFAULT_PATH_EXCLUDE) is excluded


def test_exclude_paths_none_keeps_everything():
    findings = parse_cppcheck_xml(XML)
    assert exclude_paths(findings, None) is findings
    kept = exclude_paths(findings, DEFAULT_PATH_EXCLUDE)
    assert len(kept) == 6
    assert all("test" not in f.file.split("/") for f in kept)


def test_exclude_paths_matches_below_the_scanned_root_only(tmp_path):
    # A parent directory called "testing" must not exclude the whole scan.
    root = tmp_path / "testing" / "gw"
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    keep = Finding(rule_id="cppcheck.memleak", file=str(root / "src" / "a.c"), line=1,
                   severity="ERROR", message="m", snippet="")
    drop = Finding(rule_id="cppcheck.memleak", file=str(root / "test" / "a.c"), line=1,
                   severity="ERROR", message="m", snippet="")
    assert exclude_paths([keep, drop], DEFAULT_PATH_EXCLUDE, base=root) == [keep]
    assert exclude_paths([keep, drop], DEFAULT_PATH_EXCLUDE) == []  # as written, both carry "testing"
    # A path outside the base is matched as written.
    other = Finding(rule_id="cppcheck.memleak", file="/elsewhere/gw/test/a.c", line=1,
                    severity="ERROR", message="m", snippet="")
    assert exclude_paths([other], DEFAULT_PATH_EXCLUDE, base=root) == []


def test_classify_sets_class_from_table_and_leaves_unknown_none():
    table = load_checker_table(DEFAULT_CHECKER_CSV)
    findings = classify(parse_cppcheck_xml(XML), table)
    cls = {f.rule_id + "@" + str(f.line): f.evidence_class for f in findings}
    assert cls["cppcheck.memleak@84"] == "BUG"
    assert cls["cppcheck.variableScope@10"] == "NOISE"
    assert cls["cppcheck.uninitvar@7"] == "GATE"
    assert cls["cppcheck.someNewChecker@1"] is None


def test_classify_leaves_semgrep_findings_alone():
    table = load_checker_table(DEFAULT_CHECKER_CSV)
    f = Finding(rule_id="php.lang.security.x", file="a.php", line=1, severity="ERROR",
                message="m", snippet="s", cwe=["CWE-89"])
    assert classify([f], table)[0].evidence_class is None


def test_build_cppcheck_command():
    cmd = build_cppcheck_command(Path("/tmp/repo"))
    assert cmd[0] == "cppcheck"
    assert "--xml" in cmd and "--xml-version=2" in cmd
    assert "--enable=warning,style,performance,portability" in cmd
    assert "--max-configs=1" in cmd
    assert cmd[-1] == "/tmp/repo"


def test_semgrep_command_refuses_cppcheck():
    with pytest.raises(ValueError, match="semgrep"):
        build_semgrep_command(Path("/tmp/repo"), "p/default", scanner="cppcheck")  # type: ignore[arg-type]


@dataclass
class FakeRunner:
    result: SubprocessResult
    calls: list[tuple[list[str], int]] = field(default_factory=list)

    def run(self, args, timeout):
        self.calls.append((args, timeout))
        return self.result


def test_run_cppcheck_reads_xml_from_stderr():
    runner = FakeRunner(SubprocessResult(returncode=0, stdout="Checking x.c ...\n", stderr=XML))
    out = run_cppcheck(Path("/tmp/repo"), runner=runner)
    assert out == XML
    assert runner.calls[0][0][0] == "cppcheck"


def test_run_cppcheck_raises_on_nonzero_exit_and_on_missing_report():
    with pytest.raises(CppcheckError, match="exited 1"):
        run_cppcheck(Path("/r"), runner=FakeRunner(SubprocessResult(1, "", "boom")))
    with pytest.raises(CppcheckError, match="<results>"):
        run_cppcheck(Path("/r"), runner=FakeRunner(SubprocessResult(0, "", "no xml here")))


def test_checker_lookup_mapper_maps_known_ids_only():
    table = load_checker_table(DEFAULT_CHECKER_CSV)
    findings = classify(parse_cppcheck_xml(XML), table)
    outcomes = CheckerLookupMapper(table).map_findings(findings)
    by_rule = {checker_id(o.finding): o for o in outcomes}
    leak = by_rule["memleak"].mapping
    assert leak is not None
    assert (leak.iso_char, leak.iso_sub, leak.confidence, leak.model) == (
        "reliability", "maturity", 1.0, "checker-lookup")
    assert leak.cwe == ["CWE-401"]
    assert by_rule["variableScope"].mapping is not None  # NOISE is mapped; the scorer filters
    assert by_rule["someNewChecker"].mapping is None
    semgrep = Finding(rule_id="php.x", file="a.php", line=1, severity="ERROR",
                      message="m", snippet="s", cwe=["CWE-89"])
    assert CheckerLookupMapper(table).map_finding(semgrep).mapping is None


def test_group_sites_merges_same_line_shared_anchor_and_entity():
    findings = parse_cppcheck_xml(XML)
    sites, merges = group_sites(findings)
    nulls = [i for i, f in enumerate(findings) if checker_id(f) == "nullPointerRedundantCheck"]
    assert len(nulls) == 2
    assert sites[nulls[0]] == sites[nulls[1]]  # the two reports share the redundant check
    assert merges["shared-anchor"] == 1
    assert count_sites(findings) == len(findings) - 1

    # Semgrep findings: only same-line can merge, and only within a rule.
    a = Finding(rule_id="r1", file="a.js", line=5, severity="ERROR", message="m", snippet="s")
    b = Finding(rule_id="r2", file="a.js", line=5, severity="ERROR", message="m", snippet="s")
    assert count_sites([a, b]) == 2
    assert count_sites([a, a.model_copy()]) == 1

    # Class-scoped checkers: a declaration and its definition name one class.
    c1 = Finding(rule_id="cppcheck.noCopyConstructor", file="x.h", line=3, severity="WARNING",
                 message="Class 'Gw' does not have a copy constructor which is recommended since it has dynamic memory/resource allocation(s).", snippet="")
    c2 = Finding(rule_id="cppcheck.noOperatorEq", file="x.h", line=3, severity="WARNING",
                 message="Class 'Gw' does not have a operator= which is recommended since it has dynamic memory/resource allocation(s).", snippet="")
    assert count_sites([c1, c2]) == 1


def _report(findings, mappings, **kw) -> Report:
    return Report(benchmark="gw", commit_sha="abc", findings=findings, mappings=mappings,
                  coverage=len(mappings) / len(findings) if findings else 0.0,
                  mean_confidence=1.0, **kw)


def test_scores_count_only_actionable_findings_toward_burden():
    table = load_checker_table(DEFAULT_CHECKER_CSV)
    findings = classify(exclude_paths(parse_cppcheck_xml(XML), DEFAULT_PATH_EXCLUDE), table)
    outcomes = CheckerLookupMapper(table).map_findings(findings)
    mappings = [o.mapping.model_copy(update={"finding_id": f"f-{i}"})
                for i, o in enumerate(outcomes) if o.mapping is not None]
    scores = score_report(_report(findings, mappings, scanner="cppcheck"))
    by = {c.characteristic: c for c in scores.characteristics}

    rel = by["reliability"]
    # memleak (BUG) + 2 null checks (BUG) + uninitvar (GATE)
    assert (rel.n_findings, rel.n_actionable, rel.n_noise, rel.n_gated) == (4, 3, 0, 1)
    assert rel.n_sites == 2  # the two null-check reports are one site
    assert rel.burden == pytest.approx(3.0 * 1.0 + 2.0 * 1.0 + 2.0 * 1.0)
    assert rel.quality_index == pytest.approx(1 / (1 + 7.0))

    mnt = by["maintainability"]
    assert (mnt.n_findings, mnt.n_actionable, mnt.n_noise) == (1, 0, 1)
    assert mnt.burden == 0.0
    assert mnt.quality_index is None  # noise alone is not evidence of quality

    assert scores.mapped_findings == 5
    assert (scores.actionable_findings, scores.noise_findings, scores.gated_findings) == (3, 1, 1)
    assert scores.actionable_sites == 2
    assert "NOISE" in scores.construct_note and "n_sites" in scores.construct_note


def test_scores_unchanged_for_unclassified_semgrep_findings():
    f = Finding(rule_id="r", file="a.js", line=1, severity="WARNING", message="m", snippet="s",
                cwe=["CWE-79"])
    m = Mapping(finding_id="f-0", owasp=[], cwe=["CWE-79"], iso_char="security",
                iso_sub="integrity", confidence=0.5, rationale="r", model="m")
    sec = {c.characteristic: c for c in score_report(_report([f], [m])).characteristics}["security"]
    assert (sec.n_findings, sec.n_actionable, sec.n_noise, sec.n_gated, sec.n_sites) == (1, 1, 0, 0, 1)
    assert sec.burden == pytest.approx(1.0)
    assert sec.quality_index == pytest.approx(0.5)


def test_old_report_json_without_new_fields_still_loads():
    data = {
        "benchmark": "b", "commit_sha": "c", "coverage": 1.0, "mean_confidence": 1.0,
        "findings": [{"rule_id": "r", "file": "a", "line": 1, "severity": "INFO",
                      "message": "m", "snippet": "s"}],
        "mappings": [],
    }
    report = Report.model_validate(data)
    assert report.findings[0].evidence_class is None
    assert report.findings[0].related_locations == []
    assert report.scanner == "semgrep"
    assert report.path_exclude is None


def test_pipeline_cppcheck_lookup_from_runner(tmp_path):
    runner = FakeRunner(SubprocessResult(returncode=0, stdout="", stderr=XML))
    config = PipelineConfig(repo_path=tmp_path, scanner="cppcheck", name="gw", commit_sha="abc")
    report = run_pipeline(config, runner)
    assert runner.calls[0][0][0] == "cppcheck"
    assert report.scanner == "cppcheck"
    assert report.benchmark == "gw"
    assert report.path_exclude == DEFAULT_PATH_EXCLUDE
    assert len(report.findings) == 6  # the test/ leak is excluded
    assert len(report.mappings) == 5  # someNewChecker is unmapped
    assert report.coverage == pytest.approx(5 / 6)
    assert {m.model for m in report.mappings} == {"checker-lookup"}
    assert {m.iso_char for m in report.mappings} == {"reliability", "maintainability"}
    assert {f.evidence_class for f in report.findings} == {"BUG", "NOISE", "GATE", None}


def test_pipeline_cppcheck_reads_recorded_xml_and_can_keep_tests(tmp_path):
    xml = tmp_path / "gw.xml"
    xml.write_text(XML, encoding="utf-8")
    runner = FakeRunner(SubprocessResult(returncode=0, stdout="", stderr="unused"))
    config = PipelineConfig(repo_path=tmp_path, scanner="cppcheck", scanner_output=xml,
                            cppcheck_exclude_tests=False, name="gw", commit_sha="abc")
    report = run_pipeline(config, runner)
    assert runner.calls == []  # nothing was run
    assert report.path_exclude is None
    assert len(report.findings) == 7


def test_pipeline_semgrep_reads_recorded_json(tmp_path):
    payload = {"results": [{
        "check_id": "php.x", "path": "a.php", "start": {"line": 3}, "end": {"line": 3},
        "extra": {"severity": "ERROR", "message": "m", "lines": "echo $x;",
                  "metadata": {"owasp": ["A03:2021"], "cwe": ["CWE-79"]}}}]}
    out = tmp_path / "semgrep.json"
    out.write_text(json.dumps(payload), encoding="utf-8")
    runner = FakeRunner(SubprocessResult(returncode=0, stdout="{}", stderr=""))
    config = PipelineConfig(repo_path=tmp_path, scanner_output=out, name="b", commit_sha="c")
    report = run_pipeline(config, runner)
    assert runner.calls == []
    assert report.scanner == "semgrep"
    assert report.path_exclude is None  # Semgrep runs are never filtered
    assert [m.iso_char for m in report.mappings] == ["security"]
    assert report.mappings[0].finding_id == "f-0"


def test_cli_accepts_cppcheck_scanner_and_recorded_output(tmp_path):
    from typer.testing import CliRunner

    from equill.cli import app

    xml = tmp_path / "gw.xml"
    xml.write_text(XML, encoding="utf-8")
    result = CliRunner().invoke(app, [
        "scan", str(tmp_path), "--scanner", "cppcheck", "--scanner-output", str(xml),
        "--name", "gw", "--output", str(tmp_path / "out"),
    ])
    assert result.exit_code == 0, result.output
    report = Report.model_validate_json((tmp_path / "out" / "report.json").read_text())
    assert report.scanner == "cppcheck"
    scores = json.loads((tmp_path / "out" / "scores.json").read_text())
    assert scores["actionable_findings"] == 3
    assert scores["actionable_sites"] == 2
    assert (tmp_path / "out" / "report.sarif").is_file()


def test_cli_scan_rejects_unknown_scanner(tmp_path):
    from typer.testing import CliRunner

    from equill.cli import app

    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--scanner", "bogus"])
    assert result.exit_code == 2
    assert "must be one of" in result.output


def test_cli_scan_explains_cppcheck_xml_given_without_the_scanner(tmp_path):
    from typer.testing import CliRunner

    from equill.cli import app

    xml = tmp_path / "gw.xml"
    xml.write_text(XML, encoding="utf-8")
    result = CliRunner().invoke(app, [
        "scan", str(tmp_path), "--scanner-output", str(xml), "--output", str(tmp_path / "o"),
    ])
    assert result.exit_code == 2
    assert "looks like Cppcheck XML; pass --scanner cppcheck" in result.output
