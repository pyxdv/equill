from __future__ import annotations

from equill.normalize import normalize_result, normalize_semgrep_output


def _result(**overrides):
    base = {
        "check_id": "javascript.express.security.audit.xss.template-string",
        "path": "src/index.js",
        "start": {"line": 42, "col": 1},
        "end": {"line": 42, "col": 30},
        "extra": {
            "severity": "WARNING",
            "message": "Possible XSS via template string in HTML response  ",
            "lines": "res.send(`<div>${userInput}</div>`)",
            "metadata": {
                "owasp": ["A03:2021 - Injection"],
                "cwe": ["CWE-79: Improper Neutralization of Input During Web Page Generation"],
            },
        },
    }
    for k, v in overrides.items():
        if k in base["extra"]:
            base["extra"][k] = v
        else:
            base[k] = v
    return base


def test_normalize_result_basic_fields():
    f = normalize_result(_result())
    assert f.rule_id.endswith("xss.template-string")
    assert f.file == "src/index.js"
    assert f.line == 42
    assert f.severity == "WARNING"
    assert f.message == "Possible XSS via template string in HTML response"
    assert "userInput" in f.snippet


def test_normalize_result_extracts_owasp_and_cwe_ids():
    f = normalize_result(_result())
    assert f.owasp == ["A03:2021"]
    assert f.cwe == ["CWE-79"]


def test_normalize_result_handles_multiple_tags_and_dedupes():
    r = _result()
    r["extra"]["metadata"]["owasp"] = ["A03:2021 - Injection", "A03:2021 - dup", "A01:2021"]
    r["extra"]["metadata"]["cwe"] = "CWE-79 and also CWE-79 and CWE-89"
    f = normalize_result(r)
    assert f.owasp == ["A03:2021", "A01:2021"]
    assert f.cwe == ["CWE-79", "CWE-89"]


def test_normalize_result_missing_metadata_yields_empty_lists():
    r = _result()
    r["extra"]["metadata"] = {}
    f = normalize_result(r)
    assert f.owasp == []
    assert f.cwe == []


def test_normalize_result_coerces_severity_aliases():
    for raw, expected in [
        ("info", "INFO"),
        ("Warning", "WARNING"),
        ("ERROR", "ERROR"),
        ("low", "INFO"),
        ("medium", "WARNING"),
        ("high", "ERROR"),
        ("critical", "ERROR"),
        ("weird-value", "WARNING"),
    ]:
        r = _result(severity=raw)
        assert normalize_result(r).severity == expected, raw


def test_normalize_result_missing_extra_does_not_crash():
    raw = {"check_id": "r", "path": "a.py", "start": {"line": 1}}
    f = normalize_result(raw)
    assert f.rule_id == "r"
    assert f.message == ""
    assert f.snippet == ""
    assert f.severity == "WARNING"


def test_normalize_semgrep_output_walks_results():
    payload = {"results": [_result(), _result(path="src/other.js")]}
    findings = normalize_semgrep_output(payload)
    assert len(findings) == 2
    assert {f.file for f in findings} == {"src/index.js", "src/other.js"}


def test_normalize_semgrep_output_empty_payload():
    assert normalize_semgrep_output({}) == []
    assert normalize_semgrep_output({"results": []}) == []
