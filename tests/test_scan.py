from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from equill.scan import (
    SemgrepError,
    SubprocessResult,
    build_semgrep_command,
    opengrep_env,
    run_semgrep,
)


@dataclass
class FakeRunner:
    result: SubprocessResult
    calls: list[tuple[list[str], int]] = field(default_factory=list)

    def run(self, args: list[str], timeout: int) -> SubprocessResult:
        self.calls.append((args, timeout))
        return self.result


def test_build_semgrep_command_uses_config_and_path():
    cmd = build_semgrep_command(Path("/tmp/repo"), "p/owasp-top-ten")
    assert cmd[0] == "semgrep"
    assert "scan" in cmd
    assert "--json" in cmd
    assert "--config" in cmd
    assert "p/owasp-top-ten" in cmd
    assert "/tmp/repo" in cmd


def test_run_semgrep_returns_parsed_json_on_exit_0():
    payload = {"results": []}
    runner = FakeRunner(
        result=SubprocessResult(returncode=0, stdout=json.dumps(payload), stderr="")
    )
    out = run_semgrep(Path("/tmp/repo"), runner=runner)
    assert out == payload
    assert runner.calls[0][1] == 1800


def test_run_semgrep_treats_exit_1_as_success_with_findings():
    payload = {"results": [{"check_id": "r"}]}
    runner = FakeRunner(
        result=SubprocessResult(returncode=1, stdout=json.dumps(payload), stderr="")
    )
    assert run_semgrep(Path("/tmp/repo"), runner=runner) == payload


def test_run_semgrep_raises_on_exit_2():
    runner = FakeRunner(
        result=SubprocessResult(returncode=2, stdout="", stderr="config not found")
    )
    with pytest.raises(SemgrepError, match="exited 2"):
        run_semgrep(Path("/tmp/repo"), runner=runner)


def test_run_semgrep_exit_2_surfaces_json_errors_from_stdout():
    # semgrep --json --quiet writes the fatal reason to stdout's errors array
    # (not stderr); the SemgrepError should report it instead of "(no output)".
    payload = {"errors": [{"long_msg": "Invalid rule schema: unknown config p/php"}], "results": []}
    runner = FakeRunner(
        result=SubprocessResult(returncode=2, stdout=json.dumps(payload), stderr="")
    )
    with pytest.raises(SemgrepError, match="unknown config p/php"):
        run_semgrep(Path("/tmp/repo"), runner=runner)


def test_run_semgrep_exit_2_with_no_output_reports_no_output():
    runner = FakeRunner(result=SubprocessResult(returncode=2, stdout="", stderr=""))
    with pytest.raises(SemgrepError, match=r"exited 2: \(no output\)"):
        run_semgrep(Path("/tmp/repo"), runner=runner)


def test_run_semgrep_raises_on_non_json_stdout():
    runner = FakeRunner(
        result=SubprocessResult(returncode=0, stdout="not json", stderr="")
    )
    with pytest.raises(SemgrepError, match="not valid JSON"):
        run_semgrep(Path("/tmp/repo"), runner=runner)


def test_run_semgrep_passes_custom_timeout_and_config():
    runner = FakeRunner(result=SubprocessResult(0, "{}", ""))
    run_semgrep(Path("/tmp/repo"), config="p/ci", timeout=60, runner=runner)
    args, timeout = runner.calls[0]
    assert timeout == 60
    assert "p/ci" in args


# --- Opengrep -------------------------------------------------------------


@dataclass
class EnvRecordingRunner:
    """A runner that accepts the ``env`` keyword SubprocessRunner takes."""

    result: SubprocessResult
    calls: list[tuple[list[str], int, object]] = field(default_factory=list)

    def run(self, args: list[str], timeout: int, env=None) -> SubprocessResult:
        self.calls.append((args, timeout, env))
        return self.result


def test_semgrep_argv_is_unchanged_from_the_published_runs():
    # Every reported arm ran exactly this command; the default must not move.
    assert build_semgrep_command(Path("/tmp/repo"), "p/php") == [
        "semgrep", "scan", "--json", "--quiet", "--metrics=off",
        "--config", "p/php", "/tmp/repo",
    ]


def test_opengrep_argv_drops_the_metrics_flag_it_rejects():
    cmd = build_semgrep_command(Path("/tmp/repo"), "rules/", scanner="opengrep")
    assert cmd == [
        "opengrep", "scan", "--json", "--quiet", "--config", "rules/", "/tmp/repo",
    ]
    assert not any(a.startswith("--metrics") for a in cmd)


def test_unknown_scanner_is_rejected():
    with pytest.raises(ValueError, match="scanner must be one of"):
        build_semgrep_command(Path("/tmp/repo"), "p/php", scanner="codeql")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("base", "expected_lc_all"),
    [
        ({}, "C.UTF-8"),                                      # nothing set
        ({"LANG": "C"}, "C.UTF-8"),                           # ASCII locale
        ({"LANG": "POSIX"}, "C.UTF-8"),
        ({"LANG": "en_US.UTF-8"}, None),                      # already UTF-8
        ({"LANG": "de_DE.utf8"}, None),
        ({"LC_CTYPE": "C.UTF-8"}, None),
        ({"LC_ALL": "C", "LANG": "en_US.UTF-8"}, "C.UTF-8"),  # LC_ALL outranks LANG
        ({"LC_ALL": "", "LANG": "en_GB.UTF-8"}, None),        # empty LC_ALL is unset
    ],
)
def test_opengrep_env_forces_utf8_only_when_the_locale_is_not(base, expected_lc_all):
    env = opengrep_env(base)
    if expected_lc_all is None:
        assert env == base
    else:
        assert env["LC_ALL"] == expected_lc_all
        assert {k: v for k, v in env.items() if k != "LC_ALL"} == {
            k: v for k, v in base.items() if k != "LC_ALL"
        }


def test_opengrep_env_does_not_mutate_its_input():
    base = {"LANG": "C", "PATH": "/usr/bin"}
    opengrep_env(base)
    assert base == {"LANG": "C", "PATH": "/usr/bin"}


def test_run_opengrep_passes_a_utf8_env_and_accepts_exit_0_with_findings(monkeypatch):
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_CTYPE", raising=False)
    monkeypatch.setenv("LANG", "C")
    payload = {"results": [{"check_id": "x"}]}
    runner = EnvRecordingRunner(
        result=SubprocessResult(returncode=0, stdout=json.dumps(payload), stderr="")
    )
    assert run_semgrep(Path("/tmp/repo"), "rules/", runner=runner, scanner="opengrep") == payload
    (args, _timeout, env), = runner.calls
    assert args[0] == "opengrep"
    assert env["LC_ALL"] == "C.UTF-8"


def test_run_semgrep_passes_no_env_so_the_published_call_is_unchanged():
    # FakeRunner.run has no env parameter: passing one would raise TypeError.
    runner = FakeRunner(
        result=SubprocessResult(returncode=1, stdout='{"results": []}', stderr="")
    )
    run_semgrep(Path("/tmp/repo"), runner=runner)
    assert runner.calls[0][0][0] == "semgrep"


def test_opengrep_config_error_exit_7_names_the_scanner_and_json_error():
    stdout = json.dumps({
        "results": [],
        "errors": [{"message": "invalid configuration file found (1 configs were invalid)"}],
    })
    runner = EnvRecordingRunner(
        result=SubprocessResult(returncode=7, stdout=stdout, stderr="")
    )
    with pytest.raises(SemgrepError, match=r"opengrep exited 7: invalid configuration"):
        run_semgrep(Path("/tmp/repo"), "missing.yaml", runner=runner, scanner="opengrep")


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep not on PATH")
def test_real_opengrep_scans_under_an_ascii_locale_and_returns_source_lines(
    tmp_path, monkeypatch
):
    # Opengrep 1.30 aborts on a non-ASCII rule under a C locale unless
    # opengrep_env() steps in; this rule's message is non-ASCII on purpose.
    (tmp_path / "rule.yaml").write_text(
        "rules:\n"
        "  - id: no-eval\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "    message: n’utilisez jamais eval — évitez-le\n"
        "    pattern: eval(...)\n"
        "    metadata:\n"
        "      cwe: ['CWE-95: Eval Injection']\n",
        encoding="utf-8",
    )
    (tmp_path / "target.py").write_text("x = eval(input())\n", encoding="utf-8")
    for var in ("LC_ALL", "LC_CTYPE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LANG", "C")
    out = run_semgrep(
        tmp_path / "target.py", str(tmp_path / "rule.yaml"), timeout=300, scanner="opengrep"
    )
    (result,) = out["results"]
    assert result["extra"]["lines"] == "x = eval(input())"
