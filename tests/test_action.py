"""The GitHub Action (action.yml + scripts/equill_action.sh), run without GitHub.

The action's logic lives in the script so it can be driven here with a recorded
Semgrep JSON: no scanner, no network, no runner. What a workflow relies on is
pinned: the artifacts exist, SARIF paths are relative to the scanned checkout,
the step outputs and the job summary are written, and the exit code is the
gate's verdict -- but only after the page is on the summary.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "equill_action.sh"

# Shared with the `action` job in .github/workflows/ci.yml, which maps the
# same file through action.yml on a real runner and expects the gate to fail.
SEMGREP_FIXTURE = REPO / "tests" / "data" / "action_semgrep.json"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _equill_shim(bin_dir: Path) -> Path:
    """An `equill` executable that runs this interpreter's equill.cli."""
    shim = bin_dir / "equill"
    shim.write_text(
        f'#!/usr/bin/env bash\nexec "{sys.executable}" -m equill.cli "$@"\n', encoding="utf-8"
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    return shim


def _run(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess, Path, Path, Path]:
    ws = tmp_path / "ws"
    ws.mkdir()
    shutil.copy(SEMGREP_FIXTURE, ws / "semgrep.json")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_output = tmp_path / "gh_output"
    gh_summary = tmp_path / "gh_summary"
    gh_summary.write_text("earlier step\n", encoding="utf-8")
    pythonpath = os.pathsep.join(
        p for p in (str(REPO / "src"), os.environ.get("PYTHONPATH", "")) if p
    )
    full_env = {
        **os.environ,
        "PYTHONPATH": pythonpath,
        "EQUILL_BIN": str(_equill_shim(bin_dir)),
        "EQUILL_PYTHON": sys.executable,
        "EQUILL_SCANNER_OUTPUT": "semgrep.json",
        "EQUILL_NAME": "demo",
        "GITHUB_OUTPUT": str(gh_output),
        "GITHUB_STEP_SUMMARY": str(gh_summary),
        **env,
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT)], check=False, cwd=ws, env=full_env, capture_output=True, text=True,
        timeout=120,
    )
    return proc, ws, gh_output, gh_summary


def _outputs(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


@needs_bash
def test_action_writes_artifacts_outputs_and_summary(tmp_path):
    proc, ws, gh_output, gh_summary = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = ws / "equill-report"
    for name in ("report.json", "report.sarif", "scores.json", "summary.md"):
        assert (out / name).is_file(), name

    outputs = _outputs(gh_output)
    assert outputs == {
        "report": "equill-report/report.json",
        "sarif": "equill-report/report.sarif",
        "scores": "equill-report/scores.json",
        "summary": "equill-report/summary.md",
        "findings": "2",
        "mapped": "1",
        "actionable": "1",
        "sites": "1",
        "gate": "passed",
    }

    summary = gh_summary.read_text(encoding="utf-8")
    assert summary.startswith("earlier step\n## equill")  # appended, not overwritten
    assert "**demo**" in summary
    assert "| CWE-601 | 1 |" in summary

    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]]
    assert uris == ["src/index.js", "src/r.js"]


@needs_bash
def test_failed_gate_exits_1_after_publishing(tmp_path):
    proc, _ws, gh_output, gh_summary = _run(tmp_path, EQUILL_FAIL_ON="security")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _outputs(gh_output)["gate"] == "failed"
    assert "Quality gate: failed" in gh_summary.read_text(encoding="utf-8")


@needs_bash
def test_max_actionable_gate(tmp_path):
    proc, _, gh_output, _ = _run(tmp_path, EQUILL_MAX_ACTIONABLE="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _outputs(gh_output)["gate"] == "passed"


@needs_bash
def test_an_equill_error_is_not_reported_as_a_gate_verdict(tmp_path):
    proc, _, gh_output, gh_summary = _run(tmp_path, EQUILL_FAIL_ON="secruity")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert not gh_output.exists()
    assert gh_summary.read_text(encoding="utf-8") == "earlier step\n"


def test_action_yml_wires_every_input_and_output():
    action = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    run_step = next(s for s in steps if s.get("id") == "run")
    assert run_step["run"].endswith('bash "$GITHUB_ACTION_PATH/scripts/equill_action.sh"')

    env_values = " ".join(str(v) for v in run_step["env"].values())
    used = set(re.findall(r"inputs\.([a-z-]+)", env_values))
    install_only = {"semgrep-version", "python-version", "opengrep-version", "opengrep-sha256"}
    assert used | install_only == set(action["inputs"])

    script = SCRIPT.read_text(encoding="utf-8")
    written = set(re.findall(r'echo "([a-z]+)=', script))
    assert written == set(action["outputs"])
    for name, spec in action["outputs"].items():
        assert spec["value"] == f"${{{{ steps.run.outputs.{name} }}}}"

    # The tables ship inside the package the action installs.
    assert (REPO / "src" / "equill" / "data" / "cwe_to_iso25010.csv").is_file()
    assert (REPO / "src" / "equill" / "data" / "cppcheck_checker_iso.csv").is_file()


def test_action_leaves_the_callers_python_and_path_alone():
    """setup-python must not repoint the caller's python, and the Semgrep venv
    (which holds its own python and pip) must not reach GITHUB_PATH."""
    action = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    setup = next(s for s in steps if str(s.get("uses", "")).startswith("actions/setup-python"))
    assert setup["with"]["update-environment"] is False
    for step in steps:
        assert "GITHUB_PATH" not in str(step.get("run", "")), step.get("name")
        assert "GITHUB_ENV" not in str(step.get("run", "")), step.get("name")
    run_step = next(s for s in steps if s.get("id") == "run")
    assert "semgrep-venv/bin" in run_step["run"]
