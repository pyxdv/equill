from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from equill.schema import SEMGREP_FAMILY, Scanner


class SemgrepError(RuntimeError):
    pass


@dataclass(frozen=True)
class SubprocessResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, args: list[str], timeout: int) -> SubprocessResult: ...


class SubprocessRunner:
    def run(
        self,
        args: list[str],
        timeout: int,
        env: Mapping[str, str] | None = None,
    ) -> SubprocessResult:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return SubprocessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def build_semgrep_command(
    repo_path: Path, config: str, scanner: Scanner = "semgrep"
) -> list[str]:
    """argv for one scan. Opengrep takes the same subcommand and flags, except
    that it removed telemetry and with it ``--metrics``, which it rejects (exit 2)."""
    if scanner not in SEMGREP_FAMILY:
        # Cppcheck has its own argv and output format: equill.cppcheck.
        raise ValueError(f"scanner must be one of {SEMGREP_FAMILY}, got {scanner!r}")
    args = [scanner, "scan", "--json", "--quiet"]
    if scanner == "semgrep":
        args.append("--metrics=off")
    return args + ["--config", config, str(repo_path)]


def _is_utf8(locale_name: str) -> bool:
    name = locale_name.lower()
    return "utf-8" in name or "utf8" in name


def opengrep_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment to run Opengrep in: ``base`` with a UTF-8 locale.

    Opengrep 1.30 reads rule files in the locale's encoding, so under a C/POSIX
    locale -- an unset LANG, as in many containers and CI runners -- a rule
    containing any non-ASCII byte aborts the whole scan with UnicodeDecodeError
    (exit 2, empty stdout); PYTHONUTF8=1 does not help. A locale that is already
    UTF-8 is left alone. LC_ALL outranks LC_CTYPE outranks LANG, so the first
    of them that is set decides.
    """
    env = dict(os.environ if base is None else base)
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        if env.get(var):
            if _is_utf8(env[var]):
                return env
            break
    env["LC_ALL"] = "C.UTF-8"
    return env


def _failure_detail(result: SubprocessResult, limit: int = 2000) -> str:
    """Best-effort human reason for a fatal semgrep exit.

    Under ``--json --quiet`` semgrep often writes nothing to stderr and instead
    puts the fatal error in its JSON ``errors`` array on stdout (e.g. an
    unreachable/unknown registry config, or a rule parse error). Reporting only
    stderr there yields a useless "(no stderr)", so fall back to the JSON
    errors, then to a raw stdout snippet.
    """
    stderr = result.stderr.strip()
    if stderr:
        return stderr[:limit]
    stdout = result.stdout.strip()
    if not stdout:
        return "(no output)"
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout[:limit]
    errors = data.get("errors") if isinstance(data, dict) else None
    if isinstance(errors, list) and errors:
        msgs = [
            str(e.get("long_msg") or e.get("message") or e.get("short_msg") or "").strip()
            for e in errors
            if isinstance(e, dict)
        ]
        joined = "; ".join(m for m in msgs if m)
        if joined:
            return joined[:limit]
    return stdout[:limit]


def run_semgrep(
    repo_path: Path,
    config: str = "p/default",
    timeout: int = 1800,
    runner: CommandRunner | None = None,
    scanner: Scanner = "semgrep",
) -> dict:
    """Run the scanner and return the parsed JSON output.

    Semgrep and Opengrep both exit 0 whenever the scan completes, with or
    without findings; they exit 1 on findings only under ``--error``, which
    this argv does not pass. Any other code (e.g. 2, or 7 for a bad config) is
    a fatal error. Treat 0 and 1 as success, so the check stays right if
    ``--error`` is ever added; raise SemgrepError on anything else or non-JSON
    stdout.

    The Semgrep call is unchanged from every published run: same argv, and the
    runner gets no ``env`` argument. Opengrep runs under ``opengrep_env()``.
    """
    runner = runner or SubprocessRunner()
    args = build_semgrep_command(repo_path, config, scanner)
    if scanner == "opengrep":
        result = runner.run(args=args, timeout=timeout, env=opengrep_env())  # type: ignore[call-arg]
    else:
        result = runner.run(args=args, timeout=timeout)
    if result.returncode not in (0, 1):
        raise SemgrepError(
            f"{scanner} exited {result.returncode}: {_failure_detail(result)}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise SemgrepError(f"{scanner} stdout was not valid JSON: {e}") from e


__all__ = [
    "CommandRunner",
    "SemgrepError",
    "SubprocessResult",
    "SubprocessRunner",
    "build_semgrep_command",
    "opengrep_env",
    "run_semgrep",
]
