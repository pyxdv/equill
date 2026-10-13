"""Cppcheck as an equill scanner: run it, read its XML, filter and classify.

Cppcheck is the C/C++ input of the Phase 2 study (quill's ``docs/PHASE2_IDEAS.md``
5.1-5.1e). Unlike Semgrep's security packs, almost every Cppcheck finding is a
quality finding (dead code, const-correctness, leaks, null checks), so it is
the first input on which the ISO/IEC 25010 characteristic level is a real
classification rather than the constant ``security``. Three things the 5.1b
triage measured are built in here rather than left to the reader:

* **test paths are excluded** by default (``DEFAULT_PATH_EXCLUDE``): the
  in-table hits on mosquitto were all under ``test/``;
* **each finding carries its checker's prior class** (``evidence_class``), so
  the scorer can leave the ~78 % stylistic NOISE and the known-false GATE
  checkers out of the burden;
* **secondary locations are kept** (``related_locations``) so
  ``equill.rootcause`` can fold the seven reports one unchecked ``malloc``
  produced into one site.

Cppcheck writes its XML report to **stderr** (``--xml``), with any progress on
stdout; exit code 0 means the analysis ran, with or without findings.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from equill.checker_table import CheckerEntry
from equill.scan import CommandRunner, SubprocessRunner
from equill.schema import Finding, Severity
from equill.snippets import DEFAULT_WINDOW, SnippetWindow, read_snippet

# Cppcheck's own status records, which are not findings about the code.
NOT_FINDINGS: frozenset[str] = frozenset(
    {"missingInclude", "missingIncludeSystem", "syntaxError", "checkersReport", "unknownMacro"}
)

# The 5.1b setup: every check class except the noisy "information" tier.
DEFAULT_ENABLE = "warning,style,performance,portability"

# The 5.1b exclusion, as one pattern over each path segment: test, fuzz and
# example directories and ``*_test`` / ``test_*`` / ``util_*test*`` names.
DEFAULT_PATH_EXCLUDE = (
    r"^(test|tests|tst|testing|unittest|fuzz|examples?)$|_test$|^test_|^util_.*test"
)

# Cppcheck severities -> equill's three-level scale. ``error`` is a defect the
# tool is sure of; ``warning`` a probable one; the other tiers are advice.
_SEVERITY: dict[str, Severity] = {
    "error": "ERROR",
    "warning": "WARNING",
    "style": "INFO",
    "performance": "INFO",
    "portability": "INFO",
    "information": "INFO",
    "debug": "INFO",
}

RULE_PREFIX = "cppcheck."


class CppcheckError(RuntimeError):
    pass


def build_cppcheck_command(
    repo_path: Path, enable: str = DEFAULT_ENABLE, max_configs: int = 1
) -> list[str]:
    """argv for one scan: XML v2 report, the 5.1b check classes, one
    preprocessor configuration per file (the whole-project setting 5.1b used)."""
    return [
        "cppcheck",
        "--xml",
        "--xml-version=2",
        f"--enable={enable}",
        f"--max-configs={max_configs}",
        "--quiet",
        str(repo_path),
    ]


def run_cppcheck(
    repo_path: Path,
    enable: str = DEFAULT_ENABLE,
    timeout: int = 3600,
    runner: CommandRunner | None = None,
) -> str:
    """Run Cppcheck and return its XML report (stderr) as text.

    Exit 0 is the only success code without ``--error-exitcode``; anything
    else, or output that is not a Cppcheck ``<results>`` document, raises.
    """
    runner = runner or SubprocessRunner()
    result = runner.run(args=build_cppcheck_command(repo_path, enable), timeout=timeout)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "(no output)").strip()[:2000]
        raise CppcheckError(f"cppcheck exited {result.returncode}: {detail}")
    xml_text = result.stderr
    if "<results" not in xml_text:
        raise CppcheckError("cppcheck stderr did not contain an XML <results> report")
    return xml_text


def checker_id(finding: Finding) -> str | None:
    """The Cppcheck checker id behind a finding, or None for other scanners."""
    if finding.rule_id.startswith(RULE_PREFIX):
        return finding.rule_id[len(RULE_PREFIX):]
    return None


def parse_cppcheck_xml(
    xml_text: str,
    source_root: str | Path | None = None,
    window: SnippetWindow = DEFAULT_WINDOW,
) -> list[Finding]:
    """Cppcheck XML v2 -> Findings, in document order.

    Status records (``NOT_FINDINGS``) and errors without a location are
    dropped. The first ``<location>`` is the finding's file and line; the rest
    become ``related_locations``. ``rule_id`` is ``cppcheck.<checker id>`` and
    ``cwe`` the tool's own tag when it gives one. The snippet is the flagged
    source read from ``source_root`` when one is given, else empty: Cppcheck
    does not echo code, so there is no scanner text to keep.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise CppcheckError(f"cppcheck output was not well-formed XML: {e}") from e
    findings: list[Finding] = []
    for err in root.iter("error"):
        cid = err.get("id") or ""
        if not cid or cid in NOT_FINDINGS:
            continue
        locs = [
            (loc.get("file") or "", int(loc.get("line") or 0))
            for loc in err.iter("location")
            if loc.get("file")
        ]
        if not locs:
            continue
        file, line = locs[0]
        cwe = (err.get("cwe") or "").strip()
        snippet = ""
        if source_root is not None:
            snippet = read_snippet(file, line, source_root=source_root, window=window) or ""
        findings.append(
            Finding(
                rule_id=RULE_PREFIX + cid,
                file=file,
                line=max(line, 0),
                owasp=[],
                cwe=[f"CWE-{cwe}"] if cwe else [],
                severity=_SEVERITY.get((err.get("severity") or "").lower(), "INFO"),
                message=(err.get("msg") or err.get("verbose") or "").strip(),
                snippet=snippet,
                related_locations=[f"{f}:{ln}" for f, ln in locs[1:]],
            )
        )
    return findings


def path_is_excluded(path: str, pattern: str | re.Pattern[str]) -> bool:
    """True when any directory or the file stem of ``path`` matches ``pattern``.

    Segments are matched one at a time, so ``src/net.c`` survives while
    ``test/net.c``, ``lib/tests/x.c``, ``x_test.c`` and ``test_x.c`` do not. The
    stem is matched against the same pattern as a directory, so a source file
    named ``testing.c`` or ``fuzz.c`` is excluded too: conservative, and the
    pattern is recorded in the report so a reader can see what was dropped.
    """
    rx = re.compile(pattern) if isinstance(pattern, str) else pattern
    parts = Path(path).parts
    segments = list(parts[:-1]) + ([Path(parts[-1]).stem] if parts else [])
    return any(rx.search(seg) for seg in segments)


def _relative_to(path: str, base: Path | None) -> str:
    """``path`` relative to ``base`` when it lies under it, else unchanged.

    Cppcheck reports the path as it was given, so a scan of ``/home/pi/testing/gw``
    puts ``testing`` in every path. The exclusion is about the repository's own
    layout, so it is matched below the scanned root, not on the directories
    above it. A recorded report from another machine (``--scanner-output``)
    whose paths are not under ``base`` is matched as written.
    """
    if base is None:
        return path
    try:
        return Path(path).resolve().relative_to(Path(base).resolve()).as_posix()
    except (ValueError, OSError):
        return path


def exclude_paths(findings: list[Finding], pattern: str | None, base: Path | None = None) -> list[Finding]:
    """Drop findings whose path, taken below ``base`` when it lies there,
    matches ``pattern``; ``None`` keeps everything."""
    if not pattern:
        return findings
    rx = re.compile(pattern)
    return [f for f in findings if not path_is_excluded(_relative_to(f.file, base), rx)]


def classify(findings: list[Finding], table: dict[str, CheckerEntry]) -> list[Finding]:
    """Attach each finding's checker prior class from the table.

    A checker the table does not know keeps ``evidence_class`` None, which the
    scorer counts in full: an unknown checker is unclassified, not noise.
    """
    out: list[Finding] = []
    for f in findings:
        cid = checker_id(f)
        entry = table.get(cid) if cid else None
        if entry is None:
            out.append(f)
        else:
            out.append(f.model_copy(update={"evidence_class": entry.evidence_class}))
    return out


__all__ = [
    "DEFAULT_ENABLE",
    "DEFAULT_PATH_EXCLUDE",
    "NOT_FINDINGS",
    "RULE_PREFIX",
    "CppcheckError",
    "build_cppcheck_command",
    "checker_id",
    "classify",
    "exclude_paths",
    "parse_cppcheck_xml",
    "path_is_excluded",
    "run_cppcheck",
]
