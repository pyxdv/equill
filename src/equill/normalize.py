from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from equill.schema import Finding, Severity
from equill.snippets import DEFAULT_WINDOW, SnippetWindow, is_login_placeholder, read_snippet

_OWASP_ID = re.compile(r"\bA\d{1,2}:\d{4}\b")
_CWE_ID = re.compile(r"\bCWE-\d+\b")

_VALID_SEVERITIES: set[Severity] = {"INFO", "WARNING", "ERROR"}
_SEVERITY_ALIASES: dict[str, Severity] = {
    "info": "INFO",
    "warning": "WARNING",
    "error": "ERROR",
    "low": "INFO",
    "medium": "WARNING",
    "high": "ERROR",
    "critical": "ERROR",
}


def _extract_ids(values: Any, pattern: re.Pattern[str]) -> list[str]:
    """Extract de-duplicated IDs from a string, list of strings, or nested list."""
    if values is None:
        return []
    if isinstance(values, str):
        items = [values]
    elif isinstance(values, list):
        items = [str(v) for v in values]
    else:
        items = [str(values)]
    seen: list[str] = []
    for item in items:
        for match in pattern.findall(item):
            if match not in seen:
                seen.append(match)
    return seen


def _coerce_severity(value: Any) -> Severity:
    if isinstance(value, str):
        upper = value.upper()
        if upper in _VALID_SEVERITIES:
            return upper  # type: ignore[return-value]
        lower = value.lower()
        if lower in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[lower]
    return "WARNING"


def _snippet(
    result: dict[str, Any],
    extra: dict[str, Any],
    source_root: str | Path | None,
    window: SnippetWindow,
) -> str:
    """``extra.lines`` as the scanner gave it, or source code in its place.

    Semgrep writes the literal ``requires login`` into ``extra.lines`` when the
    CLI is not logged in to its registry, so a finding would carry no code at
    all (``equill.snippets``). With a ``source_root`` --
    the directory the scanner's paths are relative to -- that placeholder is
    replaced by the flagged lines read from the checkout. Anything else, and
    every call without a root, keeps the scanner's text exactly as before. If
    the file cannot be read the placeholder is kept, so a caller that needs
    code can see it is missing rather than receive an empty string.
    """
    lines = str(extra.get("lines", "")).strip()
    if source_root is None or not is_login_placeholder(lines):
        return lines
    start = result.get("start") or {}
    end = result.get("end") or {}
    start_line = int(start.get("line", 0) or 0)
    end_line = int(end.get("line", 0) or 0) or None
    code = read_snippet(
        str(result.get("path", "")),
        start_line,
        end_line,
        source_root=source_root,
        window=window,
    )
    return lines if code is None else code


def normalize_result(
    result: dict[str, Any],
    source_root: str | Path | None = None,
    window: SnippetWindow = DEFAULT_WINDOW,
) -> Finding:
    """Convert a single semgrep result dict into a Finding.

    ``source_root`` enables the ``requires login`` fallback (see ``_snippet``);
    omitted, the output is what it has always been.
    """
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    start = result.get("start") or {}
    return Finding(
        rule_id=str(result.get("check_id", "")),
        file=str(result.get("path", "")),
        line=int(start.get("line", 0) or 0),
        owasp=_extract_ids(metadata.get("owasp"), _OWASP_ID),
        cwe=_extract_ids(metadata.get("cwe"), _CWE_ID),
        severity=_coerce_severity(extra.get("severity")),
        message=str(extra.get("message", "")).strip(),
        snippet=_snippet(result, extra, source_root, window),
    )


def normalize_semgrep_output(
    raw: dict[str, Any],
    source_root: str | Path | None = None,
    window: SnippetWindow = DEFAULT_WINDOW,
) -> list[Finding]:
    """Convert a parsed `semgrep --json` payload into a list of Findings."""
    results = raw.get("results") or []
    return [normalize_result(r, source_root, window) for r in results]


__all__ = ["normalize_result", "normalize_semgrep_output"]
