"""Read the flagged source lines for a finding, when the scanner withheld them.

WHY THIS EXISTS. Semgrep puts the matched source text in ``extra.lines``, and
``equill.normalize`` copies it into ``Finding.snippet`` in report.json. When
the scanner is not logged in to the Semgrep registry, that field carries the
literal placeholder ``requires login`` instead of code. With
``equill scan --snippet-fallback`` this module recovers the flagged lines from
the checkout the scan ran on, so a finding carries what the scanner flagged.
(Cppcheck echoes no code at all, so the same switch fills its snippets.)

OUTPUT FORMAT, exactly (pinned by tests/test_snippets.py)::

    "    88 | context line"
    ">   89 | flagged line"
    ">   90 | flagged line"
    "    91 | context line"

One line per source line, joined by ``\\n`` with no trailing newline. Each line
is a one-character marker (``>`` for a line inside the flagged span
``start_line..end_line``, a space for context), a space, the 1-based line number
right-aligned to ``max(4, digits of the last line shown)``, then `` | `` and the
source text. Source text is normalised so the snippet is deterministic across
checkouts: CRLF and CR endings are dropped, tabs are expanded to 4 columns,
trailing whitespace is stripped, and undecodable bytes become U+FFFD
(``errors="replace"``). A line longer than ``max_line_chars`` is cut and ends in
``...`` so it is visibly truncated.

LINE NUMBERING follows Semgrep, which counts ``\\n``-terminated lines. Python's
``str.splitlines`` also splits on form feed, vertical tab and Unicode line
separators, which would shift every later line number against the scanner's,
so the text is split on ``\\n`` only.

THE TOTAL CAP bounds the size of a stored snippet (quill sized it for a small
model's prompt). When the window exceeds ``max_total_chars``, context lines
are dropped first, farthest from the flagged span first; if the flagged span
alone is still too long, its tail is replaced by one elision line (blank
marker and number columns, then `` | ... N more flagged lines``, shortened to
`` | ...`` and then to ``...`` when a very small cap leaves no room for the
count). The first flagged line is kept whole whenever it fits the cap on its
own; only a first line longer than the whole cap is cut, and then it ends in
``...``. The result never exceeds ``max_total_chars``.

``None`` means "no code available" (missing file, a directory, an unreadable
file, a start line past the end of the file or below 1). The function never
raises for those: the caller decides what an absent snippet means.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Semgrep's stand-in for ``extra.lines`` when the CLI is not logged in.
LOGIN_PLACEHOLDER = "requires login"

TAB_WIDTH = 4
TRUNCATION_MARK = "..."
FLAGGED_MARK = ">"
CONTEXT_MARK = " "
MIN_NUMBER_WIDTH = 4


@dataclass(frozen=True)
class SnippetWindow:
    """How much source a snippet shows, and the caps that bound its size.

    The defaults are quill's, chosen against its mapping prompt's token budget:
    a 320-character line cap and a 1,200-character total cap, neither of which
    binds on the findings quill evaluated.
    """

    context_lines: int = 3
    max_line_chars: int = 320
    max_total_chars: int = 1200

    def __post_init__(self) -> None:
        if self.context_lines < 0:
            raise ValueError("context_lines must be >= 0")
        if self.max_line_chars < len(TRUNCATION_MARK) + 1:
            raise ValueError("max_line_chars is too small to hold any text")
        if self.max_total_chars < 1:
            raise ValueError("max_total_chars must be >= 1")

    def to_dict(self) -> dict[str, int]:
        return {
            "context_lines": self.context_lines,
            "max_line_chars": self.max_line_chars,
            "max_total_chars": self.max_total_chars,
        }


DEFAULT_WINDOW = SnippetWindow()


def is_login_placeholder(lines: object) -> bool:
    """True when a scanner ``extra.lines`` value is the not-logged-in stand-in."""
    return isinstance(lines, str) and lines.strip() == LOGIN_PLACEHOLDER


def resolve_source_path(path: str | Path, source_root: str | Path | None) -> Path:
    """Where a finding's file lives on disk.

    An absolute path is used as is (Semgrep reports absolute paths when it was
    given an absolute target). A relative one is joined to ``source_root``,
    which is what the scanner's paths are relative to -- the working directory
    Semgrep ran in -- or used relative to the current directory when no root is
    given.
    """
    p = Path(path)
    if p.is_absolute() or source_root is None:
        return p
    return Path(source_root) / p


def _read_lines(path: Path) -> list[str] | None:
    try:
        raw = path.read_bytes()
    except (OSError, ValueError):
        return None
    text = raw.decode("utf-8", errors="replace")
    if not text:
        return []
    lines = text.split("\n")
    # "a\nb\n" is two lines, not three: the empty tail after a final newline is
    # not a source line Semgrep could flag.
    if lines and lines[-1] == "" and text.endswith("\n"):
        lines.pop()
    return lines


def _clean(line: str, max_line_chars: int) -> str:
    # CR at end of line (CRLF files) is a line ending, not content; a stray CR
    # mid-line would move the terminal cursor in a rendered prompt log.
    line = line.rstrip("\r").replace("\r", " ")
    line = line.expandtabs(TAB_WIDTH).rstrip()
    if len(line) > max_line_chars:
        line = line[: max_line_chars - len(TRUNCATION_MARK)] + TRUNCATION_MARK
    return line


def _render(rows: list[tuple[int, bool, str]], width: int) -> list[str]:
    return [
        f"{FLAGGED_MARK if flagged else CONTEXT_MARK} {n:>{width}} | {text}"
        for n, flagged, text in rows
    ]


def _joined_len(lines: list[str]) -> int:
    return sum(len(s) for s in lines) + max(len(lines) - 1, 0)


def format_snippet(
    lines: list[str],
    start_line: int,
    end_line: int | None = None,
    window: SnippetWindow = DEFAULT_WINDOW,
) -> str | None:
    """Render the flagged span of already-split ``lines`` (see module docstring).

    Split out of ``read_snippet`` so the formatting and capping logic is testable
    on in-memory text, without a file.
    """
    n_lines = len(lines)
    if start_line < 1 or start_line > n_lines:
        return None
    end = start_line if end_line is None or end_line < start_line else end_line
    end = min(end, n_lines)
    first = max(1, start_line - window.context_lines)
    last = min(n_lines, end + window.context_lines)

    rows = [
        (n, start_line <= n <= end, _clean(lines[n - 1], window.max_line_chars))
        for n in range(first, last + 1)
    ]
    width = max(MIN_NUMBER_WIDTH, len(str(last)))

    # Drop context, farthest from the span first (ties: the trailing side, so
    # the lines leading into the flagged code survive longest).
    while _joined_len(_render(rows, width)) > window.max_total_chars:
        lead = start_line - rows[0][0] if not rows[0][1] else -1
        trail = rows[-1][0] - end if not rows[-1][1] else -1
        if lead < 0 and trail < 0:
            break
        if trail >= lead:
            rows.pop()
        else:
            rows.pop(0)

    rendered = _render(rows, width)
    if _joined_len(rendered) <= window.max_total_chars:
        return "\n".join(rendered)

    # Only flagged lines remain and they still do not fit: keep the longest
    # prefix of them that fits with an elision line after it. The counted
    # elision line is preferred; only when not even one flagged line fits
    # beside it is it shortened, and a line that fits is never cut.
    cap = window.max_total_chars
    pad = " " * (width + 2)
    tails = (
        lambda n: f"{pad} | ... {n} more flagged line{'s' if n != 1 else ''}",
        lambda n: f"{pad} | {TRUNCATION_MARK}",
        lambda n: TRUNCATION_MARK,
    )
    for tail in tails:
        for keep in range(len(rows) - 1, 0, -1):
            candidate = rendered[:keep] + [tail(len(rows) - keep)]
            if _joined_len(candidate) <= cap:
                return "\n".join(candidate)
    head = rendered[0]
    if len(head) <= cap:
        # Not even "\n..." fits beside the first line: keep that line whole
        # rather than cutting text that fits.
        return head
    # The first flagged line alone exceeds the cap: hard-cut it, keeping the
    # cap a guarantee.
    if cap <= len(TRUNCATION_MARK):
        return head[:cap]
    return head[: cap - len(TRUNCATION_MARK)] + TRUNCATION_MARK


def read_snippet(
    path: str | Path,
    start_line: int,
    end_line: int | None = None,
    *,
    source_root: str | Path | None = None,
    window: SnippetWindow = DEFAULT_WINDOW,
) -> str | None:
    """Numbered source for lines ``start_line..end_line`` plus context, or None.

    ``end_line`` defaults to ``start_line`` (a recorded ``Finding`` carries only
    a start line). An ``end_line`` past the end of the file is clamped; a
    ``start_line`` outside the file, a missing path, a directory or an
    unreadable file returns ``None``. Pure apart from reading ``path``.
    """
    resolved = resolve_source_path(path, source_root)
    if not resolved.is_file():
        return None
    lines = _read_lines(resolved)
    if lines is None:
        return None
    return format_snippet(lines, start_line, end_line, window)


__all__ = [
    "DEFAULT_WINDOW",
    "LOGIN_PLACEHOLDER",
    "SnippetWindow",
    "format_snippet",
    "is_login_placeholder",
    "read_snippet",
    "resolve_source_path",
]
