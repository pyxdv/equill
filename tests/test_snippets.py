"""The ``requires login`` fallback: reading flagged source lines for a finding.

An unauthenticated Semgrep writes a not-logged-in placeholder instead of code.
equill.snippets reads the flagged lines back from the checkout;
equill.normalize uses it only when given a source root and only for the
placeholder, and the pipeline only under --snippet-fallback.
"""

from __future__ import annotations

import json

import pytest

from equill.normalize import normalize_result, normalize_semgrep_output
from equill.pipeline import PipelineConfig, run_pipeline
from equill.scan import SubprocessResult
from equill.schema import Report
from equill.snippets import (
    LOGIN_PLACEHOLDER,
    SnippetWindow,
    format_snippet,
    is_login_placeholder,
    read_snippet,
    resolve_source_path,
)

TEN = "".join(f"line {n}\n" for n in range(1, 11))


def _write(tmp_path, name, data: bytes | str):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        p.write_text(data, encoding="utf-8", newline="")
    else:
        p.write_bytes(data)
    return p


# --------------------------------------------------------------------------- #
# Format
# --------------------------------------------------------------------------- #
def test_format_marks_the_flagged_span_and_numbers_every_line(tmp_path):
    _write(tmp_path, "a.php", TEN)
    out = read_snippet("a.php", 5, 6, source_root=tmp_path)
    assert out == "\n".join([
        "     2 | line 2",
        "     3 | line 3",
        "     4 | line 4",
        ">    5 | line 5",
        ">    6 | line 6",
        "     7 | line 7",
        "     8 | line 8",
        "     9 | line 9",
    ])


def test_docstring_example_shape():
    lines = [f"code {n}" for n in range(1, 101)]
    out = format_snippet(lines, 91, window=SnippetWindow(context_lines=1))
    assert out.splitlines() == ["    90 | code 90", ">   91 | code 91", "    92 | code 92"]


def test_end_line_defaults_to_start_line_and_context_clamps_at_file_edges(tmp_path):
    _write(tmp_path, "a.js", TEN)
    first = read_snippet("a.js", 1, source_root=tmp_path).splitlines()
    assert first[0] == ">    1 | line 1" and len(first) == 4
    last = read_snippet("a.js", 10, source_root=tmp_path).splitlines()
    assert last[-1] == ">   10 | line 10" and len(last) == 4


def test_number_width_grows_past_four_digits():
    lines = ["x"] * 12000
    out = format_snippet(lines, 11999, window=SnippetWindow(context_lines=1))
    assert out.splitlines() == ["  11998 | x", "> 11999 | x", "  12000 | x"]


def test_zero_context_shows_only_the_span(tmp_path):
    _write(tmp_path, "a", TEN)
    out = read_snippet("a", 3, 4, source_root=tmp_path, window=SnippetWindow(context_lines=0))
    assert out == ">    3 | line 3\n>    4 | line 4"


# --------------------------------------------------------------------------- #
# Encodings and line endings
# --------------------------------------------------------------------------- #
def test_crlf_endings_are_dropped(tmp_path):
    _write(tmp_path, "w.java", "a\r\nb\r\nc\r\n")
    out = read_snippet("w.java", 2, source_root=tmp_path)
    assert "\r" not in out
    assert out.splitlines()[1] == ">    2 | b"


def test_non_utf8_bytes_are_replaced_not_raised(tmp_path):
    _write(tmp_path, "latin.php", b"ok\ncaf\xe9 = 1;\nend\n")
    out = read_snippet("latin.php", 2, source_root=tmp_path)
    assert ">    2 | caf\ufffd = 1;" in out


def test_tabs_expand_to_four_columns_and_trailing_space_is_stripped(tmp_path):
    _write(tmp_path, "t.py", "\tif x:   \n\t\treturn 1\n")
    out = read_snippet("t.py", 2, source_root=tmp_path)
    assert out.splitlines() == ["     1 |     if x:", ">    2 |         return 1"]


def test_only_newline_splits_lines_like_the_scanner(tmp_path):
    # A form feed is a line break to str.splitlines but not to Semgrep; the
    # line numbers must follow Semgrep's or the flagged line drifts.
    _write(tmp_path, "ff.c", "one\x0ctwo\nthree\n")
    out = read_snippet("ff.c", 2, source_root=tmp_path, window=SnippetWindow(context_lines=0))
    assert out == ">    2 | three"


def test_file_without_trailing_newline_keeps_its_last_line(tmp_path):
    _write(tmp_path, "n", "a\nb")
    assert read_snippet("n", 2, source_root=tmp_path, window=SnippetWindow(0)) == ">    2 | b"


# --------------------------------------------------------------------------- #
# Out of range, missing, paths
# --------------------------------------------------------------------------- #
def test_start_past_eof_or_below_one_is_none(tmp_path):
    _write(tmp_path, "a", TEN)
    assert read_snippet("a", 11, source_root=tmp_path) is None
    assert read_snippet("a", 0, source_root=tmp_path) is None
    assert read_snippet("a", -3, source_root=tmp_path) is None


def test_end_past_eof_is_clamped_and_end_before_start_is_ignored(tmp_path):
    _write(tmp_path, "a", TEN)
    out = read_snippet("a", 9, 50, source_root=tmp_path, window=SnippetWindow(0))
    assert out == ">    9 | line 9\n>   10 | line 10"
    assert read_snippet("a", 5, 2, source_root=tmp_path, window=SnippetWindow(0)) == ">    5 | line 5"


def test_missing_file_and_directory_return_none(tmp_path):
    assert read_snippet("nope.php", 1, source_root=tmp_path) is None
    (tmp_path / "dir").mkdir()
    assert read_snippet("dir", 1, source_root=tmp_path) is None


def test_empty_file_is_none(tmp_path):
    _write(tmp_path, "empty", "")
    assert read_snippet("empty", 1, source_root=tmp_path) is None


def test_absolute_path_ignores_the_root(tmp_path):
    p = _write(tmp_path, "abs/a.ts", TEN)
    assert resolve_source_path(p, "/elsewhere") == p
    assert read_snippet(str(p), 1, source_root="/elsewhere") is not None


def test_relative_path_resolves_against_the_root(tmp_path):
    _write(tmp_path, "benchmarks/x/a.ts", TEN)
    assert resolve_source_path("benchmarks/x/a.ts", tmp_path) == tmp_path / "benchmarks/x/a.ts"
    assert read_snippet("benchmarks/x/a.ts", 2, source_root=tmp_path) is not None


def test_relative_path_without_root_is_relative_to_cwd(tmp_path, monkeypatch):
    _write(tmp_path, "a", TEN)
    monkeypatch.chdir(tmp_path)
    assert read_snippet("a", 1) is not None


# --------------------------------------------------------------------------- #
# Caps
# --------------------------------------------------------------------------- #
def test_long_line_is_cut_visibly_at_the_line_cap():
    out = format_snippet(["y" * 50], 1, window=SnippetWindow(0, max_line_chars=10))
    text = out.split(" | ", 1)[1]
    assert text == "yyyyyyy..." and len(text) == 10


def test_total_cap_drops_context_farthest_first_and_keeps_the_span():
    lines = [f"l{n:02d}" for n in range(1, 21)]
    full = format_snippet(lines, 10, window=SnippetWindow(3, 80, 10_000))
    assert len(full.splitlines()) == 7
    # Room for five 13-char lines plus separators: two context lines must go.
    out = format_snippet(lines, 10, window=SnippetWindow(3, 80, 5 * 13 + 4))
    assert [ln[1:7].strip() for ln in out.splitlines()] == ["8", "9", "10", "11", "12"]
    assert len(out) <= 5 * 13 + 4


def test_total_cap_elides_the_tail_of_a_long_span():
    lines = [f"code{n}" for n in range(1, 30)]
    window = SnippetWindow(0, 80, 60)
    out = format_snippet(lines, 1, 20, window)
    assert len(out) <= 60
    assert out.splitlines()[0] == ">    1 | code1"
    assert out.splitlines()[-1].endswith("more flagged lines")


def test_a_small_cap_keeps_a_flagged_line_that_fits_and_marks_the_elision():
    # Each flagged line renders as 19 chars (">    2 | xxxxxxx..."), so line 2
    # fits the 40-char cap, and so do lines 2-3 (39), but neither fits beside
    # the full "... 2 more flagged lines" tail. The first line must survive
    # whole and the elision must still be marked -- never a hard cut that
    # doubles the line cap's "..." into "......".
    out = format_snippet(["x" * 50] * 6, 2, 4, SnippetWindow(3, 10, 40))
    assert len(out) <= 40
    assert "......" not in out
    lines = out.splitlines()
    assert lines[0] == ">    2 | xxxxxxx..."
    assert len(lines) == 2 and lines[1].strip() == "| ..."


def test_a_first_flagged_line_that_fits_alone_is_never_cut():
    # Room for line 1 but not for any elision line after it.
    line = format_snippet(["y" * 20] * 3, 1, 3, SnippetWindow(0, 80, 100))
    first = line.splitlines()[0]
    out = format_snippet(["y" * 20] * 3, 1, 3, SnippetWindow(0, 80, len(first) + 2))
    assert out == first


def test_only_a_first_line_longer_than_the_cap_is_hard_cut():
    out = format_snippet(["w" * 60] * 3, 1, 3, SnippetWindow(0, 80, 20))
    assert len(out) == 20 and out.endswith("...") and "......" not in out


@pytest.mark.parametrize("cap", [1, 3, 5, 12, 40, 200])
def test_total_cap_is_a_guarantee(cap):
    lines = ["z" * 30] * 10
    out = format_snippet(lines, 4, 6, SnippetWindow(3, 30, cap))
    assert out is not None and len(out) <= cap


def test_window_rejects_nonsense():
    with pytest.raises(ValueError):
        SnippetWindow(context_lines=-1)
    with pytest.raises(ValueError):
        SnippetWindow(max_line_chars=2)
    with pytest.raises(ValueError):
        SnippetWindow(max_total_chars=0)


def test_placeholder_detection_is_exact_after_strip():
    assert is_login_placeholder("requires login")
    assert is_login_placeholder("  requires login\n")
    assert not is_login_placeholder("requires login to view")
    assert not is_login_placeholder(None)


# --------------------------------------------------------------------------- #
# normalize: the fallback, and nothing else
# --------------------------------------------------------------------------- #
def _result(path="src/a.php", line=3, end=None, lines=LOGIN_PLACEHOLDER):
    return {
        "check_id": "php.echo",
        "path": path,
        "start": {"line": line},
        "end": {"line": end if end is not None else line},
        "extra": {
            "severity": "ERROR",
            "message": " Echoed input ",
            "lines": lines,
            "metadata": {"owasp": ["A03:2021 - Injection"], "cwe": ["CWE-79: XSS"]},
        },
    }


def test_without_a_root_the_placeholder_is_kept_verbatim(tmp_path):
    _write(tmp_path, "src/a.php", TEN)
    assert normalize_result(_result()).snippet == LOGIN_PLACEHOLDER


def test_with_a_root_the_placeholder_becomes_the_flagged_lines(tmp_path):
    _write(tmp_path, "src/a.php", TEN)
    f = normalize_result(_result(line=3, end=4), source_root=tmp_path)
    assert f.snippet == read_snippet("src/a.php", 3, 4, source_root=tmp_path)
    assert ">    3 | line 3" in f.snippet and ">    4 | line 4" in f.snippet


def test_real_scanner_lines_are_never_replaced(tmp_path):
    _write(tmp_path, "src/a.php", TEN)
    f = normalize_result(_result(lines="echo $x;"), source_root=tmp_path)
    assert f.snippet == "echo $x;"


def test_unreadable_source_keeps_the_placeholder(tmp_path):
    f = normalize_result(_result(path="gone.php"), source_root=tmp_path)
    assert f.snippet == LOGIN_PLACEHOLDER
    f = normalize_result(_result(line=99), source_root=tmp_path)
    assert f.snippet == LOGIN_PLACEHOLDER


def test_fallback_changes_only_the_snippet(tmp_path):
    _write(tmp_path, "src/a.php", TEN)
    before = normalize_result(_result())
    after = normalize_result(_result(), source_root=tmp_path)
    assert before.model_dump(exclude={"snippet"}) == after.model_dump(exclude={"snippet"})


def test_semgrep_output_threads_root_and_window(tmp_path):
    _write(tmp_path, "src/a.php", TEN)
    raw = {"results": [_result(line=5)]}
    out = normalize_semgrep_output(raw, source_root=tmp_path, window=SnippetWindow(0))
    assert out[0].snippet == ">    5 | line 5"
    assert normalize_semgrep_output(raw)[0].snippet == LOGIN_PLACEHOLDER


# --------------------------------------------------------------------------- #
# pipeline: fresh scans resolve paths the way Semgrep reports them
# --------------------------------------------------------------------------- #
class _Runner:
    def __init__(self, payload):
        self.payload = payload

    def run(self, args, timeout, env=None):
        return SubprocessResult(returncode=0, stdout=json.dumps(self.payload), stderr="")


def test_pipeline_fills_the_placeholder_only_when_asked(tmp_path, monkeypatch):
    _write(tmp_path, "src/a.php", "<?php\n$a = 1;\necho $_GET['x'];\n")
    monkeypatch.chdir(tmp_path)
    payload = {"results": [_result()]}
    # The placeholder is what an unauthenticated Semgrep writes.
    kept = run_pipeline(PipelineConfig(repo_path=tmp_path, commit_sha="c", scanner="semgrep"),
                        _Runner(payload))
    assert kept.snippet_fallback is False
    assert kept.findings[0].snippet == LOGIN_PLACEHOLDER
    filled = run_pipeline(
        PipelineConfig(repo_path=tmp_path, commit_sha="c", snippet_fallback=True,
                       scanner="semgrep"),
        _Runner(payload),
    )
    assert filled.snippet_fallback is True
    assert "echo $_GET['x'];" in filled.findings[0].snippet


def test_a_report_written_before_the_field_reads_as_no_fallback():
    data = {"benchmark": "b", "commit_sha": "c", "findings": [], "mappings": [],
            "coverage": 0.0, "mean_confidence": 0.0}
    assert Report.model_validate(data).snippet_fallback is False
