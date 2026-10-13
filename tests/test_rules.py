"""equill.rules: fetch, curate and select the open opengrep-rules. No network."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from equill import rules
from equill.pipeline import PipelineConfig, resolve_config
from equill.scan import build_semgrep_command

RULE = "rules:\n  - id: r\n    pattern: x\n    message: m\n    languages: [python]\n    severity: WARNING\n"


def _checkout(root: Path) -> Path:
    """A small opengrep-rules-shaped tree with every case curate() decides."""
    files = {
        "python/lang/security/eval.yaml": RULE,
        "python/lang/security/eval.py": "eval(x)\n",  # test target, not a rule
        "python/lang/security/audit/noisy.yaml": RULE,  # audit: dropped
        "python/lang/security/thing.test.yaml": RULE,  # fixture: dropped
        "yaml/github-actions/injection.yml": RULE,
        "yaml/github-actions/workflow.yaml": "on: push\njobs: {}\n",  # not a rule
        "generic/secrets/key.yaml": RULE,
        "javascript/xss.yaml": RULE,
        "ai/python/llm.yaml": RULE,
        "scripts/tool.yaml": RULE,  # tooling folder: dropped
        "stats/numbers.yaml": RULE,
        ".github/workflows/ci.yaml": RULE,
        "template.yaml": RULE,  # root-level file: dropped
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _tarball(src: Path, top: str = "opengrep-rules-abc") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(src, arcname=top)
    return buf.getvalue()


def test_curate_keeps_ci_rules_only(tmp_path):
    out = tmp_path / "out"
    assert rules.curate(_checkout(tmp_path / "src"), out) == 5
    kept = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert kept == [
        "ai/python/llm.yaml",
        "generic/secrets/key.yaml",
        "javascript/xss.yaml",
        "python/lang/security/eval.yaml",
        "yaml/github-actions/injection.yml",
    ]


def test_tree_digest_is_stable_and_content_sensitive(tmp_path):
    a = tmp_path / "a"
    rules.curate(_checkout(tmp_path / "src"), a)
    first = rules.tree_digest(a)
    assert rules.tree_digest(a) == first
    (a / "javascript" / "xss.yaml").write_text(RULE + "# changed\n", encoding="utf-8")
    assert rules.tree_digest(a) != first


def test_detect_dirs_follows_extensions_and_skips_dependencies(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "ui.tsx").write_text("")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.go").write_text("")
    dirs = rules.detect_dirs(tmp_path)
    assert dirs == sorted({
        "python", "ai/python", "typescript", "javascript", "ai/typescript",
        "dockerfile", "generic/dockerfile", "generic/secrets",
    })
    assert "go" not in dirs


def test_detect_dirs_always_includes_secrets(tmp_path):
    assert rules.detect_dirs(tmp_path) == ["generic/secrets"]


def test_fetch_from_tarball_verifies_digest_and_caches(tmp_path):
    src = _checkout(tmp_path / "src")
    expected = tmp_path / "expected"
    rules.curate(src, expected)
    digest = rules.tree_digest(expected)
    calls = []

    def download(url):
        calls.append(url)
        return _tarball(src)

    got = rules.fetch(cache=tmp_path / "cache", commit="abc123", digest=digest,
                      download=download, use_git=False)
    assert rules.tree_digest(got) == digest
    assert calls == ["https://codeload.github.com/opengrep/opengrep-rules/tar.gz/abc123"]
    # Second call is served from the cache.
    again = rules.fetch(cache=tmp_path / "cache", commit="abc123", digest=digest,
                        download=download, use_git=False)
    assert again == got and len(calls) == 1


def test_fetch_rejects_an_unexpected_rule_set_and_caches_nothing(tmp_path):
    src = _checkout(tmp_path / "src")
    with pytest.raises(rules.RulesError, match="unexpected rule set"):
        rules.fetch(cache=tmp_path / "cache", commit="abc123", digest="0" * 64,
                    download=lambda url: _tarball(src), use_git=False)
    assert not (tmp_path / "cache" / "opengrep-rules" / "abc123" / "ok").exists()
    assert not (tmp_path / "cache" / "opengrep-rules" / "abc123" / "rules").exists()


def test_fetch_rejects_path_traversal(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = RULE.encode()
        info = tarfile.TarInfo("../escape.yaml")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(rules.RulesError, match="unsafe path"):
        rules.fetch(cache=tmp_path / "cache", commit="abc123", digest=None,
                    download=lambda url: buf.getvalue(), use_git=False)
    assert not (tmp_path / "escape.yaml").exists()


def test_fetch_reports_a_download_failure_with_the_offline_way_out(tmp_path):
    def broken(url):
        raise OSError("no route")

    with pytest.raises(rules.RulesError, match="--config"):
        rules.fetch(cache=tmp_path / "cache", commit="abc123", download=broken, use_git=False)


def test_pinned_commit_and_digest_look_like_hashes():
    assert len(rules.RULES_COMMIT) == 40 and int(rules.RULES_COMMIT, 16) >= 0
    assert len(rules.CURATED_DIGEST) == 64 and int(rules.CURATED_DIGEST, 16) >= 0


def test_resolve_config_auto_selects_cached_rules_for_opengrep(tmp_path, monkeypatch):
    cached = tmp_path / "cache" / "rules"
    rules.curate(_checkout(tmp_path / "src"), cached)
    monkeypatch.setattr(rules, "fetch", lambda cache=None: cached)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print(1)\n")
    configs, provenance = resolve_config(PipelineConfig(repo_path=repo))
    assert [Path(c).relative_to(cached).as_posix() for c in configs] == [
        "ai/python", "generic/secrets", "python",
    ]
    assert provenance == (
        f"opengrep/opengrep-rules@{rules.RULES_COMMIT[:12]} (ai/python, generic/secrets, python)"
    )


def test_resolve_config_auto_is_p_default_for_semgrep_and_explicit_values_pass_through():
    assert resolve_config(PipelineConfig(repo_path=Path("."), scanner="semgrep")) == (
        ["p/default"], "p/default",
    )
    assert resolve_config(
        PipelineConfig(repo_path=Path("."), semgrep_config="p/python, ./my-rules")
    ) == (["p/python", "./my-rules"], "p/python, ./my-rules")


def test_build_command_repeats_config_and_keeps_semgrep_metrics_off():
    cmd = build_semgrep_command(Path("/r"), ["a", "b"], scanner="opengrep")
    assert cmd == ["opengrep", "scan", "--json", "--quiet", "--config", "a", "--config", "b", "/r"]
    assert "--metrics=off" in build_semgrep_command(Path("/r"), "p/default")
    with pytest.raises(ValueError):
        build_semgrep_command(Path("/r"), [], scanner="opengrep")


def test_cli_scan_defaults_to_opengrep_with_auto_rules():
    from typer.main import get_command

    from equill.cli import app

    scan = get_command(app).commands["scan"]
    defaults = {p.name: p.default for p in scan.params}
    assert defaults["scanner"] == "opengrep"
    assert defaults["semgrep_config"] == "auto"
