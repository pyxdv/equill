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


# --- review fixes -------------------------------------------------------------

def test_javascript_also_selects_typescript_rules(tmp_path):
    (tmp_path / "App.jsx").write_text("")
    assert "typescript" in rules.detect_dirs(tmp_path)


@pytest.mark.parametrize("name", ["Dockerfile", "dockerfile", "Dockerfile.prod", "prod.dockerfile"])
def test_dockerfile_variants_select_dockerfile_rules(tmp_path, name):
    (tmp_path / name).write_text("FROM scratch\n")
    assert {"dockerfile", "generic/dockerfile"} <= set(rules.detect_dirs(tmp_path))


def test_a_single_file_target_selects_its_language(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    assert "python" in rules.detect_dirs(f)


def test_stable_rule_id_drops_any_cache_prefix():
    from equill.pipeline import stable_rule_id

    tail = "python.flask.security.injection.subprocess-injection"
    for prefix in (
        "home.runner..cache.equill",
        "tmp.x.rules.eqcache",  # a folder named rules in the cache path
        "C:.Users.me.AppData.Local.equill",
    ):
        rid = f"{prefix}.opengrep-rules.{rules.RULES_COMMIT}.rules.{tail}"
        assert stable_rule_id(rid) == tail
    assert stable_rule_id("p.default.rule") == "p.default.rule"


def test_auto_scan_reports_stable_rule_ids_and_provenance(tmp_path, monkeypatch):
    from equill.pipeline import run_pipeline
    from equill.scan import SubprocessResult

    cached = tmp_path / "rules" / "cache" / "opengrep-rules" / rules.RULES_COMMIT / "rules"
    rules.curate(_checkout(tmp_path / "src"), cached)
    monkeypatch.setattr(rules, "fetch", lambda cache=None: cached)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("eval(x)\n")
    dotted = ".".join(p for p in cached.parts if p not in ("/", "\\"))
    payload = {"results": [{
        "check_id": f"{dotted}.python.lang.security.eval", "path": "main.py",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": "WARNING", "message": "m", "lines": "eval(x)",
                  "metadata": {"cwe": ["CWE-95"]}}}]}

    class Runner:
        def run(self, args, timeout, env=None):
            import json
            return SubprocessResult(returncode=0, stdout=json.dumps(payload), stderr="")

    report = run_pipeline(PipelineConfig(repo_path=repo, commit_sha="c"), Runner())
    assert report.findings[0].rule_id == "python.lang.security.eval"
    assert report.rules.endswith("(ai/python, generic/secrets, python)")


def test_a_peer_that_installed_the_rules_first_is_not_an_error(tmp_path):
    src = _checkout(tmp_path / "src")
    expected = tmp_path / "expected"
    rules.curate(src, expected)
    digest = rules.tree_digest(expected)
    root = tmp_path / "cache" / "opengrep-rules" / "abc123"

    def download(url):
        # Another process finishes first, while this one is downloading.
        (root / "rules").mkdir(parents=True)
        rules.curate(src, root / "rules")
        return _tarball(src)

    got = rules.fetch(cache=tmp_path / "cache", commit="abc123", digest=digest,
                      download=download, use_git=False)
    assert rules.tree_digest(got) == digest


@pytest.mark.parametrize("payload", [b"", b"not a tarball", b"\x1f\x8b\x08\x00truncated"])
def test_a_broken_download_is_a_rules_error(tmp_path, payload):
    with pytest.raises(rules.RulesError, match="offline"):
        rules.fetch(cache=tmp_path / "cache", commit="abc123", digest=None,
                    download=lambda url: payload, use_git=False)
