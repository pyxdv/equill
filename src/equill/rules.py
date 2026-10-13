"""Open rules for the default scanner: opengrep-rules, fetched, curated, selected.

equill's default scanner is Opengrep with the rules of ``opengrep/opengrep-rules``,
the community fork of semgrep-rules from before Semgrep's licence change. Those
rules are LGPL-2.1 with the Commons Clause: free to use and redistribute, not to
sell. Semgrep Registry packs (``p/default``) are under the Semgrep Rules License
instead, which allows internal use only, and an unauthenticated Semgrep withholds
the matched code; neither applies here.

Three steps, each deterministic:

* **fetch** gets the repository at ``RULES_COMMIT`` (a pinned commit, so the
  rule set never moves under a user) once per machine into the cache: with git
  when it is installed (a fetch by commit id, which git verifies by content),
  else as GitHub's source tarball;
* **curate** keeps the files that are rules and are meant for routine CI: it
  drops test fixtures, ``audit`` rules (written for manual security audits and
  noisy by design), and the repository's tooling folders. The curated tree is
  checked against ``CURATED_DIGEST``, so a tampered or truncated download fails
  loudly instead of scanning with fewer rules;
* **select** picks the rule folders for the languages present in the target, by
  file extension. Opengrep parses every rule it is given before it scans, and
  all 1,450 curated rules cost over a minute on a one-file repository; the
  languages actually present cost seconds.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

RULES_REPO = "opengrep/opengrep-rules"
RULES_COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa"  # 2025-01-26
RULES_LICENSE = "LGPL-2.1 with the Commons Clause"
# sha256 over the curated tree (see tree_digest); pinned with RULES_COMMIT.
CURATED_DIGEST = "7bfab1332a293d1fc54d5ef555e511aafc1f5238b1ac2c4a5d5bb0044a69380f"

# Top-level folders that hold tooling, statistics or duplicate packs, not rules
# for a language.
_SKIP_TOP = frozenset({"scripts", "stats", "problem-based-packs", "trusted_python"})
_TEST_FILE = re.compile(r"\.test\.ya?ml$")
_IS_RULE = re.compile(r"(?m)^rules:\s*$")

# File extension (or exact file name) -> rule folders. ``ai/<lang>`` folders
# hold rules about LLM API use in that language and ride along with it.
_LANGUAGE_DIRS: dict[str, tuple[str, ...]] = {
    ".py": ("python", "ai/python"),
    ".pyi": ("python",),
    ".js": ("javascript",),
    ".mjs": ("javascript",),
    ".cjs": ("javascript",),
    ".jsx": ("javascript",),
    ".ts": ("typescript", "javascript", "ai/typescript"),
    ".tsx": ("typescript", "javascript", "ai/typescript"),
    ".java": ("java",),
    ".go": ("go", "ai/go"),
    ".php": ("php",),
    ".rb": ("ruby",),
    ".cs": ("csharp", "ai/csharp"),
    ".c": ("c",),
    ".h": ("c",),
    ".cc": ("c",),
    ".cpp": ("c",),
    ".hpp": ("c",),
    ".kt": ("kotlin", "ai/kotlin"),
    ".kts": ("kotlin", "ai/kotlin"),
    ".scala": ("scala",),
    ".rs": ("rust",),
    ".swift": ("swift", "ai/swift"),
    ".dart": ("ai/dart",),
    ".ex": ("elixir",),
    ".exs": ("elixir",),
    ".clj": ("clojure",),
    ".cljs": ("clojure",),
    ".cljc": ("clojure",),
    ".ml": ("ocaml",),
    ".mli": ("ocaml",),
    ".sol": ("solidity",),
    ".cls": ("apex",),
    ".trigger": ("apex",),
    ".sh": ("bash",),
    ".bash": ("bash",),
    ".tf": ("terraform",),
    ".hcl": ("terraform",),
    ".yml": ("yaml",),
    ".yaml": ("yaml",),
    ".json": ("json",),
    ".html": ("html",),
    "Dockerfile": ("dockerfile", "generic/dockerfile"),
}
# Always included: hard-coded secrets matter in any repository.
ALWAYS_DIRS: tuple[str, ...] = ("generic/secrets",)

# Directories never walked when detecting languages: dependencies, build output
# and VCS metadata say nothing about the code under review.
_IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", ".venv", "venv",
    "env", "__pycache__", "dist", "build", "target", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "bower_components",
})


class RulesError(RuntimeError):
    pass


def cache_root() -> Path:
    """Where fetched rules live: $EQUILL_CACHE, else $XDG_CACHE_HOME/equill,
    else ~/.cache/equill."""
    if os.environ.get("EQUILL_CACHE"):
        return Path(os.environ["EQUILL_CACHE"])
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "equill"


def curate(src: Path, dst: Path) -> int:
    """Copy the CI-worthy rule files from a checkout ``src`` to ``dst``.

    Keeps ``*.yaml``/``*.yml`` files below a language folder that declare a
    top-level ``rules:`` key; drops ``*.test.yaml`` fixtures, anything under an
    ``audit`` folder, root-level files and the tooling folders. Returns the
    number of rule files kept.
    """
    kept = 0
    for root, dirs, files in os.walk(src):
        dirs.sort()
        rel = Path(root).relative_to(src)
        parts = rel.parts
        if parts and (parts[0] in _SKIP_TOP or parts[0].startswith(".")):
            dirs[:] = []
            continue
        if not parts:
            continue  # root-level files are templates and docs, not rules
        if "audit" in parts:
            continue
        for name in sorted(files):
            if not name.endswith((".yaml", ".yml")) or _TEST_FILE.search(name):
                continue
            path = Path(root) / name
            text = path.read_text(encoding="utf-8", errors="replace")
            if not _IS_RULE.search(text):
                continue
            out = dst / rel / name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, out)
            kept += 1
    return kept


def tree_digest(root: Path) -> str:
    """sha256 over every file's relative path and content, in sorted order."""
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(path.relative_to(root).as_posix().encode())
        h.update(b"\0")
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https URL
        return resp.read()


def _git_checkout(commit: str, dest: Path) -> Path | None:
    """Check ``commit`` out into ``dest`` with git; None when git is missing."""
    git = shutil.which("git")
    if git is None:
        return None
    url = f"https://github.com/{RULES_REPO}"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    steps = (
        [git, "init", "-q", str(dest)],
        [git, "-C", str(dest), "fetch", "-q", "--depth", "1", url, commit],
        [git, "-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"],
    )
    for argv in steps:
        done = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=300,
                              check=False)
        if done.returncode != 0:
            raise RulesError(
                f"git could not fetch {RULES_REPO}@{commit[:12]}: "
                f"{(done.stderr or done.stdout).strip()[:500]}"
            )
    head = subprocess.run([git, "-C", str(dest), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=False).stdout.strip()
    if head != commit:
        raise RulesError(f"git checked out {head[:12]}, not {commit[:12]}")
    return dest


def _extract(tarball: bytes, dest: Path) -> Path:
    """Extract a GitHub source tarball safely; return its single top folder."""
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise RulesError(f"unsafe path in rules archive: {member.name}")
            if not (member.isfile() or member.isdir()):
                continue
            if hasattr(tarfile, "data_filter"):  # 3.12+, backported to 3.11.4
                tar.extract(member, dest, filter="data")
            else:  # pragma: no cover - older 3.11
                tar.extract(member, dest)  # noqa: S202 - members checked above
    tops = [p for p in dest.iterdir() if p.is_dir()]
    if len(tops) != 1:
        raise RulesError("unexpected layout in rules archive")
    return tops[0]


def fetch(
    cache: Path | None = None,
    commit: str = RULES_COMMIT,
    digest: str | None = CURATED_DIGEST,
    download=_download,
    use_git: bool = True,
) -> Path:
    """Return the curated rules folder for ``commit``, fetching it if needed.

    The commit is fetched with git when available, else downloaded as GitHub's
    source tarball (``download``). The curated tree is verified against ``digest`` (pass None to skip, e.g. for a commit
    other than the pinned one) before it is moved into place, so an interrupted
    or altered download never becomes the cached rule set.
    """
    root = (cache or cache_root()) / "opengrep-rules" / commit
    rules = root / "rules"
    if (root / "ok").is_file() and rules.is_dir():
        return rules
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as tmp:
        checkout = _git_checkout(commit, Path(tmp) / "git") if use_git else None
        if checkout is None:
            url = f"https://codeload.github.com/{RULES_REPO}/tar.gz/{commit}"
            try:
                tarball = download(url)
            except OSError as e:
                raise RulesError(
                    f"could not download {RULES_REPO}@{commit[:12]} ({e}); pass --config "
                    "with a local rules folder to scan offline"
                ) from e
            checkout = _extract(tarball, Path(tmp) / "src")
        staged = Path(tmp) / "rules"
        staged.mkdir()
        if not curate(checkout, staged):
            raise RulesError("the rules archive held no rule files")
        if digest is not None and (got := tree_digest(staged)) != digest:
            raise RulesError(
                f"{RULES_REPO}@{commit[:12]} curated to an unexpected rule set "
                f"(sha256 {got[:16]}…, expected {digest[:16]}…)"
            )
        if rules.exists():
            shutil.rmtree(rules)
        staged.rename(rules)
    (root / "ok").write_text(commit + "\n", encoding="utf-8")
    return rules


def detect_dirs(target: Path, max_files: int = 200_000) -> list[str]:
    """Rule folders for the languages present under ``target``, sorted."""
    dirs: set[str] = set(ALWAYS_DIRS)
    seen = 0
    for _root, subdirs, files in os.walk(target):
        subdirs[:] = [d for d in subdirs if d not in _IGNORE_DIRS]
        for name in files:
            seen += 1
            key = name if name in _LANGUAGE_DIRS else os.path.splitext(name)[1].lower()
            if key == "dockerfile" or name.startswith("Dockerfile"):
                key = "Dockerfile"
            dirs.update(_LANGUAGE_DIRS.get(key, ()))
        if seen >= max_files:
            break
    return sorted(dirs)


def select(rules: Path, target: Path) -> list[Path]:
    """Existing rule folders under ``rules`` for the languages in ``target``."""
    return [rules / d for d in detect_dirs(target) if (rules / d).is_dir()]


def resolve_auto(target: Path, scanner: str, cache: Path | None = None) -> list[str]:
    """What ``--config auto`` means for a scanner: the selected open rules for
    Opengrep, Semgrep's own ``p/default`` registry pack for Semgrep."""
    if scanner == "semgrep":
        return ["p/default"]
    return [str(p) for p in select(fetch(cache), target)]


__all__ = [
    "ALWAYS_DIRS",
    "CURATED_DIGEST",
    "RULES_COMMIT",
    "RULES_LICENSE",
    "RULES_REPO",
    "RulesError",
    "cache_root",
    "curate",
    "detect_dirs",
    "fetch",
    "resolve_auto",
    "select",
    "tree_digest",
]
