"""Mine a repository's own history for bug fixes, and turn each into an instance.

This is the bridge from benchmark to product. On a customer's codebase there is no
curated corpus and no gold patch -- but there *is* a git history full of bug fixes,
and every one of them is a rediscovery instance whose oracle the customer wrote
themselves.

That yields the only pre-sales artifact in this category that is evidence rather than
a promise: "we replayed your last 50 bug fixes, found 11 of them blind, at $4 each,
and here are the failing tests." It is measured on their code, in their domain,
against bugs their own team shipped.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Instance

# Commit messages that claim to fix something. Deliberately broad: the expensive
# mistake is missing real fixes, and the cheap filters below remove the noise.
FIX_RE = re.compile(
    r"\b(fix(e[sd])?|bug|defect|regression|incorrect|wrong|broken|crash(es|ed)?|"
    r"fail(s|ed|ure)?|error|off.by.one|leak)\b",
    re.IGNORECASE,
)
# Messages that match FIX_RE but are not bug fixes.
NOT_A_FIX_RE = re.compile(
    r"\b(typos?|lint(ing)?|format(ting)?|whitespace|docs?|readme|changelog|comments?|"
    r"bump|release|merge branch|revert|rename[ds]?|refactor(ing)?|"
    r"tox|ci|mypy|flake8|coverage)\b",
    re.IGNORECASE,
)

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".rs"}
TEST_HINT = re.compile(r"(^|/)(tests?|spec)s?/|(^|/)test_|_test\.|\.spec\.|\.test\.")


@dataclass
class WitnessSpec:
    """A mined regression test, narrowed to the tests the fix introduced."""
    path: str
    stage_as: str
    select: str


@dataclass
class FixCommit:
    sha: str
    parent: str
    subject: str
    source_files: list[str]
    test_files: list[str]
    changed_lines: int

    @property
    def has_regression_test(self) -> bool:
        """The strongest available signal that this was a real, reproducible bug.

        A developer who wrote a test alongside the fix demonstrated the bug was
        observable from outside the code -- which is exactly what a hunter must do.
        A fix with no test may still be real, but it is far more likely to be a
        refactor, a config tweak, or something with no behavioural surface.
        """
        return bool(self.test_files)


def _git(repo: Path, *args: str, timeout: int = 300) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def mine(
    repo: Path,
    limit: int = 40,
    scan_commits: int = 2000,
    max_changed_lines: int = 120,
    require_test: bool = True,
    branch: str = "HEAD",
) -> list[FixCommit]:
    """Find focused, testable bug fixes, newest first.

    The filters exist to keep instances *solvable*. A 4000-line refactor labelled
    "fix stuff" is not something any agent can rediscover from the buggy side, and
    including it depresses the score while telling you nothing.
    """
    repo = Path(repo)
    raw = _git(repo, "log", branch, f"-n{scan_commits}", "--no-merges",
               "--pretty=format:%H%x00%P%x00%s")

    out: list[FixCommit] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        sha, parents, subject = line.split("\x00", 2)
        if not parents.strip():
            continue  # root commit: no buggy state to check out
        if not FIX_RE.search(subject) or NOT_A_FIX_RE.search(subject):
            continue

        try:
            stat = _git(repo, "show", "--numstat", "--format=", sha)
        except RuntimeError:
            continue

        source_files, test_files, changed = [], [], 0
        for row in stat.splitlines():
            parts = row.split("\t")
            if len(parts) != 3:
                continue
            added, removed, path = parts
            if added != "-":
                changed += int(added) + int(removed or 0)
            if Path(path).suffix not in SOURCE_SUFFIXES:
                continue
            (test_files if TEST_HINT.search(path) else source_files).append(path)

        if not source_files or changed == 0 or changed > max_changed_lines:
            continue
        if require_test and not test_files:
            continue

        out.append(FixCommit(
            sha=sha, parent=parents.split()[0], subject=subject,
            source_files=source_files, test_files=test_files, changed_lines=changed,
        ))
        if len(out) >= limit:
            break
    return out


def to_instance(
    repo: Path,
    fix: FixCommit,
    install_cmd: str | None = None,
    python: str = "python3",
) -> Instance:
    """One mined fix -> one instance. The fix's diff is the oracle; its parent is the bug."""
    repo = Path(repo).resolve()
    patch = _git(repo, "diff", f"{fix.parent}..{fix.sha}")
    return Instance(
        instance_id=f"replay__{repo.name.removesuffix('.git')}__{fix.sha[:10]}",
        repo=str(repo),
        base_commit=fix.parent,
        gold_patch=patch,
        install_cmd=install_cmd if install_cmd is not None else guess_install(repo, fix.sha),
        python=python,
        source="replay",
        tier="surviving",
        notes=f"{fix.subject[:120]} | fix {fix.sha[:10]} | "
              f"{fix.changed_lines} lines, {len(fix.source_files)} source file(s)"
              + (", has regression test" if fix.has_regression_test else ""),
    )


ADDED_TEST_RE = re.compile(r"^\+\s*(?:async\s+)?def\s+(test_\w+)", re.MULTILINE)


def added_test_names(repo: Path, fix: FixCommit, path: str) -> list[str]:
    """Test functions this commit *added* to `path`.

    Running the whole post-fix test file is useless as a witness: it carries dozens of
    unrelated tests, and any one of them failing for environmental reasons (a missing
    plugin, a network fixture) makes the file fail on both sides of the patch. Only the
    tests the fix introduced are evidence about this bug.
    """
    try:
        diff = _git(repo, "diff", f"{fix.parent}..{fix.sha}", "--", path)
    except RuntimeError:
        return []
    seen, names = set(), []
    for name in ADDED_TEST_RE.findall(diff):
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def write_auto_witness(repo: Path, fix: FixCommit, dest_dir: Path) -> WitnessSpec | None:
    """Extract the developer's own regression test as this instance's witness.

    The customer already wrote the proof that the bug was real and observable -- it is
    sitting in the fix commit. Taking the *post-fix* version of the test file gives a
    witness for free, which is what makes replay run on an arbitrary repo with zero
    human labelling. An instance whose auto-witness does not discriminate is dropped
    rather than counted, so unsolvable instances never depress the score.
    """
    if not fix.test_files:
        return None
    # Prefer the test file where this commit added the most new test functions.
    best = None
    for path in fix.test_files:
        names = added_test_names(repo, fix, path)
        if not names:
            continue
        if best is None or len(names) > len(best[1]):
            try:
                best = (path, names, _git(repo, "show", f"{fix.sha}:{path}"))
            except RuntimeError:
                continue
    if best is None:
        return None

    path, names, content = best
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{fix.sha[:10]}__{Path(path).name}"
    dest.write_text(content)
    # Staged at its original path so the project's conftest still applies, and narrowed
    # to just the tests this fix introduced.
    return WitnessSpec(path=str(dest.resolve()), stage_as=path, select=" or ".join(names))




def guess_install(repo: Path, ref: str) -> str:
    """Best-effort install command, read from the tree as it was at `ref`.

    Reading the *historical* tree matters: a repo that uses pyproject.toml today may
    have used setup.py at the commit we are about to check out.
    """
    try:
        listing = _git(repo, "ls-tree", "--name-only", ref).split()
    except RuntimeError:
        return ""
    if any(name in listing for name in ("pyproject.toml", "setup.py", "setup.cfg")):
        return "python -m pip install -e ."
    return ""
