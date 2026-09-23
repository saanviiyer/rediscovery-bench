"""Workspace management: materialize a buggy repo, install it, run tests against it.

Two things here are load-bearing for the benchmark's validity:

1. **Leak prevention.** The hunter must not be able to read its way to the answer.
   A plain `git clone && git checkout <base>` leaves every *future* commit -- including
   the fix -- sitting in the object database and reachable via `origin/main`. We instead
   `git archive` the tree at base_commit into a clean directory and re-init a single-commit
   repo, so there is no future history to find.

2. **Pristine validation.** Findings are validated in a workspace the hunter never touched,
   so an agent that edits the source (deliberately or not) cannot manufacture a passing repro.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .models import Instance

PYTEST_PASSED = 0
PYTEST_FAILED = 1
PYTEST_NO_TESTS = 5


class SetupError(RuntimeError):
    pass


def _run(
    cmd: list[str] | str,
    cwd: Path | None = None,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        shell=isinstance(cmd, str),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


@dataclass
class Workspace:
    """A materialized, installed copy of one instance at its buggy commit."""

    root: Path
    python: Path       # interpreter inside the venv
    instance: Instance

    # ---- test execution -------------------------------------------------

    def run_pytest(
        self, target: str | Path, timeout: int = 600, select: str | None = None
    ) -> tuple[str, str]:
        """Run a pytest target. Returns (outcome, output).

        outcome is one of "passed" | "failed" | "error". We keep "error" distinct
        from "failed" on purpose: a repro that cannot even be collected tells us
        nothing about the code under test, and must not be scored as a bug.
        """
        cmd = [str(self.python), "-m", "pytest", str(target),
               "-x", "-q", "--no-header", "-p", "no:cacheprovider"]
        if select:
            cmd += ["-k", select]
        proc = _run(cmd, cwd=self.root, timeout=timeout)
        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == PYTEST_PASSED:
            return "passed", output
        if proc.returncode == PYTEST_FAILED:
            return "failed", output
        if proc.returncode == PYTEST_NO_TESTS:
            return "error", "no tests collected\n" + output
        return "error", f"pytest exit {proc.returncode}\n{output}"

    # ---- patch management -----------------------------------------------

    def apply_gold_patch(self, exclude: list[str] | None = None) -> None:
        self._patch(reverse=False, exclude=exclude)

    def revert_gold_patch(self, exclude: list[str] | None = None) -> None:
        self._patch(reverse=True, exclude=exclude)

    def _patch(self, reverse: bool, exclude: list[str] | None = None) -> None:
        """Apply (or reverse) the oracle patch.

        `exclude` matters when a mined regression test is staged at its original path:
        the fix commit also modifies that file, so the patch would try to edit content
        we have already replaced with the post-fix version and fail outright -- turning
        a perfectly good instance into an unexplained error.
        """
        patch = self.instance.gold_patch
        if not patch.strip():
            raise SetupError(f"{self.instance.instance_id}: empty gold patch")
        args = ["git", "apply", "--whitespace=nowarn"]
        for path in exclude or []:
            args.append(f"--exclude={path}")
        if reverse:
            args.append("--reverse")
        proc = subprocess.run(
            args + ["-"], cwd=self.root, input=patch, capture_output=True, text=True
        )
        if proc.returncode != 0 and exclude:
            raise SetupError(
                f"{self.instance.instance_id}: gold patch failed to "
                f"{'revert' if reverse else 'apply'} with excludes {exclude}\n{proc.stderr}"
            )
        if proc.returncode != 0:
            # Fall back to patch(1), which is more forgiving about fuzz.
            fallback = ["patch", "-p1", "--batch", "--forward"]
            if reverse:
                fallback = ["patch", "-p1", "--batch", "--reverse"]
            proc2 = subprocess.run(
                fallback, cwd=self.root, input=patch, capture_output=True, text=True
            )
            if proc2.returncode != 0:
                raise SetupError(
                    f"{self.instance.instance_id}: gold patch failed to "
                    f"{'revert' if reverse else 'apply'}\n{proc.stderr}\n{proc2.stdout}"
                )

    def destroy(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


_WORKSPACE_PATH_RE_CACHE: dict[str, "re.Pattern[str]"] = {}


def sanitize_repro(text: str, work_dir: Path, ws_root: Path) -> tuple[str, bool]:
    """Re-point any absolute workspace path in a repro at the validation workspace.

    Observed in a real run: a hunter wrote `sys.path.insert(0, "<its own workspace>")`
    into its reproduction. Validation runs in a *different* workspace whose source has
    been restored, so the repro silently imported code from a directory that agent had
    write access to -- defeating the pristine-source guarantee entirely.

    Nothing malicious was happening; the agent was just making its imports work. That is
    exactly why this has to be enforced mechanically rather than asked for in a prompt.
    """
    import re as _re

    key = str(work_dir)
    pattern = _WORKSPACE_PATH_RE_CACHE.get(key)
    if pattern is None:
        pattern = _re.compile(_re.escape(key.rstrip("/")) + r"/[\w.\-]+")
        _WORKSPACE_PATH_RE_CACHE[key] = pattern
    new_text, count = pattern.subn(str(ws_root), text)
    return new_text, count > 0


TEST_REQUIREMENT_FILES = (
    "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt",
    "test-requirements.txt", "requirements-test.txt",
    "requirements/dev.txt", "requirements/test.txt", "requirements/tests.txt",
)
TEST_EXTRAS = ("tests", "test", "dev", "testing")


def _install_test_deps(root: Path, py: Path, installer: list[str]) -> list[str]:
    """Best-effort install of the project's own test dependencies.

    Replaying a repo's history means running the repo's own tests, and those routinely
    need plugins (`pytest-httpbin`, `pytest-asyncio`, fixture servers) that the package
    install does not pull in. Without them the developer's regression test errors out
    identically before and after the fix, and a perfectly good instance gets discarded
    as unsolvable.

    Every attempt is optional: a repo with no dev requirements is normal, not an error.
    """
    installed: list[str] = []
    for name in TEST_REQUIREMENT_FILES:
        if (root / name).exists():
            proc = _run(installer + ["-r", name], cwd=root, timeout=1800)
            if proc.returncode == 0:
                installed.append(name)
    if not installed:
        for extra in TEST_EXTRAS:
            proc = _run(installer + ["-e", f".[{extra}]"], cwd=root, timeout=1800)
            if proc.returncode == 0:
                installed.append(f".[{extra}]")
                break
    return installed


class WorkspaceFactory:
    """Builds workspaces, reusing a bare cache clone so repeated runs stay fast."""

    def __init__(self, cache_dir: Path, work_dir: Path, use_uv: bool | None = None):
        # Resolve up front: workspace commands run with cwd=root, so a relative work_dir
        # would make the venv interpreter path resolve against the workspace itself.
        self.cache_dir = Path(cache_dir).expanduser().resolve()
        self.work_dir = Path(work_dir).expanduser().resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.use_uv = shutil.which("uv") is not None if use_uv is None else use_uv

    # ---- source acquisition ---------------------------------------------

    def _cached_repo(self, instance: Instance) -> Path:
        local = Path(instance.repo).expanduser()
        if local.exists():
            return local.resolve()

        slug = instance.repo.rstrip("/").split("/")[-1].removesuffix(".git")
        dest = self.cache_dir / f"{slug}.git"
        if not dest.exists():
            proc = _run(["git", "clone", "--bare", instance.repo, str(dest)], timeout=1800)
            if proc.returncode != 0:
                raise SetupError(f"clone failed for {instance.repo}: {proc.stderr}")
        else:
            _run(["git", "fetch", "--all", "--quiet"], cwd=dest, timeout=1800)
        return dest

    def _export_tree(self, repo: Path, commit: str, dest: Path) -> None:
        """Extract the tree at `commit` with no surrounding history (see module docstring)."""
        dest.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            tar_path = Path(tmp.name)
        try:
            with open(tar_path, "wb") as fh:
                proc = subprocess.run(
                    ["git", "archive", "--format=tar", commit],
                    cwd=repo, stdout=fh, stderr=subprocess.PIPE, text=False,
                )
            if proc.returncode != 0:
                raise SetupError(f"git archive {commit} failed: {proc.stderr.decode()}")
            with tarfile.open(tar_path) as tf:
                tf.extractall(dest)
        finally:
            tar_path.unlink(missing_ok=True)

        # A single-commit repo: tools that expect git still work, but there is
        # no future commit -- and so no fix -- for the hunter to discover.
        for cmd in (
            ["git", "init", "--quiet", "-b", "main"],
            ["git", "add", "-A"],
            ["git", "-c", "user.email=bench@local", "-c", "user.name=bench",
             "commit", "--quiet", "-m", "baseline"],
        ):
            proc = _run(cmd, cwd=dest)
            if proc.returncode != 0 and cmd[1] != "commit":
                raise SetupError(f"{' '.join(cmd)} failed: {proc.stderr}")

    # ---- environment -----------------------------------------------------

    def _make_venv(self, root: Path, instance: Instance) -> Path:
        venv = root / ".bench-venv"
        if self.use_uv:
            proc = _run(["uv", "venv", "--python", instance.python, str(venv)], timeout=600)
        else:
            proc = _run([instance.python, "-m", "venv", str(venv)], timeout=600)
        if proc.returncode != 0:
            raise SetupError(f"venv creation failed: {proc.stderr}")

        py = venv / "bin" / "python"
        if not py.exists():  # Windows layout
            py = venv / "Scripts" / "python.exe"

        installer = (
            ["uv", "pip", "install", "--python", str(py)]
            if self.use_uv
            else [str(py), "-m", "pip", "install", "-q"]
        )
        proc = _run(installer + ["pytest"], cwd=root, timeout=900)
        if proc.returncode != 0:
            raise SetupError(f"pytest install failed: {proc.stderr[-2000:]}")

        # Test dependencies go in FIRST. A project's dev requirements routinely pin a
        # released build of the project itself, which lands in site-packages and shadows
        # the editable install -- so the oracle patch edits source nothing imports, and
        # every instance silently scores `unmatched`. Installing the package last
        # guarantees the workspace source is what gets imported.
        if instance.test_deps == "auto":
            _install_test_deps(root, py, installer)
        elif instance.test_deps:
            _run(instance.test_deps.replace("python", f'"{py}"', 1), cwd=root, timeout=1800)

        if instance.install_cmd:
            # Rewrite only a LEADING `python` token. A blind str.replace also rewrites
            # the word "python" inside the venv path we just substituted in, producing
            # a mangled interpreter path and an install that cannot fail informatively.
            cmd = instance.install_cmd
            if cmd == "python" or cmd.startswith("python "):
                cmd = f'"{py}"' + cmd[len("python"):]
            proc = _run(
                cmd, cwd=root, timeout=1800,
                env={"VIRTUAL_ENV": str(venv), "PATH": f"{py.parent}:{os.environ['PATH']}"},
            )
            if proc.returncode != 0:
                raise SetupError(f"install failed: {proc.stderr[-2000:]}")
        return py

    # ---- public API ------------------------------------------------------

    def build(self, instance: Instance, label: str) -> Workspace:
        repo = self._cached_repo(instance)
        root = self.work_dir / f"{instance.instance_id}__{label}"
        shutil.rmtree(root, ignore_errors=True)
        self._export_tree(repo, instance.base_commit, root)
        py = self._make_venv(root, instance)
        return Workspace(root=root, python=py, instance=instance)
