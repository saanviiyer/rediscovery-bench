"""Hunters: agents that look for bugs in a repo they know nothing about.

A hunter is handed a workspace at the buggy commit and nothing else -- no issue
text, no failing test, no hint that a bug exists at all. Its only deliverable is
an executable repro, because a finding you cannot run is a finding you cannot score.

The swarm gets its leverage from *diversity of hypothesis*, not volume: N identical
hunters re-explore the same region N times, so each one is given a different lens.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

# Each lens is a different prior about where bugs live. Diversity here is what
# makes a swarm worth more than a single agent run.
LENSES: dict[str, str] = {
    "boundary": (
        "Focus on boundary and degenerate inputs: empty collections, None, zero, "
        "negative numbers, single-element cases, maximum/minimum values, and "
        "off-by-one behaviour at the edges of ranges and slices."
    ),
    "state": (
        "Focus on state and sequencing: operations whose result depends on call order, "
        "functions that mutate shared or default arguments, caching and memoization that "
        "goes stale, and operations that are not idempotent when they claim to be."
    ),
    "errors": (
        "Focus on failure paths: exception handling that swallows or mislabels errors, "
        "cleanup that does not run, partial failures that leave inconsistent state, and "
        "retry or fallback logic that behaves wrongly on the second attempt."
    ),
    "contract": (
        "Focus on contract mismatches: places where the docstring, type hints, or public "
        "API promise one behaviour and the implementation delivers another. Read the "
        "documented intent first, then check whether the code honours it."
    ),
    "resource": (
        "Focus on resources and laziness: file and socket handling, context managers, "
        "generators consumed more than once, iterators exhausted early, and anything "
        "whose behaviour changes between the first and second use."
    ),
    "data": (
        "Focus on data handling: type coercion, unicode and encoding, floating-point "
        "precision, serialization round-trips that do not preserve the original value, "
        "and silent truncation or loss of information."
    ),
}

_PROMPT = """You are auditing a Python codebase for defects. This is an authorized audit of \
code the operator owns.

There is no bug report. Nobody has told you a bug exists, or where. Your job is to find real \
defects by reading and exercising the code.

{lens}

## What counts as a finding

A real defect: the code produces a wrong result, crashes when it should not, corrupts state, \
or contradicts its own documented contract. Style, naming, missing type hints, and "this could \
be faster" are NOT findings. Do not pad the list.

## Your deliverable

For each defect, create a directory `{findings_dir}/finding_<n>/` containing exactly two files:

1. `meta.json`
   {{"title": "one line", "description": "what is wrong and why it is wrong",
     "target_files": ["path/to/file.py"]}}

2. `test_repro.py` -- a self-contained pytest file that FAILS on the current code because of \
this defect, and would PASS if the defect were fixed.

## Rules that determine whether your work counts

- The repro must FAIL right now. Run it yourself before you submit it. An untested repro is \
worthless to me.
- Assert the CORRECT behaviour, then let the buggy code fail the assertion. Do not write a \
test that asserts the buggy behaviour and passes.
- Do NOT modify, fix, or delete anything inside the repository. Your repros are validated \
against the untouched original source, so any edit you make is discarded and a repro that \
depends on it will be scored as a failure.
- Import the code under test normally (`from package.module import thing`). Do NOT touch `sys.path`, and never hardcode an absolute path: your repro is executed elsewhere, and one that depends on this directory will be discarded.
- Write repros that are deterministic. No network, no wall-clock timing, no randomness \
without a fixed seed.
- Report only defects you have actually demonstrated. A well-evidenced finding is worth more \
than five speculative ones.

Run the repro with: `{python} -m pytest <path> -x -q`

Work in {root}. Begin.
"""


@dataclass
class HuntResult:
    findings: list[Finding]
    cost_usd: float = 0.0
    seconds: float = 0.0
    error: str = ""
    modified_repo: bool = False


def collect_findings(findings_dir: Path, reported_by: str) -> list[Finding]:
    """Read whatever the agent left behind, tolerating sloppy output."""
    out: list[Finding] = []
    if not findings_dir.exists():
        return out
    for d in sorted(p for p in findings_dir.iterdir() if p.is_dir()):
        repro = d / "test_repro.py"
        if not repro.exists():
            candidates = sorted(d.glob("test_*.py"))
            if not candidates:
                continue
            repro = candidates[0]
        meta: dict = {}
        meta_path = d / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except json.JSONDecodeError:
                meta = {}
        out.append(
            Finding(
                finding_id=f"{reported_by}:{d.name}",
                title=str(meta.get("title", d.name)),
                description=str(meta.get("description", "")),
                repro_path=str(repro),
                target_files=list(meta.get("target_files", []) or []),
                reported_by=reported_by,
            )
        )
    return out


class Hunter:
    name = "base"

    def hunt(self, root: Path, python: Path, findings_dir: Path, lens: str) -> HuntResult:
        raise NotImplementedError


class ClaudeCodeHunter(Hunter):
    """Drives the `claude` CLI headlessly inside the workspace."""

    name = "claude-code"

    def __init__(
        self,
        model: str = "claude-opus-5",
        effort: str = "high",
        budget_usd: float = 2.0,
        timeout: int = 1800,
    ):
        self.model = model
        self.effort = effort
        self.budget_usd = budget_usd
        self.timeout = timeout
        if shutil.which("claude") is None:
            raise RuntimeError("`claude` CLI not found on PATH")
        self.preflight()

    @staticmethod
    def preflight() -> None:
        """Fail fast on missing credentials.

        A spawned `claude` is a fresh process: it does not inherit the auth of an
        interactive session that launched it. Without this check the whole run
        completes in seconds, reports zero findings, and looks like a genuine
        0% rediscovery rate -- the most expensive kind of wrong answer.
        """
        proc = subprocess.run(
            ["claude", "-p", "ok", "--output-format", "json"],
            capture_output=True, text=True, timeout=120,
        )
        try:
            payload = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return  # unrecognized output; let the real run surface it
        if payload.get("is_error") and "logged in" in str(payload.get("result", "")).lower():
            raise RuntimeError(
                "the `claude` CLI has no credentials in this environment "
                f"({payload.get('result')!r}).\n"
                "  Fix with either:\n"
                "    export ANTHROPIC_API_KEY=sk-ant-...\n"
                "    claude   # run once interactively and complete /login\n"
                "  Auth held by a parent interactive session is NOT inherited by subprocesses."
            )

    def hunt(self, root: Path, python: Path, findings_dir: Path, lens: str) -> HuntResult:
        findings_dir.mkdir(parents=True, exist_ok=True)
        tag = f"{self.name}-{lens}-{uuid.uuid4().hex[:6]}"
        prompt = _PROMPT.format(
            lens=LENSES.get(lens, ""),
            findings_dir=findings_dir,
            python=python,
            root=root,
        )
        cmd = [
            "claude", "-p", prompt,
            "--output-format", "json",
            "--model", self.model,
            "--effort", self.effort,
            "--permission-mode", "bypassPermissions",
            "--add-dir", str(findings_dir),
            "--no-session-persistence",
            "--setting-sources", "",
            "--max-budget-usd", str(self.budget_usd),
        ]

        started = time.time()
        error, cost = "", 0.0
        try:
            proc = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, timeout=self.timeout
            )
            parts: list[str] = []
            if proc.returncode != 0:
                parts.append(f"claude exited {proc.returncode}")
            try:
                payload = json.loads(proc.stdout)
                cost = float(payload.get("total_cost_usd") or 0.0)
                if payload.get("is_error"):
                    # The CLI puts the actual reason here, not on stderr. Reporting
                    # only the exit code turns a diagnosable failure into a mystery.
                    parts.append(str(payload.get("result", ""))[:1000])
            except (json.JSONDecodeError, TypeError, ValueError):
                if proc.returncode != 0 or not proc.stdout.strip():
                    parts.append("could not parse claude JSON output")
            if proc.stderr.strip():
                parts.append(proc.stderr.strip()[-800:])
            error = "; ".join(p for p in parts if p)
        except subprocess.TimeoutExpired:
            error = f"hunt timed out after {self.timeout}s"

        return HuntResult(
            findings=collect_findings(findings_dir, tag),
            cost_usd=cost,
            seconds=time.time() - started,
            error=error,
            modified_repo=_repo_dirty(root),
        )


class NullHunter(Hunter):
    """Reads pre-written findings off disk. Used to test the harness itself
    without spending a cent -- if the plumbing is wrong, you want to know that
    before you pay for a swarm."""

    name = "null"

    def hunt(self, root: Path, python: Path, findings_dir: Path, lens: str) -> HuntResult:
        return HuntResult(findings=collect_findings(findings_dir, f"null-{lens}"))


def _repo_dirty(root: Path) -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True
    )
    return bool(proc.stdout.strip())


def restore_repo(root: Path) -> None:
    """Undo anything the hunter changed, so validation runs against pristine source."""
    subprocess.run(["git", "checkout", "--", "."], cwd=root, capture_output=True)
    subprocess.run(["git", "clean", "-fdq"], cwd=root, capture_output=True)


def build_hunter(kind: str, **kw) -> Hunter:
    if kind == "claude-code":
        return ClaudeCodeHunter(**kw)
    if kind == "null":
        return NullHunter()
    raise ValueError(f"unknown hunter: {kind}")
