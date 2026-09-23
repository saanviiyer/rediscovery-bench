"""Core data types.

The central idea: an Instance is a repo pinned to a commit where a *known* bug
exists, plus the patch that fixes it. The patch is never shown to the hunter --
it is used only as the oracle that decides whether a finding is the bug.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Literal

Verdict = Literal[
    "rediscovered",  # repro fails on base, passes under the gold patch -> found THE bug
    "unmatched",     # repro fails on base and still fails patched -> other bug, or noise
    "invalid",       # repro passes on base -> no bug demonstrated
    "flaky",         # repro is nondeterministic on base or patched
    "error",         # repro could not be executed at all
]


@dataclass
class Instance:
    """One held-out bug."""

    instance_id: str
    repo: str                    # git URL or local path
    base_commit: str             # buggy state; the hunter sees exactly this
    gold_patch: str              # unified diff that fixes it -- ORACLE ONLY, never shown
    test_cmd: str = "python -m pytest -x -q"
    install_cmd: str = "python -m pip install -e ."
    # "auto" discovers dev/test requirement files and extras; "" skips; anything else
    # is run verbatim. Replaying a repo's own tests needs its own test plugins.
    test_deps: str = "auto"
    python: str = "python3"
    # Provenance so results stay interpretable months later.
    source: str = "manual"       # "manual" | "cve" | "swebench" | "mutation"
    tier: str = "unknown"        # "surviving" (suite misses it) | "killed" | "unknown"
    notes: str = ""
    cve: str = ""
    # A hand-written repro that SHOULD score "rediscovered". Its only job is to prove
    # the instance is solvable at all. An instance nobody can solve produces a zero that
    # says nothing about the hunter, and you will not find that out by reading the JSON.
    witness: str = ""

    @staticmethod
    def load(path: Path) -> "Instance":
        path = Path(path)
        data = json.loads(path.read_text())
        if "gold_patch_file" in data:
            data["gold_patch"] = (path.parent / data.pop("gold_patch_file")).read_text()
        if data.get("witness"):
            witness = path.parent / data["witness"]
            data["witness"] = str(witness.resolve()) if witness.exists() else data["witness"]
        return Instance(**data)

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))


@dataclass
class Finding:
    """One bug the hunter claims to have found, with an executable repro."""

    finding_id: str
    title: str
    description: str
    repro_path: str              # path to a pytest file, relative to the findings dir
    target_files: list[str] = field(default_factory=list)
    reported_by: str = ""
    # Where to place the repro inside the workspace. Agent findings are standalone and
    # land at the repo root; a mined regression test must land at its original path so
    # the project's conftest and package layout still apply.
    stage_as: str = ""
    # Optional pytest -k expression. A mined test file holds many tests; only the ones
    # the fix added are evidence for this bug, and the rest add unrelated failures.
    select: str = ""


@dataclass
class Validation:
    finding_id: str
    verdict: Verdict
    fails_on_base: bool | None = None
    passes_on_patched: bool | None = None
    base_runs: list[bool] = field(default_factory=list)      # True == test failed
    patched_runs: list[bool] = field(default_factory=list)
    detail: str = ""


@dataclass
class InstanceReport:
    instance_id: str
    findings: list[Finding] = field(default_factory=list)
    validations: list[Validation] = field(default_factory=list)
    hunt_cost_usd: float = 0.0
    hunt_seconds: float = 0.0
    hunt_error: str = ""
    setup_error: str = ""

    @property
    def rediscovered(self) -> bool:
        return any(v.verdict == "rediscovered" for v in self.validations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "rediscovered": self.rediscovered,
            "hunt_cost_usd": self.hunt_cost_usd,
            "hunt_seconds": self.hunt_seconds,
            "hunt_error": self.hunt_error,
            "setup_error": self.setup_error,
            "findings": [asdict(f) for f in self.findings],
            "validations": [asdict(v) for v in self.validations],
        }
