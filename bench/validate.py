"""The differential oracle.

This is the part that makes the benchmark trustworthy. We never ask a model to
judge whether a finding is real, and we never string-match a description against
a patch. We ask one mechanical question:

    Does the held-out fix flip this repro from failing to passing?

If yes, the hunter found *that* bug -- not something that sounds like it. If the
repro fails both before and after the fix, the hunter found something else (which
may be a genuine unrelated bug, or may be noise) and we say so rather than quietly
counting it. If the repro passes on the buggy code, no bug was demonstrated at all.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .models import Finding, Validation
from .workspace import SetupError, Workspace


def _stage(ws: Workspace, finding: Finding) -> tuple[Path, bytes | None]:
    """Place the repro in the workspace. Returns (path, displaced original bytes).

    A mined regression test overwrites the project's own copy of that file, so the
    original must be handed back for restoration -- otherwise validating one finding
    silently corrupts the workspace for the next.
    """
    if finding.stage_as:
        dest = ws.root / finding.stage_as
        dest.parent.mkdir(parents=True, exist_ok=True)
        displaced = dest.read_bytes() if dest.exists() else None
    else:
        digest = hashlib.sha1(finding.finding_id.encode()).hexdigest()[:10]
        dest = ws.root / f"test_bench_repro_{digest}.py"
        displaced = None
    shutil.copyfile(finding.repro_path, dest)
    return dest, displaced


def _repeat(
    ws: Workspace, target: Path, reps: int, select: str = ""
) -> tuple[list[bool], str]:
    """Run a repro `reps` times. Returns (per-run 'did it fail?', last output).

    Repetition is not paranoia. A repro that fails on the buggy code and passes on
    the patched code *by coincidence* would be scored as a rediscovery, and one
    flaky test is enough to make the headline number a lie.
    """
    failures: list[bool] = []
    last = ""
    for _ in range(reps):
        outcome, out = ws.run_pytest(target, select=select or None)
        last = out
        if outcome == "error":
            return [], out
        failures.append(outcome == "failed")
    return failures, last


def validate_finding(ws: Workspace, finding: Finding, reps: int = 2) -> Validation:
    """Score one finding against the pristine workspace. Leaves `ws` as it found it."""
    target, displaced = _stage(ws, finding)
    patched = False
    try:
        base_runs, base_out = _repeat(ws, target, reps, finding.select)
        if not base_runs:
            return Validation(finding.finding_id, "error", detail=base_out[-1500:])
        if not all(base_runs):
            if any(base_runs):
                return Validation(
                    finding.finding_id, "flaky", base_runs=base_runs,
                    detail="repro is nondeterministic on the buggy code",
                )
            return Validation(
                finding.finding_id, "invalid", fails_on_base=False, base_runs=base_runs,
                detail="repro passes on the buggy code -- no defect demonstrated",
            )

        excludes = [finding.stage_as] if finding.stage_as else None
        ws.apply_gold_patch(exclude=excludes)
        patched = True
        patched_runs, patched_out = _repeat(ws, target, reps, finding.select)
        if not patched_runs:
            return Validation(
                finding.finding_id, "error", fails_on_base=True, base_runs=base_runs,
                detail="repro could not execute under the fix: " + patched_out[-1500:],
            )
        if any(patched_runs) and not all(patched_runs):
            return Validation(
                finding.finding_id, "flaky", fails_on_base=True,
                base_runs=base_runs, patched_runs=patched_runs,
                detail="repro is nondeterministic under the fix",
            )

        if not any(patched_runs):
            return Validation(
                finding.finding_id, "rediscovered", fails_on_base=True,
                passes_on_patched=True, base_runs=base_runs, patched_runs=patched_runs,
                detail="the held-out fix flips this repro from failing to passing",
            )
        return Validation(
            finding.finding_id, "unmatched", fails_on_base=True, passes_on_patched=False,
            base_runs=base_runs, patched_runs=patched_runs,
            detail="reproducible failure the held-out fix does not address "
                   "-- an unrelated real bug, or a broken repro",
        )
    except SetupError as exc:
        return Validation(finding.finding_id, "error", detail=str(exc)[:1500])
    finally:
        if patched:
            try:
                ws.revert_gold_patch(
                    exclude=[finding.stage_as] if finding.stage_as else None
                )
            except SetupError:
                pass
        # Restore the workspace exactly as found: put back any file we displaced,
        # otherwise remove the repro we added.
        if displaced is not None:
            target.write_bytes(displaced)
        else:
            target.unlink(missing_ok=True)


def validate_all(ws: Workspace, findings: list[Finding], reps: int = 2) -> list[Validation]:
    return [validate_finding(ws, f, reps=reps) for f in findings]
