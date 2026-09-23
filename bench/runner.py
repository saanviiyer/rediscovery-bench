"""Orchestration: build -> hunt (fan out) -> validate (fan in) -> score."""

from __future__ import annotations

import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .hunter import LENSES, Hunter, restore_repo
from .models import Instance, InstanceReport
from .validate import validate_all
from .workspace import SetupError, WorkspaceFactory


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run_instance(
    instance: Instance,
    hunter: Hunter,
    factory: WorkspaceFactory,
    out_dir: Path,
    swarm: int = 1,
    lenses: list[str] | None = None,
    reps: int = 2,
    keep: bool = False,
) -> InstanceReport:
    report = InstanceReport(instance_id=instance.instance_id)
    lens_list = (lenses or list(LENSES))[:swarm] or ["boundary"]
    while len(lens_list) < swarm:  # more hunters than lenses: cycle
        lens_list.append(lens_list[len(lens_list) % len(LENSES)])

    workspaces = []
    try:
        _log(f"[{instance.instance_id}] building {swarm} workspace(s)...")
        for i in range(swarm):
            workspaces.append(factory.build(instance, label=f"h{i}"))
    except SetupError as exc:
        report.setup_error = str(exc)
        _log(f"[{instance.instance_id}] SETUP FAILED: {exc}")
        for ws in workspaces:
            ws.destroy()
        return report

    findings_root = out_dir / instance.instance_id / "findings"
    findings_root.mkdir(parents=True, exist_ok=True)

    def _one(idx: int):
        ws = workspaces[idx]
        lens = lens_list[idx]
        fdir = findings_root / f"h{idx}_{lens}"
        _log(f"[{instance.instance_id}] hunting (lens={lens})...")
        return hunter.hunt(ws.root, ws.python, fdir, lens)

    with ThreadPoolExecutor(max_workers=swarm) as pool:
        results = list(pool.map(_one, range(swarm)))

    for r in results:
        report.findings.extend(r.findings)
        report.hunt_cost_usd += r.cost_usd
        report.hunt_seconds = max(report.hunt_seconds, r.seconds)  # wall clock, not sum
        if r.error:
            report.hunt_error = (report.hunt_error + " | " + r.error).strip(" |")
        if r.modified_repo:
            _log(f"[{instance.instance_id}] note: hunter modified the repo; reverting")

    _log(f"[{instance.instance_id}] {len(report.findings)} finding(s); validating...")

    # Validate in a workspace restored to pristine source, so a hunter that edited
    # the code under test cannot manufacture a passing repro.
    validation_ws = workspaces[0]
    restore_repo(validation_ws.root)
    try:
        report.validations = validate_all(validation_ws, report.findings, reps=reps)
    except Exception:
        report.setup_error = traceback.format_exc()[-2000:]

    verdicts = ", ".join(v.verdict for v in report.validations) or "none"
    _log(f"[{instance.instance_id}] -> {verdicts}")

    if not keep:
        for ws in workspaces:
            ws.destroy()
    return report


def run(
    instances: list[Instance],
    hunter: Hunter,
    out_dir: Path,
    cache_dir: Path,
    work_dir: Path,
    swarm: int = 1,
    lenses: list[str] | None = None,
    reps: int = 2,
    keep: bool = False,
) -> list[InstanceReport]:
    factory = WorkspaceFactory(cache_dir=cache_dir, work_dir=work_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reports: list[InstanceReport] = []

    for inst in instances:
        report = run_instance(
            inst, hunter, factory, out_dir,
            swarm=swarm, lenses=lenses, reps=reps, keep=keep,
        )
        reports.append(report)
        # Write after every instance: a long run that dies at #9 should not
        # cost you the first eight results.
        (out_dir / inst.instance_id / "report.json").write_text(
            json.dumps(report.to_dict(), indent=2)
        )
    return reports
