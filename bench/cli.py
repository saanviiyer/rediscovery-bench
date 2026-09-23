"""Command line entry point.

    python -m bench selftest              prove the harness works, for free
    python -m bench mutate <repo>         generate instances by injecting faults
    python -m bench run instances/*.json  run the benchmark
"""

from __future__ import annotations

import argparse
import difflib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .hunter import LENSES, build_hunter
from .models import Instance
from .runner import run
from .score import score

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".cache" / "repos"
DEFAULT_WORK = ROOT / ".cache" / "work"


# --------------------------------------------------------------------------- run


def cmd_run(args: argparse.Namespace) -> int:
    paths: list[Path] = []
    for pattern in args.instances:
        p = Path(pattern)
        paths.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    if not paths:
        print("no instance files found", file=sys.stderr)
        return 2

    instances = [Instance.load(p) for p in paths]
    hunter = (
        build_hunter("null")
        if args.hunter == "null"
        else build_hunter(
            "claude-code",
            model=args.model,
            effort=args.effort,
            budget_usd=args.budget,
            timeout=args.timeout,
        )
    )

    reports = run(
        instances,
        hunter=hunter,
        out_dir=Path(args.out),
        cache_dir=Path(args.cache),
        work_dir=Path(args.work),
        swarm=args.swarm,
        lenses=args.lens or None,
        reps=args.reps,
        keep=args.keep,
    )

    card = score(reports)
    print(card.render())
    out = Path(args.out) / "scorecard.json"
    out.write_text(json.dumps(card.to_dict(), indent=2))
    print(f"  full results: {Path(args.out).resolve()}\n")
    return 0


# ------------------------------------------------------------------------ mutate


def cmd_mutate(args: argparse.Namespace) -> int:
    from .mutate import generate

    instances = generate(
        repo=Path(args.repo),
        out_root=Path(args.out),
        count=args.count,
        seed=args.seed,
        install_cmd=args.install_cmd,
        python=args.python,
    )
    if not instances:
        print("no mutation sites found", file=sys.stderr)
        return 1
    for inst in instances:
        print(f"{inst.instance_id}  {inst.notes}")
    print(f"\n{len(instances)} instance(s) written to {Path(args.out).resolve()}")
    print("Note: some mutants may be behaviourally equivalent and unfindable by anyone.")
    return 0


# ------------------------------------------------------------------------ curate


def cmd_curate(args: argparse.Namespace) -> int:
    from .curate import CurationError, curate, write

    try:
        inst = curate(
            args.cve, repo=args.repo, fix_sha=args.fix,
            install_cmd=args.install_cmd, python=args.python,
        )
    except CurationError as exc:
        print(f"\nerror: {exc}\n", file=sys.stderr)
        return 1
    path = write(inst, Path(args.out))
    print(f"{inst.instance_id}")
    print(f"  base   {inst.base_commit[:12]}   (the buggy state)")
    print(f"  {inst.notes[:100]}")
    print(f"  -> {path}")
    print("\nNext: write a witness repro and run `python3 -m bench verify` -- an instance "
          "nobody can solve\nproduces a zero that says nothing about the hunter.")
    return 0


# ------------------------------------------------------------------------ replay


def cmd_replay(args: argparse.Namespace) -> int:
    """Point it at any repo; it mines that repo's own bug fixes and replays them blind.

    Two phases, and the first is free:
      calibrate -- mine fixes, extract each developer's regression test as a witness,
                   and keep only the instances that provably discriminate.
      hunt      -- run the agent against the kept instances and score it.

    Calibration exists so a broken instance never becomes a fake zero. Run it alone
    with --calibrate-only to see what a repo can support before spending anything.
    """
    from .mine import mine, to_instance, write_auto_witness
    from .models import Finding
    from .report import replay_report
    from .validate import validate_finding
    from .workspace import SetupError, WorkspaceFactory

    repo = Path(args.repo).expanduser().resolve()
    out_dir = Path(args.out) / repo.name.removesuffix(".git")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"mining {repo.name} for bug fixes...", file=sys.stderr)
    fixes = mine(repo, limit=args.limit, scan_commits=args.scan,
                 max_changed_lines=args.max_lines)
    if not fixes:
        print("no replayable bug fixes found; try --scan higher or --max-lines larger",
              file=sys.stderr)
        return 1
    print(f"  {len(fixes)} candidate fix(es)", file=sys.stderr)

    factory = WorkspaceFactory(cache_dir=Path(args.cache), work_dir=Path(args.work))
    instances, notes, dropped = [], {}, []

    for fix in fixes:
        inst = to_instance(repo, fix, install_cmd=args.install_cmd, python=args.python)
        notes[inst.instance_id] = f"`{fix.sha[:10]}` {fix.subject}"
        spec = write_auto_witness(repo, fix, out_dir / "witnesses")
        if spec is None:
            dropped.append((inst.instance_id, "fix added no new test to calibrate against"))
            continue
        inst.witness = spec.path

        try:
            ws = factory.build(inst, label="calib")
        except SetupError as exc:
            dropped.append((inst.instance_id, f"workspace build failed: {str(exc)[-120:]}"))
            continue
        try:
            v = validate_finding(
                ws,
                Finding(finding_id=f"witness:{inst.instance_id}", title="witness",
                        description="", repro_path=spec.path,
                        stage_as=spec.stage_as, select=spec.select),
                reps=1,
            )
        finally:
            ws.destroy()

        if v.verdict == "rediscovered":
            instances.append(inst)
            print(f"  [keep] {inst.instance_id}  {fix.subject[:56]}", file=sys.stderr)
        else:
            dropped.append((inst.instance_id,
                            f"developer's own test did not discriminate ({v.verdict})"))
            print(f"  [drop] {inst.instance_id}  ({v.verdict})", file=sys.stderr)

    print(f"\n{len(instances)} replayable instance(s), {len(dropped)} dropped",
          file=sys.stderr)
    if args.calibrate_only or not instances:
        (out_dir / "calibration.txt").write_text(
            "\n".join([f"KEEP {i.instance_id}  {notes[i.instance_id]}" for i in instances]
                      + [f"DROP {n}  {r}" for n, r in dropped])
        )
        print(f"calibration written to {out_dir / 'calibration.txt'}", file=sys.stderr)
        return 0 if instances else 1

    hunter = build_hunter("claude-code", model=args.model, effort=args.effort,
                          budget_usd=args.budget, timeout=args.timeout)
    reports = run(instances, hunter=hunter, out_dir=out_dir,
                  cache_dir=Path(args.cache), work_dir=Path(args.work),
                  swarm=args.swarm, reps=args.reps)

    card = score(reports)
    print(card.render())
    md = replay_report(repo.name.removesuffix(".git"), reports, card, notes, dropped)
    path = out_dir / "REPORT.md"
    path.write_text(md)
    print(f"  evidence report: {path}\n")
    return 0


# -------------------------------------------------------------------------- scan


def cmd_scan(args: argparse.Namespace) -> int:
    """Hunt current HEAD for unknown bugs. No oracle exists here -- see bench/scan.py."""
    from .report import scan_report
    from .scan import Verifier, scan_repo

    hunter = (
        build_hunter("null") if args.hunter == "null"
        else build_hunter("claude-code", model=args.model, effort=args.effort,
                          budget_usd=args.budget, timeout=args.timeout)
    )
    verifier = None if args.verifiers == 0 else Verifier(
        model=args.model, effort=args.verifier_effort, budget_usd=args.verifier_budget
    )

    repo = Path(args.repo).expanduser().resolve()
    out_dir = Path(args.out) / repo.name.removesuffix(".git")
    report = scan_repo(
        repo, hunter=hunter, out_dir=out_dir,
        cache_dir=Path(args.cache), work_dir=Path(args.work),
        ref=args.ref, swarm=args.swarm, lenses=args.lens or None,
        reps=args.reps, verifiers=args.verifiers, verifier=verifier,
        install_cmd=args.install_cmd, python=args.python, keep=args.keep,
    )

    (out_dir / "scan.json").write_text(json.dumps(report.to_dict(), indent=2))
    md = scan_report(report)
    (out_dir / "SCAN.md").write_text(md)

    counts: dict[str, int] = {}
    for r in report.results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    total = report.hunt_cost_usd + report.verify_cost_usd
    print("\n" + "=" * 62)
    print(f"  SCAN — {repo.name} @ {args.ref}")
    print("=" * 62)
    print(f"\n  {report.raw_findings} reported -> "
          f"{counts.get('confirmed', 0)} confirmed "
          f"({len({r.cluster_id for r in report.confirmed})} distinct defects)")
    for verdict in ("confirmed", "disputed", "not_reproducible", "error"):
        if counts.get(verdict):
            print(f"    {verdict:<18} {counts[verdict]}")
    print(f"\n  ${total:.2f} total "
          f"(hunt ${report.hunt_cost_usd:.2f} + review ${report.verify_cost_usd:.2f})")
    if args.verifiers == 0:
        print("  ! adversarial review skipped (--verifiers 0): reproducibility only")
    if report.hunt_error:
        print(f"  ! hunter: {report.hunt_error[:200]}")
    print(f"\n  report: {out_dir / 'SCAN.md'}\n")
    return 0


# ------------------------------------------------------------------------ verify


def cmd_verify(args: argparse.Namespace) -> int:
    """Prove each instance is solvable, and that its oracle actually discriminates.

    Runs the hand-written witness repro through the exact same oracle a hunter's
    finding goes through. A witness that does not score `rediscovered` means the
    instance is broken -- and you want to learn that here, not from a mysterious
    0% after paying for a swarm.
    """
    from .validate import validate_finding
    from .workspace import SetupError, WorkspaceFactory

    paths: list[Path] = []
    for pattern in args.instances:
        p = Path(pattern)
        paths.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])

    factory = WorkspaceFactory(cache_dir=Path(args.cache), work_dir=Path(args.work))
    rows, ok = [], True
    for path in paths:
        inst = Instance.load(path)
        if not inst.witness or not Path(inst.witness).exists():
            rows.append((inst.instance_id, "NO WITNESS", "cannot prove solvable"))
            ok = False
            continue
        try:
            ws = factory.build(inst, label="verify")
        except SetupError as exc:
            rows.append((inst.instance_id, "BUILD FAIL", str(exc)[-160:]))
            ok = False
            continue
        try:
            from .models import Finding
            v = validate_finding(
                ws,
                Finding(finding_id=f"witness:{inst.instance_id}", title="witness",
                        description="", repro_path=inst.witness),
                reps=args.reps,
            )
            rows.append((inst.instance_id, v.verdict.upper(), v.detail[:160]))
            ok &= v.verdict == "rediscovered"
        finally:
            if not args.keep:
                ws.destroy()

    print("\n  instance solvability")
    print("  " + "-" * 74)
    for name, verdict, detail in rows:
        mark = "ok  " if verdict == "REDISCOVERED" else "FAIL"
        print(f"  [{mark}] {name[:36]:<36} {verdict}")
        if verdict != "REDISCOVERED":
            print(f"         {detail}")
    print("  " + "-" * 74)
    print(f"  {sum(1 for r in rows if r[1] == 'REDISCOVERED')}/{len(rows)} instances proven "
          f"solvable\n")
    return 0 if ok else 1


# ---------------------------------------------------------------------- selftest


def _toy_repo(tmp: Path) -> Path:
    """Copy the toy fixture into a single-commit git repo."""
    repo = tmp / "toy"
    shutil.copytree(ROOT / "fixtures" / "toy", repo)
    for cmd in (
        ["git", "init", "--quiet", "-b", "main"],
        ["git", "add", "-A"],
        ["git", "-c", "user.email=b@l", "-c", "user.name=b", "commit", "--quiet", "-m", "x"],
    ):
        subprocess.run(cmd, cwd=repo, capture_output=True)
    return repo


def _toy_instance(tmp: Path) -> Instance:
    """The toy repo plus the gold patch that fixes its planted defect."""
    repo = _toy_repo(tmp)
    rel = "toylib/core.py"
    buggy = (repo / rel).read_text()
    fixed = buggy.replace("items[i:i + size - 1]", "items[i:i + size]")
    assert fixed != buggy, "fixture drifted: the deliberate defect is gone"
    patch = "".join(
        difflib.unified_diff(
            buggy.splitlines(keepends=True), fixed.splitlines(keepends=True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}",
        )
    )
    return Instance(
        instance_id="selftest__toy",
        repo=str(repo),
        base_commit="HEAD",
        gold_patch=patch,
        install_cmd="",  # pytest's rootdir insertion is enough for the fixture
        source="manual",
        tier="surviving",
        notes="chunk() drops the last element of each chunk",
    )


def _scan_selftest(tmp: Path) -> int:
    """Prove the scan gates discriminate, without spending anything.

    The interesting case is `unmatched`: in the benchmark it is distinguishable from a
    real rediscovery because a gold patch exists. On HEAD there is no gold patch, so a
    reproducible-but-intended behaviour is indistinguishable *mechanically* and must
    come out `confirmed`. That is precisely the gap the adversarial reviewer fills, and
    the self-test asserts the gap is where we think it is.
    """
    from .report import scan_report
    from .scan import cluster, scan_repo

    repo = _toy_repo(tmp)
    out = tmp / "scanout"
    planted = out / "findings" / "h0_boundary"
    planted.mkdir(parents=True)
    expected = {
        "correct": "confirmed",
        "invalid": "not_reproducible",
        "unmatched": "confirmed",
    }
    for kind in expected:
        shutil.copytree(ROOT / "fixtures" / f"findings_{kind}" / "finding_1",
                        planted / f"finding_{kind}")
    # A near-duplicate of the correct finding, to exercise clustering.
    shutil.copytree(planted / "finding_correct", planted / "finding_dupe")
    (planted / "finding_dupe" / "meta.json").write_text(json.dumps({
        "title": "chunk() silently loses the final element of each chunk",
        "description": "Slice bound is short by one, so elements vanish.",
        "target_files": ["toylib/core.py"],
    }))

    report = scan_repo(
        repo, hunter=build_hunter("null"), out_dir=out,
        cache_dir=tmp / "cache", work_dir=tmp / "work",
        swarm=1, reps=2, verifiers=0, install_cmd="",
    )

    got = {r.finding.finding_id.split("finding_")[-1]: r for r in report.results}
    ok = True
    print("\n  scan gate discrimination")
    print("  " + "-" * 62)
    for kind, want in expected.items():
        r = got.get(kind)
        actual = r.verdict if r else "MISSING"
        mark = "ok  " if actual == want else "FAIL"
        print(f"  [{mark}] {kind:<10} expected {want:<18} got {actual}")
        ok &= actual == want

    dupe, correct = got.get("dupe"), got.get("correct")
    clustered = bool(dupe and correct and dupe.cluster_id == correct.cluster_id)
    print(f"  [{'ok  ' if clustered else 'FAIL'}] dedup      near-duplicate "
          f"{'clustered with' if clustered else 'NOT clustered with'} original")
    ok &= clustered
    print("  " + "-" * 62)
    (out / "SCAN.md").write_text(scan_report(report))
    print(f"  {len(report.confirmed)} confirmed from {report.raw_findings} raw findings")
    print("\n  scan self-test PASSED\n" if ok else "\n  scan self-test FAILED\n")
    return 0 if ok else 1


def cmd_selftest(args: argparse.Namespace) -> int:
    """Verify the oracle discriminates in every direction, without spending anything.

    A harness that says "rediscovered" for everything is worse than no harness, so
    this plants one finding of each kind and asserts each is scored correctly.
    """
    expected = {
        "correct": "rediscovered",
        "invalid": "invalid",
        "unmatched": "unmatched",
    }
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        if args.scan:
            return _scan_selftest(tmp)
        instance = _toy_instance(tmp)
        out = Path(args.out) if args.live else tmp / "out"

        if args.live:
            # A real agent hunts the fixture blind. This is the only way to
            # exercise the prompt, the findings contract, and cost parsing.
            hunter = build_hunter(
                "claude-code", model=args.model, effort=args.effort,
                budget_usd=args.budget, timeout=args.timeout,
            )
        else:
            hunter = build_hunter("null")
            findings_root = out / instance.instance_id / "findings" / "h0_boundary"
            findings_root.mkdir(parents=True)
            for kind in expected:
                shutil.copytree(
                    ROOT / "fixtures" / f"findings_{kind}" / "finding_1",
                    findings_root / f"finding_{kind}",
                )

        reports = run(
            [instance],
            hunter=hunter,
            out_dir=out,
            cache_dir=tmp / "cache",
            work_dir=tmp / "work",
            swarm=args.swarm,
        )

        report = reports[0]
        if report.setup_error:
            print(f"\nFAIL: setup error\n{report.setup_error}\n", file=sys.stderr)
            return 1

        if args.live:
            print(f"\n  live hunt on the toy fixture (planted defect: {instance.notes})")
            print("  " + "-" * 56)
            by_id = {v.finding_id: v for v in report.validations}
            for f in report.findings:
                v = by_id.get(f.finding_id)
                print(f"  [{(v.verdict if v else '?'):<13}] {f.title[:60]}")
            if report.hunt_error:
                print(f"  hunter reported: {report.hunt_error[:300]}")
            print("  " + "-" * 56)
            print(score(reports).render())
            found = report.rediscovered
            print("  live check PASSED -- the agent found the planted defect blind\n"
                  if found else
                  "  live check: agent did NOT find the planted defect "
                  "(a real result, not a harness failure)\n")
            return 0

        got = {v.finding_id.split("finding_")[-1]: v for v in report.validations}
        ok = True
        print("\n  oracle discrimination check")
        print("  " + "-" * 56)
        for kind, want in expected.items():
            v = got.get(kind)
            actual = v.verdict if v else "MISSING"
            mark = "ok  " if actual == want else "FAIL"
            print(f"  [{mark}] {kind:<10} expected {want:<14} got {actual}")
            if v and actual != want:
                print(f"         detail: {v.detail[:200]}")
            ok &= actual == want
        print("  " + "-" * 56)
        print(score(reports).render())
        print("  self-test PASSED\n" if ok else "  self-test FAILED\n")
        return 0 if ok else 1


# --------------------------------------------------------------------------- cli


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bench", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the benchmark over instance files")
    r.add_argument("instances", nargs="+", help="instance .json files or a directory")
    r.add_argument("--hunter", default="claude-code", choices=["claude-code", "null"])
    r.add_argument("--model", default="claude-opus-5")
    r.add_argument("--effort", default="high", choices=["low", "medium", "high", "max"])
    r.add_argument("--swarm", type=int, default=1, help="hunters per instance")
    r.add_argument("--lens", action="append", choices=list(LENSES),
                   help="restrict to specific lenses (repeatable)")
    r.add_argument("--budget", type=float, default=2.0, help="USD cap per hunter")
    r.add_argument("--timeout", type=int, default=1800, help="seconds per hunter")
    r.add_argument("--reps", type=int, default=2, help="repro repetitions per side")
    r.add_argument("--out", default=str(ROOT / "results"))
    r.add_argument("--cache", default=str(DEFAULT_CACHE))
    r.add_argument("--work", default=str(DEFAULT_WORK))
    r.add_argument("--keep", action="store_true", help="do not delete workspaces")
    r.set_defaults(func=cmd_run)

    m = sub.add_parser("mutate", help="generate instances by injecting faults")
    m.add_argument("repo", help="path to a checked-out repo")
    m.add_argument("--out", default=str(ROOT / "instances" / "mutants"))
    m.add_argument("--count", type=int, default=5)
    m.add_argument("--seed", type=int, default=0)
    m.add_argument("--install-cmd", default="python -m pip install -e .")
    m.add_argument("--python", default="python3")
    m.set_defaults(func=cmd_mutate)

    c = sub.add_parser("curate", help="build an instance from a published CVE advisory")
    c.add_argument("cve", help="e.g. CVE-2023-32681")
    c.add_argument("--repo", help="owner/name, when the advisory cites several")
    c.add_argument("--fix", help="fix commit SHA, when the advisory cites several")
    c.add_argument("--out", default=str(ROOT / "instances" / "cve"))
    c.add_argument("--install-cmd", default="python -m pip install -e .")
    c.add_argument("--python", default="python3")
    c.set_defaults(func=cmd_curate)

    rp = sub.add_parser(
        "replay",
        help="mine a repo's own bug fixes and replay them blind (the customer-facing PoC)",
    )
    rp.add_argument("repo", help="path to a git repo (bare or working clone)")
    rp.add_argument("--limit", type=int, default=10, help="max fixes to replay")
    rp.add_argument("--scan", type=int, default=2000, help="commits of history to scan")
    rp.add_argument("--max-lines", type=int, default=120,
                    help="skip fixes larger than this; big refactors are not replayable")
    rp.add_argument("--calibrate-only", action="store_true",
                    help="mine and validate instances without spending anything")
    rp.add_argument("--install-cmd", default=None,
                    help="override the guessed install command")
    rp.add_argument("--python", default="python3")
    rp.add_argument("--model", default="claude-opus-5")
    rp.add_argument("--effort", default="high", choices=["low", "medium", "high", "max"])
    rp.add_argument("--swarm", type=int, default=3)
    rp.add_argument("--budget", type=float, default=2.0)
    rp.add_argument("--timeout", type=int, default=1800)
    rp.add_argument("--reps", type=int, default=2)
    rp.add_argument("--out", default=str(ROOT / "results" / "replay"))
    rp.add_argument("--cache", default=str(DEFAULT_CACHE))
    rp.add_argument("--work", default=str(DEFAULT_WORK))
    rp.set_defaults(func=cmd_replay)

    sc = sub.add_parser("scan", help="hunt current HEAD for unknown bugs (the product)")
    sc.add_argument("repo")
    sc.add_argument("--ref", default="HEAD")
    sc.add_argument("--hunter", default="claude-code", choices=["claude-code", "null"])
    sc.add_argument("--swarm", type=int, default=3)
    sc.add_argument("--lens", action="append", choices=list(LENSES))
    sc.add_argument("--reps", type=int, default=3,
                    help="reproducibility runs; a flaky repro is worse than no finding")
    sc.add_argument("--verifiers", type=int, default=2,
                    help="adversarial reviewers per distinct defect (0 to skip)")
    sc.add_argument("--model", default="claude-opus-5")
    sc.add_argument("--effort", default="high", choices=["low", "medium", "high", "max"])
    sc.add_argument("--verifier-effort", default="medium",
                    choices=["low", "medium", "high", "max"])
    sc.add_argument("--budget", type=float, default=2.0, help="USD cap per hunter")
    sc.add_argument("--verifier-budget", type=float, default=0.5, help="USD cap per review")
    sc.add_argument("--timeout", type=int, default=1800)
    sc.add_argument("--install-cmd", default=None)
    sc.add_argument("--python", default="python3")
    sc.add_argument("--out", default=str(ROOT / "results" / "scan"))
    sc.add_argument("--cache", default=str(DEFAULT_CACHE))
    sc.add_argument("--work", default=str(DEFAULT_WORK))
    sc.add_argument("--keep", action="store_true")
    sc.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify", help="prove instances are solvable before spending money")
    v.add_argument("instances", nargs="+")
    v.add_argument("--reps", type=int, default=2)
    v.add_argument("--cache", default=str(DEFAULT_CACHE))
    v.add_argument("--work", default=str(DEFAULT_WORK))
    v.add_argument("--keep", action="store_true")
    v.set_defaults(func=cmd_verify)

    s = sub.add_parser("selftest", help="verify the oracle without spending anything")
    s.add_argument("--scan", action="store_true",
                   help="exercise the scan gates instead of the benchmark oracle (free)")
    s.add_argument("--live", action="store_true",
                   help="hunt the fixture with a real agent instead of planted findings "
                        "(costs money; exercises the prompt and findings contract)")
    s.add_argument("--model", default="claude-opus-5")
    s.add_argument("--effort", default="high", choices=["low", "medium", "high", "max"])
    s.add_argument("--swarm", type=int, default=1)
    s.add_argument("--budget", type=float, default=1.0, help="USD cap per hunter")
    s.add_argument("--timeout", type=int, default=900)
    s.add_argument("--out", default=str(ROOT / "results" / "selftest-live"))
    s.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"\nerror: {exc}\n", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
