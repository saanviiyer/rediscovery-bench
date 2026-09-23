"""Scan: hunt current HEAD for unknown bugs.

This is the product surface, and it is harder than the benchmark for one reason: on
HEAD there is no held-out fix, so the differential oracle -- the thing that makes
`bench run` trustworthy -- does not exist. Nothing can mechanically prove a finding
is a real defect rather than intended behaviour.

So the oracle degrades into a pipeline of filters, strongest first:

  1. Reproducibility (mechanical, cheap, unforgiving).
     The repro must FAIL deterministically on untouched HEAD across N runs. A repro
     that passes proves nothing; one that errors on import proves nothing about the
     code; one that flickers is worse than nothing because it will waste a real
     engineer's afternoon. This gate alone removes most of what a swarm produces.

  2. Independent rediscovery (free signal, already paid for).
     Findings are clustered. A defect that three differently-primed hunters found
     separately is far more likely to be real than one that a single hunter reported
     once. The swarm was going to run anyway; the agreement is a bonus.

  3. Adversarial review (expensive, judgement).
     Independent agents are asked to REFUTE the finding -- argue it is intended
     behaviour, a misread contract, or a bad test. Findings are dropped by majority.
     Prompting for refutation rather than assessment matters: an agent asked "is this
     real?" agrees with almost anything put in front of it.

What none of this gives you is a precision number. You cannot measure precision
without ground truth, and HEAD has none. That is what `bench replay` is for: it
measures precision against the same repo's real history, and scan inherits it.
Anyone quoting scan precision without a replay number behind it is guessing.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

from .models import Finding
from .workspace import Workspace, sanitize_repro

ScanVerdict = Literal[
    "confirmed",         # reproduces deterministically and survived refutation
    "disputed",          # reproduces, but reviewers call it intended behaviour
    "not_reproducible",  # passes on HEAD, or flickers between runs
    "error",             # the repro could not execute at all
]

_STOP = {
    "the", "and", "for", "with", "when", "that", "this", "from", "into", "not",
    "does", "are", "was", "has", "have", "but", "its", "it's", "can", "will",
    "bug", "issue", "error", "incorrect", "wrong", "fails", "fail", "failure",
}


# --------------------------------------------------------------------- gate 1


@dataclass
class ScanResult:
    finding: Finding
    verdict: ScanVerdict
    runs: list[bool] = field(default_factory=list)
    votes: list[dict] = field(default_factory=list)
    cluster_id: str = ""
    signature: str = ""
    path_rewritten: bool = False
    duplicates: list[str] = field(default_factory=list)
    confidence: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["finding"] = asdict(self.finding)
        return d


def check_reproducible(
    ws: Workspace, finding: Finding, reps: int = 3, work_dir: Path | None = None
) -> tuple[ScanVerdict, list[bool], str, bool]:
    """Does this repro fail, every time, against untouched source?

    Deliberately stricter than the benchmark's gate (3 runs by default, not 2). In the
    benchmark a false positive costs a wrong number; here it costs an engineer's trust,
    and you only get to spend that once.
    """
    digest = re.sub(r"\W+", "_", finding.finding_id)[-40:]
    dest = ws.root / f"test_scan_{digest}.py"
    text = Path(finding.repro_path).read_text()
    rewritten = False
    if work_dir is not None:
        text, rewritten = sanitize_repro(text, work_dir, ws.root)
    dest.write_text(text)
    try:
        runs: list[bool] = []
        last = ""
        for _ in range(reps):
            outcome, out = ws.run_pytest(dest)
            last = out
            if outcome == "error":
                return "error", runs, "repro could not execute: " + out[-1200:], rewritten
            runs.append(outcome == "failed")
        if all(runs):
            return "confirmed", runs, last[-1500:], rewritten
        if any(runs):
            return "not_reproducible", runs, "repro is nondeterministic across runs", rewritten
        return "not_reproducible", runs, "repro passes on current code -- nothing shown", rewritten
    finally:
        dest.unlink(missing_ok=True)


# --------------------------------------------------------------------- gate 2


def _tokens(text: str) -> set[str]:
    return {
        w for w in re.findall(r"[a-z0-9_]+", text.lower())
        if len(w) > 2 and w not in _STOP
    }


_FRAME_RE = re.compile(r"^([\w./\-]+\.py):(\d+): (\w+)", re.MULTILINE)
_ASSERT_RE = re.compile(r"^E\s+(\w*(?:Error|Exception|Warning)?[^\n]{0,120})", re.MULTILINE)


def failure_signature(output: str) -> str:
    """Fingerprint *where and how* a repro fails, from its pytest output.

    Two write-ups of the same defect can share almost no vocabulary -- "drops the last
    element" and "silently loses the final item" are the same bug -- so clustering on
    prose is unreliable in exactly the case that matters. Where the failure lands in the
    source is evidence rather than description, and it is already captured by the
    reproducibility gate, so it costs nothing extra.
    """
    frames = [
        f"{path}:{line}"
        for path, line, _ in _FRAME_RE.findall(output)
        # Skip the staged repro itself: every finding fails there, so it carries no
        # information about which defect was hit.
        if not Path(path).name.startswith("test_scan_")
    ]
    if frames:
        return "frames:" + "|".join(sorted(set(frames)))
    # An assertion that never leaves the test file gives no source frame; fall back to
    # the exception text, normalised so incidental values do not split a cluster.
    m = _ASSERT_RE.search(output)
    if m:
        return "assert:" + re.sub(r"\d+", "N", m.group(1).strip())[:120]
    return ""


def cluster(
    findings: list[Finding],
    signatures: dict[str, str] | None = None,
    threshold: float = 0.25,
) -> dict[str, list[Finding]]:
    """Group findings that describe the same defect.

    Two findings merge when they name the same primary file AND either fail with an
    identical signature or share enough vocabulary. Deterministic and free: asking a
    model to dedup would add cost, latency, and a second thing that can be wrong.

    Merging is deliberately conservative. Over-clustering hides distinct bugs behind one
    another, which is worse than showing a developer the same bug twice.
    """
    signatures = signatures or {}
    clusters: dict[str, list[Finding]] = {}
    keys: dict[str, tuple[str, set[str], set[str]]] = {}

    for f in findings:
        primary = (f.target_files or [""])[0]
        toks = _tokens(f"{f.title} {f.description[:200]}")
        sig = signatures.get(f.finding_id, "")
        placed = False
        for cid, (cfile, ctoks, csigs) in keys.items():
            if cfile != primary:
                continue
            union = ctoks | toks
            same_sig = bool(sig) and sig in csigs
            overlap = len(ctoks & toks) / len(union) if union else 0.0
            if same_sig or overlap >= threshold:
                clusters[cid].append(f)
                keys[cid] = (cfile, ctoks | toks, csigs | {sig} if sig else csigs)
                placed = True
                break
        if not placed:
            cid = f"cluster_{len(clusters) + 1:03d}"
            clusters[cid] = [f]
            keys[cid] = (primary, toks, {sig} if sig else set())
    return clusters


# --------------------------------------------------------------------- gate 3

_REFUTE_PROMPT = """You are reviewing a defect report against this codebase, as a skeptic.

Your job is to REFUTE it. Assume it is wrong until the code forces you to conclude \
otherwise. Most reported defects are one of these, and you should say so plainly:

- intended behaviour that the reporter misread
- a test asserting the reporter's preference rather than the code's actual contract
- a misunderstanding of the documented API
- a test that is simply written incorrectly

Only conclude the defect is real if you can point to the specific code that produces \
wrong behaviour, and say what the correct behaviour would be.

## The report

Title: {title}

Description:
{description}

## The reproduction

It has already been confirmed that this test FAILS against the current code. That is \
not in question, and it is not evidence the behaviour is wrong. Your question is \
whether failing is *correct*.

```python
{repro}
```

## Answer

Read the relevant source in {root} before answering. Then output ONLY a JSON object:

{{"real": true|false,
  "reason": "one or two sentences citing the specific code",
  "confidence": 0.0-1.0}}

Default to `"real": false` when you are genuinely unsure. A false positive that reaches \
a developer costs far more than a missed bug.
"""


class Verifier:
    """Adversarial reviewer. Independent of the hunter that produced the finding."""

    def __init__(
        self,
        model: str = "claude-opus-5",
        effort: str = "medium",
        budget_usd: float = 0.5,
        timeout: int = 900,
    ):
        self.model, self.effort = model, effort
        self.budget_usd, self.timeout = budget_usd, timeout

    def review(self, root: Path, finding: Finding) -> dict:
        try:
            repro = Path(finding.repro_path).read_text()[:6000]
        except OSError:
            return {"real": False, "reason": "repro unreadable", "confidence": 0.0}

        prompt = _REFUTE_PROMPT.format(
            title=finding.title, description=finding.description[:2000],
            repro=repro, root=root,
        )
        cmd = [
            "claude", "-p", prompt,
            "--output-format", "json",
            "--model", self.model,
            "--effort", self.effort,
            "--permission-mode", "bypassPermissions",
            "--no-session-persistence",
            "--setting-sources", "",
            "--max-budget-usd", str(self.budget_usd),
            # Read-only: a reviewer that edits the code under review is not a reviewer.
            "--disallowed-tools", "Edit", "Write", "NotebookEdit",
        ]
        try:
            proc = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, timeout=self.timeout
            )
            payload = json.loads(proc.stdout)
            text = str(payload.get("result", ""))
            cost = float(payload.get("total_cost_usd") or 0.0)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError, TypeError):
            return {"real": False, "reason": "verifier failed to run", "confidence": 0.0,
                    "cost_usd": 0.0}

        vote = _parse_vote(text)
        vote["cost_usd"] = cost
        return vote


def _parse_vote(text: str) -> dict:
    """Extract the verdict, tolerating prose wrapped around the JSON.

    An unparseable vote is counted as a refusal to endorse, never as an endorsement --
    a broken verifier must not be able to promote a finding.
    """
    for match in re.finditer(r"\{[^{}]*\"real\"[^{}]*\}", text, re.DOTALL):
        try:
            data = json.loads(match.group(0))
            return {
                "real": bool(data.get("real")),
                "reason": str(data.get("reason", ""))[:400],
                "confidence": float(data.get("confidence", 0.5)),
            }
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return {"real": False, "reason": "unparseable verifier output", "confidence": 0.0}


def adjudicate(votes: list[dict], cluster_size: int, verifiers: int) -> tuple[ScanVerdict, float]:
    """Combine refutation votes and independent-rediscovery count into one score."""
    if verifiers == 0:
        # No adversarial pass ran. Report reproducibility only and say so in the score
        # rather than inventing a confidence nobody measured.
        base, verdict = 0.5, "confirmed"
    else:
        endorsed = sum(1 for v in votes if v.get("real"))
        base = endorsed / max(len(votes), 1)
        verdict = "confirmed" if endorsed * 2 > len(votes) else "disputed"

    # Independent rediscovery by differently-primed hunters is corroboration.
    bonus = min(0.2, 0.1 * (cluster_size - 1))
    return verdict, round(min(1.0, base + bonus), 3)


# ------------------------------------------------------------------- pipeline


@dataclass
class ScanReport:
    repo: str
    ref: str
    results: list[ScanResult] = field(default_factory=list)
    raw_findings: int = 0
    hunt_cost_usd: float = 0.0
    verify_cost_usd: float = 0.0
    hunt_seconds: float = 0.0
    hunt_error: str = ""
    verifiers: int = 0          # 0 means adversarial review never ran

    @property
    def confirmed(self) -> list[ScanResult]:
        return sorted(
            (r for r in self.results if r.verdict == "confirmed"),
            key=lambda r: -r.confidence,
        )

    def to_dict(self) -> dict:
        return {
            "repo": self.repo, "ref": self.ref,
            "raw_findings": self.raw_findings,
            "hunt_cost_usd": self.hunt_cost_usd,
            "verify_cost_usd": self.verify_cost_usd,
            "hunt_seconds": self.hunt_seconds,
            "hunt_error": self.hunt_error,
            "verifiers": self.verifiers,
            "results": [r.to_dict() for r in self.results],
        }


def scan_repo(
    repo: Path,
    hunter,
    out_dir: Path,
    cache_dir: Path,
    work_dir: Path,
    ref: str = "HEAD",
    swarm: int = 3,
    lenses: list[str] | None = None,
    reps: int = 3,
    verifiers: int = 2,
    verifier: "Verifier | None" = None,
    install_cmd: str | None = None,
    python: str = "python3",
    keep: bool = False,
) -> ScanReport:
    from concurrent.futures import ThreadPoolExecutor

    from .hunter import LENSES, restore_repo
    from .mine import guess_install
    from .models import Instance
    from .workspace import WorkspaceFactory

    repo = Path(repo).expanduser().resolve()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    instance = Instance(
        instance_id=f"scan__{repo.name.removesuffix('.git')}",
        repo=str(repo),
        base_commit=ref,
        gold_patch="",  # there is no fix to compare against; that is the whole problem
        install_cmd=install_cmd if install_cmd is not None else guess_install(repo, ref),
        python=python,
    )

    lens_list = (lenses or list(LENSES))[:swarm] or ["boundary"]
    while len(lens_list) < swarm:
        lens_list.append(list(LENSES)[len(lens_list) % len(LENSES)])

    factory = WorkspaceFactory(cache_dir=cache_dir, work_dir=work_dir)
    report = ScanReport(repo=repo.name, ref=ref, verifiers=verifiers)
    workspaces = [factory.build(instance, label=f"scan{i}") for i in range(swarm)]

    try:
        def _hunt(i: int):
            ws = workspaces[i]
            fdir = out_dir / "findings" / f"h{i}_{lens_list[i]}"
            return hunter.hunt(ws.root, ws.python, fdir, lens_list[i])

        with ThreadPoolExecutor(max_workers=swarm) as pool:
            hunts = list(pool.map(_hunt, range(swarm)))

        findings: list[Finding] = []
        for h in hunts:
            findings.extend(h.findings)
            report.hunt_cost_usd += h.cost_usd
            report.hunt_seconds = max(report.hunt_seconds, h.seconds)
            if h.error:
                report.hunt_error = (report.hunt_error + " | " + h.error).strip(" |")
        report.raw_findings = len(findings)

        # Gate 1 -- reproducibility, against source the hunters cannot have touched.
        ws = workspaces[0]
        restore_repo(ws.root)
        # Tear down the other hunters' workspaces before validating. Combined with path
        # sanitization this means a repro that reaches outside the validation workspace
        # fails loudly instead of silently importing agent-writable code.
        for extra in workspaces[1:]:
            extra.destroy()
        surviving: list[Finding] = []
        prelim: dict[str, ScanResult] = {}
        for f in findings:
            verdict, runs, detail, rewritten = check_reproducible(
                ws, f, reps=reps, work_dir=Path(work_dir)
            )
            prelim[f.finding_id] = ScanResult(
                finding=f, verdict=verdict, runs=runs, detail=detail,
                signature=failure_signature(detail), path_rewritten=rewritten,
            )
            if verdict == "confirmed":
                surviving.append(f)

        # Gate 2 -- cluster, so the reviewer pays once per defect, not once per report.
        clusters = cluster(
            surviving,
            signatures={fid: r.signature for fid, r in prelim.items()},
        )
        reps_by_cluster = {cid: group[0] for cid, group in clusters.items()}

        # Gate 3 -- adversarial review of one representative per cluster.
        vote_map: dict[str, list[dict]] = {}
        if verifiers > 0 and reps_by_cluster:
            verifier = verifier or Verifier()

            def _review(item):
                cid, finding = item
                return cid, [verifier.review(ws.root, finding) for _ in range(verifiers)]

            with ThreadPoolExecutor(max_workers=min(4, len(reps_by_cluster))) as pool:
                for cid, votes in pool.map(_review, reps_by_cluster.items()):
                    vote_map[cid] = votes
                    report.verify_cost_usd += sum(v.get("cost_usd", 0.0) for v in votes)

        for cid, group in clusters.items():
            votes = vote_map.get(cid, [])
            verdict, confidence = adjudicate(votes, len(group), verifiers)
            for f in group:
                r = prelim[f.finding_id]
                r.cluster_id = cid
                r.duplicates = [g.finding_id for g in group if g.finding_id != f.finding_id]
                r.votes = votes
                # Only the cluster representative was reviewed; duplicates inherit its
                # verdict, which is the point of clustering.
                r.verdict = verdict
                r.confidence = confidence

        report.results = list(prelim.values())
        return report
    finally:
        if not keep:
            for w in workspaces:
                w.destroy()
