"""Aggregate reports into the handful of numbers that actually decide anything.

Deliberately kept honest in two ways:

- Instances that failed to build are reported separately and never silently
  dropped from a denominator. A 60% rediscovery rate over the 5 repos that
  happened to install is not a 60% rediscovery rate.
- "Findings" is never the headline. Cost per *confirmed* rediscovery is, because
  that is the number a customer's budget actually meets.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Any

from .models import InstanceReport

# A hunter that writes "this is CVE-2023-32681" did not derive the bug from the code --
# it recognised a fix that was in its training data. That is not the capability the
# benchmark claims to measure, so it is surfaced rather than quietly counted as a win.
_RECALL_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b",
                        re.IGNORECASE)


def recall_flagged(report: InstanceReport) -> set[str]:
    """Findings that name a public advisory ID -- evidence of recall, not reasoning."""
    return {
        f.finding_id
        for f in report.findings
        if _RECALL_RE.search(f"{f.title}\n{f.description}")
    }


@dataclass
class Scorecard:
    instances_total: int
    instances_scored: int
    instances_failed_setup: int
    rediscovered_instances: int
    rediscovery_rate: float

    findings_total: int
    verdicts: dict[str, int]
    precision: float           # rediscovered findings / all findings
    valid_repro_rate: float    # findings that reproduce a real failure / all findings
    noise_rate: float          # findings that demonstrate nothing / all findings

    total_cost_usd: float
    cost_per_rediscovery_usd: float | None
    total_hunt_seconds: float
    # Rediscoveries whose write-up cites a CVE/GHSA id. On a corpus drawn from public
    # advisories these are the ones to distrust: subtract them for a contamination-
    # resistant floor, and compare against mutation instances, which cannot be recalled.
    recall_flagged_rediscoveries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
        lines = [
            "",
            "=" * 62,
            "  REDISCOVERY BENCHMARK",
            "=" * 62,
            "",
            f"  Rediscovery rate      {pct(self.rediscovery_rate)}"
            f"   ({self.rediscovered_instances}/{self.instances_scored} known bugs found blind)",
            f"  Cost per rediscovery  "
            + (f"${self.cost_per_rediscovery_usd:.2f}"
               if self.cost_per_rediscovery_usd is not None
               else "n/a  (nothing rediscovered)"),
            f"  Total spend           ${self.total_cost_usd:.2f}"
            f"   over {self.total_hunt_seconds / 60:.1f} min of hunting",
            "",
            f"  Findings reported     {self.findings_total}",
            f"    precision           {pct(self.precision)}   were the held-out bug",
            f"    valid repro         {pct(self.valid_repro_rate)}   demonstrated a real failure",
            f"    noise               {pct(self.noise_rate)}   demonstrated nothing",
            "",
            "  Verdict breakdown",
        ]
        for verdict in ("rediscovered", "unmatched", "invalid", "flaky", "error"):
            lines.append(f"    {verdict:<14} {self.verdicts.get(verdict, 0)}")
        if self.recall_flagged_rediscoveries:
            lines += [
                "",
                f"  ! {self.recall_flagged_rediscoveries} rediscovery(ies) cite a CVE/GHSA id"
                " -- likely recalled, not derived.",
                "    Contamination-resistant floor: "
                f"{self.rediscovered_instances - self.recall_flagged_rediscoveries}"
                f"/{self.instances_scored}",
            ]
        if self.instances_failed_setup:
            lines += [
                "",
                f"  ! {self.instances_failed_setup} instance(s) failed to build and are"
                " excluded from every rate above.",
            ]
        lines += ["", "=" * 62, ""]
        return "\n".join(lines)


def score(reports: list[InstanceReport]) -> Scorecard:
    scored = [r for r in reports if not r.setup_error]
    failed = len(reports) - len(scored)

    verdicts = Counter(v.verdict for r in scored for v in r.validations)
    findings_total = sum(verdicts.values())
    rediscovered = sum(1 for r in scored if r.rediscovered)
    cost = sum(r.hunt_cost_usd for r in reports)

    flagged = 0
    for r in scored:
        suspect = recall_flagged(r)
        if any(v.verdict == "rediscovered" and v.finding_id in suspect for v in r.validations):
            flagged += 1

    def over_findings(n: int) -> float:
        return n / findings_total if findings_total else 0.0

    return Scorecard(
        instances_total=len(reports),
        instances_scored=len(scored),
        instances_failed_setup=failed,
        rediscovered_instances=rediscovered,
        rediscovery_rate=rediscovered / len(scored) if scored else 0.0,
        findings_total=findings_total,
        verdicts=dict(verdicts),
        precision=over_findings(verdicts.get("rediscovered", 0)),
        valid_repro_rate=over_findings(
            verdicts.get("rediscovered", 0) + verdicts.get("unmatched", 0)
        ),
        noise_rate=over_findings(verdicts.get("invalid", 0) + verdicts.get("error", 0)),
        total_cost_usd=cost,
        cost_per_rediscovery_usd=(cost / rediscovered) if rediscovered else None,
        total_hunt_seconds=sum(r.hunt_seconds for r in reports),
        recall_flagged_rediscoveries=flagged,
    )
