"""Render results as an evidence report.

The audience is someone deciding whether to trust an autonomous bug finder on their
own codebase. That person is not moved by a findings count -- they have seen linters.
They are moved by: these are bugs your team actually shipped, here is what we found
blind, here is the failing test, here is what it cost.

So the report leads with what was caught and what was missed, and never hides the
denominator.
"""

from __future__ import annotations

from pathlib import Path

from .models import InstanceReport
from .score import Scorecard, recall_flagged


def _fence(text: str, lang: str = "python", limit: int = 2400) -> str:
    body = text if len(text) <= limit else text[:limit] + "\n... (truncated)"
    return f"```{lang}\n{body}\n```"


def scan_report(report) -> str:
    """Render a scan as something a developer can act on in one pass.

    Every confirmed item leads with a runnable failing test, because a bug report is
    work handed to the developer and a failing test is work already done for them.
    Everything filtered out is shown as counts, not hidden: a tool that reports 3
    findings without saying it discarded 40 is asking to be trusted on faith.
    """
    confirmed = report.confirmed
    by_verdict: dict[str, int] = {}
    seen_clusters: set[str] = set()
    for r in report.results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1

    lines = [
        f"# Scan — {report.repo} @ {report.ref}",
        "",
        f"**{len(confirmed)} confirmed** · {report.raw_findings} raw findings · "
        f"${report.hunt_cost_usd + report.verify_cost_usd:.2f} "
        f"({report.hunt_seconds / 60:.1f} min)",
        "",
        "| Stage | Result |",
        "|---|---|",
        f"| Reported by hunters | {report.raw_findings} |",
        f"| Reproduce deterministically | "
        f"{report.raw_findings - by_verdict.get('not_reproducible', 0) - by_verdict.get('error', 0)} |",
        (f"| Survived adversarial review | {by_verdict.get('confirmed', 0)} |"
         if report.verifiers else
         "| Survived adversarial review | _skipped (`--verifiers 0`)_ |"),
        f"| Distinct defects after dedup | {len({r.cluster_id for r in confirmed})} |",
        "",
    ]

    if not confirmed:
        lines += ["No findings survived the filters.", ""]
    else:
        lines += ["## Confirmed", ""]

    for r in confirmed:
        if r.cluster_id in seen_clusters:
            continue
        seen_clusters.add(r.cluster_id)
        f = r.finding
        lines += [
            f"### {f.title}",
            "",
            (f"**Confidence {r.confidence:.2f}**" if report.verifiers
             else "**Confidence unmeasured** (no adversarial review)")
            + (f" · found independently by {len(r.duplicates) + 1} hunters"
               if r.duplicates else "")
            + (f" · files: {', '.join(f.target_files)}" if f.target_files else ""),
            "",
            f.description.strip(),
            "",
        ]
        if r.path_rewritten:
            lines += ["> _Note: this reproduction hardcoded a workspace path; it was "
                      "re-pointed at the validation workspace before running._", ""]
        try:
            lines += ["**Failing test**", _fence(Path(f.repro_path).read_text()), ""]
        except OSError:
            pass
        for v in r.votes:
            if v.get("reason"):
                lines += [f"> Reviewer: {v['reason']}", ""]

    rejected = [r for r in report.results if r.verdict != "confirmed"]
    if rejected:
        lines += [
            "## Filtered out",
            "",
            "Shown so the numbers above are auditable rather than taken on trust.",
            "",
            "| Finding | Why |",
            "|---|---|",
        ]
        for r in rejected[:40]:
            reason = {
                "not_reproducible": "did not fail reliably on current code",
                "error": "reproduction could not execute",
                "disputed": "reviewers judged it intended behaviour",
            }.get(r.verdict, r.verdict)
            lines.append(f"| {r.finding.title[:70]} | {reason} |")
        lines.append("")

    lines += [
        "## How to read this",
        "",
        "- Every confirmed item **fails on your current code**, verified repeatedly "
        "against source no agent modified.",
        ("- Confirmed means reproducible and not refuted by independent review. It does "
         "not mean important — severity is your call."
         if report.verifiers else
         "- Adversarial review was skipped, so `confirmed` here means **reproducible "
         "only**. Nothing has judged whether these behaviours are intended."),
        "- This scan cannot report its own precision. Precision is measured by replaying "
        "this repository's real bug history (`bench replay`); without that number, treat "
        "confidence scores as ordering, not probability.",
        "",
    ]
    return "\n".join(lines)


def replay_report(
    repo_name: str,
    reports: list[InstanceReport],
    card: Scorecard,
    instance_notes: dict[str, str],
    dropped: list[tuple[str, str]],
) -> str:
    hits = [r for r in reports if r.rediscovered]
    misses = [r for r in reports if not r.rediscovered and not r.setup_error]

    lines = [
        f"# Bug rediscovery report — {repo_name}",
        "",
        "We took bug fixes from this repository's own history, checked the code out at "
        "the commit **before** each fix, and asked an agent to find defects with no issue "
        "report, no hint, and no access to the fix.",
        "",
        "A finding counts only if the developer's real fix flips its reproduction from "
        "failing to passing. There is no human judgement and no model grading that call.",
        "",
        "## Result",
        "",
        f"- **{card.rediscovered_instances} of {card.instances_scored}** past bugs "
        f"rediscovered blind (**{100 * card.rediscovery_rate:.0f}%**)",
    ]
    if card.cost_per_rediscovery_usd is not None:
        lines.append(f"- **${card.cost_per_rediscovery_usd:.2f}** per confirmed bug "
                     f"(${card.total_cost_usd:.2f} total)")
    lines += [
        f"- {card.findings_total} findings reported; "
        f"{100 * card.precision:.0f}% were a real past bug, "
        f"{100 * card.noise_rate:.0f}% demonstrated nothing",
        "",
    ]
    if card.verdicts.get("unmatched"):
        lines += [
            f"> {card.verdicts['unmatched']} finding(s) reproduced a real failure that "
            "none of these fixes address. Some are unrelated bugs still live in the code "
            "today; they are reported separately rather than counted either way.",
            "",
        ]

    lines += ["## Bugs we caught", ""]
    if not hits:
        lines.append("_None._")
    for r in hits:
        note = instance_notes.get(r.instance_id, "")
        lines += [f"### `{r.instance_id}`", "", f"Original fix: {note}", ""]
        for f, v in ((f, v) for f in r.findings for v in r.validations
                     if v.finding_id == f.finding_id and v.verdict == "rediscovered"):
            lines += [f"**Found:** {f.title}", "", f.description.strip(), ""]
            try:
                lines += ["Reproduction:", _fence(Path(f.repro_path).read_text()), ""]
            except OSError:
                pass
            break

    lines += ["## Bugs we missed", ""]
    if not misses:
        lines.append("_None._")
    for r in misses:
        lines.append(f"- `{r.instance_id}` — {instance_notes.get(r.instance_id, '')}")
    lines.append("")

    if dropped:
        lines += [
            "## Excluded from the denominator",
            "",
            "These fixes could not be replayed, so counting them would have understated "
            "the result. Listed for completeness:",
            "",
        ]
        lines += [f"- `{name}` — {reason}" for name, reason in dropped]
        lines.append("")

    flagged = sum(len(recall_flagged(r)) for r in reports)
    if flagged:
        lines += [
            "## Caveat",
            "",
            f"{flagged} finding(s) cite a public advisory ID, which suggests recall of "
            "published material rather than analysis of the code. Discount accordingly.",
            "",
        ]

    lines += [
        "## Method",
        "",
        "- The agent saw the repository at the parent of each fix commit, exported with no "
        "git history — the fix is not reachable, not even via `git log`.",
        "- Every reproduction was run against untouched source in a separate workspace, so "
        "an agent that edited the code could not manufacture a pass.",
        "- Each reproduction ran multiple times before and after the fix; anything "
        "nondeterministic was discarded rather than counted.",
        "",
    ]
    return "\n".join(lines)
