"""Turn a published security advisory into a benchmark instance.

Curating by hand does not scale and does not survive review: a mistyped commit SHA
produces an instance that silently scores zero forever. Everything here is resolved
from GitHub at curation time, so the only human input is "which CVE".

    python3 -m bench curate CVE-2023-32681

The buggy state is the fix commit's *parent*. The fix commit itself becomes the gold
patch, which the hunter never sees.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from pathlib import Path

from .models import Instance

COMMIT_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")


class CurationError(RuntimeError):
    pass


def _gh(path: str) -> dict | list:
    proc = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0:
        raise CurationError(f"gh api {path} failed: {proc.stderr.strip()[:400]}")
    return json.loads(proc.stdout)


def resolve_advisory(cve: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (summary, [(repo, sha), ...]) for every fix commit the advisory cites."""
    data = _gh(f"/advisories?cve_id={cve}")
    if not data:
        raise CurationError(f"no GitHub advisory found for {cve}")
    adv = data[0]
    commits: list[tuple[str, str]] = []
    for ref in adv.get("references", []):
        m = COMMIT_RE.search(ref)
        if m and (m.group(1), m.group(2)) not in commits:
            commits.append((m.group(1), m.group(2)))
    return adv.get("summary", ""), commits


def fetch_patch(repo: str, sha: str) -> str:
    """The commit's own diff. Used only as the oracle -- never shown to a hunter."""
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    with urllib.request.urlopen(url, timeout=120) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    # A .patch is mbox-formatted; strip the mail header so `git apply` is happy.
    idx = raw.find("\ndiff --git ")
    if idx == -1:
        raise CurationError(f"no diff found in {url}")
    return raw[idx + 1:]


def curate(
    cve: str,
    repo: str | None = None,
    fix_sha: str | None = None,
    install_cmd: str = "python -m pip install -e .",
    python: str = "python3",
    instance_id: str | None = None,
) -> Instance:
    summary, commits = resolve_advisory(cve)
    if fix_sha and repo:
        chosen = (repo, fix_sha)
    else:
        candidates = [c for c in commits if repo is None or c[0] == repo]
        if not candidates:
            raise CurationError(
                f"{cve}: no fix commit found in the advisory references. "
                f"Pass --repo/--fix explicitly. Saw: {commits}"
            )
        if len(candidates) > 1:
            # Multiple commits usually means backports to release branches. Guessing
            # picks the wrong parent and silently produces an unsolvable instance.
            raise CurationError(
                f"{cve}: advisory cites {len(candidates)} fix commits; pick one with "
                f"--repo/--fix.\n  " + "\n  ".join(f"{r} {s}" for r, s in candidates)
            )
        chosen = candidates[0]

    repo_name, sha = chosen
    meta = _gh(f"repos/{repo_name}/commits/{sha}")
    parents = meta.get("parents", [])
    if not parents:
        raise CurationError(f"{sha} has no parent; cannot derive a buggy state")
    base = parents[0]["sha"]

    slug = repo_name.split("/")[-1]
    return Instance(
        instance_id=instance_id or f"{slug}__{cve}",
        repo=f"https://github.com/{repo_name}.git",
        base_commit=base,
        gold_patch=fetch_patch(repo_name, meta["sha"]),
        install_cmd=install_cmd,
        python=python,
        test_deps="",  # curated instances use a hand-written witness, not the repo's suite
        source="cve",
        tier="surviving",  # a shipped release means the suite did not catch it
        cve=cve,
        notes=f"{summary} | fix {meta['sha'][:12]} in {repo_name}",
    )


def write(instance: Instance, out_dir: Path) -> Path:
    """Write the instance, keeping the gold patch in a sidecar file.

    The patch lives outside the JSON so it stays reviewable in a diff -- an oracle
    you cannot eyeball is an oracle you cannot trust.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    patch_name = f"{instance.instance_id}.patch"
    (out_dir / patch_name).write_text(instance.gold_patch)

    data = {k: v for k, v in instance.__dict__.items() if k != "gold_patch"}
    data["gold_patch_file"] = patch_name
    path = out_dir / f"{instance.instance_id}.json"
    path.write_text(json.dumps(data, indent=2))
    return path
