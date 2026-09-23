"""Generate instances by injecting faults.

Curated corpora are small and slow to build. Mutation gives you unlimited instances
from any repo, with a *free* oracle: the fix for an injected fault is exactly its
reversal, so there is nothing to hand-label.

Two tiers, and the distinction matters more than the count:

  killed     -- the repo's own test suite already catches the mutant. A smoke test:
                a hunter that cannot find these is broken, but finding them proves
                little, since running the suite is enough.
  surviving  -- the suite misses it. This is the real target. A surviving mutant is
                a genuine hole in the project's test coverage, and finding it requires
                reasoning about the code rather than running what is already there.

The known limitation is *equivalent mutants*: a change that alters the source without
altering behaviour. No repro can discriminate one, so it depresses the measured
rediscovery rate through no fault of the hunter. Treat surviving-mutant scores as a
lower bound, and spot-check a sample by hand before quoting a number to anyone.
"""

from __future__ import annotations

import ast
import difflib
import json
import random
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Instance

# (kind, from, to). Applied as a scoped textual edit inside one expression's span,
# never a whole-file rewrite -- the hunter must read code that looks hand-written,
# not code an AST round-trip reformatted.
COMPARE_SWAPS = [
    ("<=", "<"), ("<", "<="), (">=", ">"), (">", ">="),
    ("==", "!="), ("!=", "=="),
    ("is not", "is"), ("not in", "in"),
]
BOOL_SWAPS = [(" and ", " or "), (" or ", " and ")]


@dataclass
class Mutant:
    rel_path: str
    line: int
    original_line: str
    mutated_line: str
    operator: str


def _span(source_lines: list[str], node: ast.AST) -> tuple[int, int, int] | None:
    """Return (line_index, start_col, end_col) for a single-line node."""
    if not hasattr(node, "lineno") or node.lineno != getattr(node, "end_lineno", None):
        return None
    return node.lineno - 1, node.col_offset, node.end_col_offset


def find_mutants(source: str, rel_path: str) -> list[Mutant]:
    """Enumerate single-token faults that keep the file parseable."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    out: list[Mutant] = []

    def emit(node: ast.AST, swaps, kind: str) -> None:
        loc = _span(lines, node)
        if loc is None:
            return
        idx, start, end = loc
        line = lines[idx]
        expr = line[start:end]
        for src, dst in swaps:
            if src not in expr:
                continue
            # Only mutate when the token appears once, so the edit is unambiguous.
            if expr.count(src) != 1:
                continue
            new_expr = expr.replace(src, dst, 1)
            new_line = line[:start] + new_expr + line[end:]
            candidate = "\n".join(lines[:idx] + [new_line] + lines[idx + 1:])
            try:
                ast.parse(candidate)
            except SyntaxError:
                continue
            out.append(Mutant(rel_path, idx + 1, line, new_line, f"{kind}:{src}->{dst}"))
            return  # one mutation per node keeps the corpus varied

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            emit(node, COMPARE_SWAPS, "compare")
        elif isinstance(node, ast.BoolOp):
            emit(node, BOOL_SWAPS, "boolop")
    return out


def _diff(rel_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )


def _git(args: list[str], cwd: Path, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, **kw)


def build_instance(
    source_repo: Path,
    mutant: Mutant,
    out_root: Path,
    instance_id: str,
    test_cmd: str,
    install_cmd: str,
    python: str,
) -> Instance:
    """Materialize one mutant as a standalone single-commit repo plus its Instance spec.

    The mutant repo has exactly one commit, so the correct version of the line is
    nowhere in the history for a hunter to find.
    """
    dest = out_root / instance_id
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=False)
    subprocess.run(
        ["cp", "-R", f"{source_repo}/.", str(dest)], check=True,
    )
    subprocess.run(["rm", "-rf", str(dest / ".git")], check=False)

    target = dest / mutant.rel_path
    original = target.read_text()
    lines = original.splitlines(keepends=True)
    ending = "\n" if lines[mutant.line - 1].endswith("\n") else ""
    lines[mutant.line - 1] = mutant.mutated_line + ending
    mutated = "".join(lines)
    target.write_text(mutated)

    _git(["init", "--quiet", "-b", "main"], dest)
    _git(["add", "-A"], dest)
    _git(
        ["-c", "user.email=bench@local", "-c", "user.name=bench",
         "commit", "--quiet", "-m", "baseline"],
        dest,
    )

    return Instance(
        instance_id=instance_id,
        repo=str(dest.resolve()),
        base_commit="HEAD",
        gold_patch=_diff(mutant.rel_path, mutated, original),  # the fix reverses the fault
        test_cmd=test_cmd,
        install_cmd=install_cmd,
        python=python,
        source="mutation",
        tier="unknown",
        notes=f"{mutant.operator} at {mutant.rel_path}:{mutant.line}",
    )


def generate(
    repo: Path,
    out_root: Path,
    count: int = 5,
    include: str = "**/*.py",
    seed: int = 0,
    test_cmd: str = "python -m pytest -x -q",
    install_cmd: str = "python -m pip install -e .",
    python: str = "python3",
) -> list[Instance]:
    repo = Path(repo).resolve()
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    candidates: list[Mutant] = []
    for path in sorted(repo.glob(include)):
        rel = path.relative_to(repo).as_posix()
        if any(part in rel for part in ("test", ".venv", "site-packages", "build/", "dist/")):
            continue
        try:
            candidates.extend(find_mutants(path.read_text(), rel))
        except (UnicodeDecodeError, OSError):
            continue

    if not candidates:
        return []

    rng = random.Random(seed)
    rng.shuffle(candidates)
    slug = repo.name.replace(" ", "_")
    instances = []
    for i, mutant in enumerate(candidates[:count]):
        inst = build_instance(
            repo, mutant, out_root, f"mut__{slug}__{i:03d}",
            test_cmd=test_cmd, install_cmd=install_cmd, python=python,
        )
        (out_root / f"{inst.instance_id}.json").write_text(
            json.dumps(inst.__dict__, indent=2)
        )
        instances.append(inst)
    return instances
