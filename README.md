# rediscovery-bench

Measures whether an agent can find a bug nobody told it about.

SWE-bench hands the model an issue report and grades the fix. Here the issue report is withheld. The agent gets a repo at a commit where a known bug exists and is asked to find defects blind. The held-out fix is never shown to it and serves only as the oracle.

That gives the one number that decides whether an autonomous bug-finding product is real. Can it rediscover bugs whose existence is already documented? An agent that cannot find bugs in software whose bugs are known will not find unknown ones in a stranger's codebase, and you learn that in a week instead of two years.

## The oracle

Every finding must ship with an executable repro. Scoring asks one mechanical question: does the held-out fix flip this repro from failing to passing? There is no LLM judge and no matching of a description against a patch.

| verdict | meaning |
|---|---|
| `rediscovered` | fails on the buggy code, passes under the fix. The agent found the bug. |
| `unmatched` | a reproducible failure the fix does not address. An unrelated real bug, or a broken repro. |
| `invalid` | passes on the buggy code. Nothing was demonstrated. |
| `flaky` | nondeterministic across repetitions. Never counted as a success. |
| `error` | the repro could not execute at all. |

Separating `rediscovered` from `unmatched` is the point. "The agent reported something plausible" and "the agent found the bug" are different claims.

## Quick start

```bash
pip install -r requirements.txt
python3 -m bench selftest          # the benchmark oracle
python3 -m bench selftest --scan   # the scan gates
```

The first command runs the whole pipeline against a fixture with a planted defect and three planted findings. One is correct, one proves nothing, and one fails for an unrelated reason. It asserts each is scored correctly. It is free and needs no credentials. Verify it passes before trusting any number the harness prints.

```bash
python3 -m bench verify instances/cve        # prove instances are solvable (free)
python3 -m bench run instances/cve --swarm 3 --budget 2.0
```

The hunter shells out to the `claude` CLI. A spawned subprocess does not inherit the auth of an interactive session, so either set `ANTHROPIC_API_KEY` or run `claude` once interactively and complete `/login`. The harness preflights this and fails with a diagnosis. Without that check, a credential problem finishes in seconds, reports zero findings, and looks identical to a genuine 0% score.

## The CVE corpus

Five real vulnerabilities, curated from published GitHub advisories. Every commit SHA is resolved from the GitHub API at curation time and never typed by hand, because a mistyped SHA produces an instance that silently scores zero forever.

| instance | CVE | the defect |
|---|---|---|
| `requests` | CVE-2023-32681 | `Proxy-Authorization` attached to https:// requests, leaking proxy credentials through the CONNECT tunnel to the destination |
| `jinja` | CVE-2024-22195 | `\|xmlattr` escaped attribute values but not keys, so a key containing a space injects arbitrary HTML attributes |
| `pyjwt` | CVE-2022-29217 | HMAC refused asymmetric keys through a four-entry string blocklist, so any other key format slipped through and enabled algorithm confusion |
| `flask` | CVE-2023-30861 | `Vary: Cookie` was added after the early return for an empty session, so caches could serve one user's session cookie to another |
| `urllib3` | CVE-2023-45803 | a 303 rewrites the method to GET, and the request body was still forwarded, leaking POST credentials to the redirect target |

All five are proven solvable. `python3 -m bench verify instances/cve` scores 5/5 REDISCOVERED. Each instance ships a witness, a hand-written repro that must score `rediscovered`. Its job is to prove the instance is findable at all, through the same oracle a hunter's finding goes through. Without it, an unsolvable instance and an incapable agent produce the same number.

Contamination matters here. These fixes are public and predate most training cutoffs, so an agent can recall the advisory instead of deriving the bug, and recall is not the capability this benchmark claims to measure. Three mitigations, weakest first. The scorecard flags any rediscovery whose write-up cites a CVE or GHSA id and prints a floor with those subtracted. Mutation instances are generated locally and cannot be recalled, so a large CVE-to-mutation gap is a contamination signal. Curating CVEs published after the model's cutoff is the only real fix, and it means the corpus needs continuous refresh.

## Replay: measuring on a customer's own repo

A customer has code with unknown bugs and no gold patch, so the oracle that makes scoring trustworthy is the thing their repo does not come with. Their git history supplies it. Every bug fix is a rediscovery instance whose oracle their own team wrote.

```bash
python3 -m bench replay ~/src/their-repo --limit 10 --calibrate-only   # free
python3 -m bench replay ~/src/their-repo --limit 10 --swarm 3          # costs money
```

Calibration mines fix commits, extracts the developer's own regression test as the witness, and keeps only instances that provably discriminate. It needs no human labeling and no API spend. The hunt phase then runs the agent against the kept instances and writes `REPORT.md` with bugs caught, bugs missed, the failing test for each, cost per bug, and what was excluded and why.

Calibration yield depends on the repo. On `requests`, 3 of 6 mined fixes were replayable. On `jinja`, 3 of 5. Fixes are dropped when they add no new test, when the developer's test does not discriminate, or when the environment cannot be rebuilt. Dropped instances are excluded from the denominator and not counted as misses, because an unbuildable instance says nothing about the agent.

Three failure modes silently invalidate replay. Each produced confident wrong output during development, and each is now handled. First, a released copy of the package can shadow the source, because dev requirements often pin the project itself, which lands in `site-packages` and wins the import. The oracle patch then edits source nothing imports, and every instance scores `unmatched`. Installing test dependencies first and the package under test last took `jinja` from 0/5 to 3/5. Second, the oracle patch can collide with the staged witness when the fix commit also modifies the test file, so `git apply` fails. The staged path is now excluded from the patch. Third, a witness that runs the whole post-fix test file drags in unrelated tests, and one environmental failure makes the file fail on both sides. Only the test functions the fix introduced are selected.

## Scan: hunting current HEAD

```bash
python3 -m bench scan ~/src/their-repo --swarm 3 --verifiers 2
python3 -m bench selftest --scan          # prove the gates discriminate, free
```

There is no oracle on HEAD, because there is no held-out fix, so nothing can mechanically prove a finding is a defect and not intended behaviour. The oracle degrades into a filter pipeline, strongest first.

Reproducibility is mechanical and unforgiving. The repro must fail deterministically across N runs against source no agent touched. A repro that passes proves nothing. One that errors on import proves nothing about the code. One that flickers is worse than nothing, because it will burn a real engineer's afternoon. This gate removes most of what a swarm produces.

Independent rediscovery is free, because the swarm already ran. Findings are clustered by failure signature, meaning where in the source the repro actually fails. Two write-ups of the same bug can share almost no vocabulary, so clustering on prose fails in the case that matters. Clustering on evidence does not.

Adversarial review is expensive and needs judgement. Independent agents are asked to refute the finding, by arguing it is intended behaviour, a misread contract or a bad test, and it is dropped by majority. Asking for refutation matters, because an agent asked "is this real?" agrees with almost anything. Reviewers run with edit tools disabled, since a reviewer that can modify the code under review is not a reviewer. An unparseable vote counts as not endorsing, so a broken verifier can never promote a finding.

The report leads with a runnable failing test for each confirmed item and lists everything filtered out with the reason. A tool that reports 3 findings without mentioning it discarded 40 is asking to be trusted on faith.

Scan cannot report its own precision, because precision needs ground truth and HEAD has none. `bench replay` measures precision against the same repo's real bug history, and scan inherits that number. A scan precision quoted with no replay number behind it is a guess.

## Getting more instances

Mutation gives an unlimited free oracle. Inject a single-token fault into any repo, and the fix is its reversal, so there is nothing to hand-label.

```bash
python3 -m bench mutate ~/src/some-repo --count 20
```

The two tiers matter more than the count. A mutant the project's own test suite already kills is a smoke test, since running the existing suite finds it. A mutant that survives the suite is the real target, because it is a genuine hole in coverage that requires reasoning about the code.

Curation from advisories is more realistic. One command resolves the advisory, picks the fix commit, derives the buggy state from its parent, and downloads the patch.

```bash
python3 -m bench curate CVE-2023-32681 --repo psf/requests --fix 74ea7cf
```

Then write a witness and run `bench verify`. SWE-bench instances convert directly, because they already carry `repo`, `base_commit` and the gold patch. You simply never show the issue text.

Pin dependencies to the era of the bug. The flask instance first scored `unmatched`, with the witness failing both before and after the fix, because modern Werkzeug removed `werkzeug.__version__` and Flask 2.3's `test_client()` crashed for reasons unrelated to the CVE. Every curated instance needs `install_cmd` pinned to contemporaneous dependencies, or transitive-dependency drift manufactures fake zeros. `bench verify` catches this.

## Anti-cheat

History leak. `git clone && git checkout <base>` leaves every future commit, including the fix, in the object database, reachable through `origin/main`. Workspaces are built with `git archive` into a fresh single-commit repo, so there is no future to read.

Self-serving repros. An agent that edits the source could make its own repro pass. Validation runs in a workspace restored to pristine source, and edits are logged.

Workspace escape. A live scan found this one. A hunter wrote `sys.path.insert(0, "<its own workspace>")` into its reproduction, so validation imported code from a directory that agent could write to. Nothing malicious happened. The agent was making its imports work, which is why the fix is mechanical and not a line in the prompt. Absolute workspace paths are now rewritten to the validation workspace, the other hunters' workspaces are torn down before validation so a stale path fails loudly, and any rewrite is disclosed in the report.

A guarantee you have only reasoned about is a guarantee you have not tested. The first live scan run invalidated a claim this README was already making.

## Interpreting results

The scorecard leads with cost per confirmed rediscovery and not with findings count, because a swarm can produce a thousand findings.

Instances that fail to build are reported separately and never dropped from a denominator, so a 60% rate over the 5 repos that happened to install is not a 60% rate. `unmatched` findings are always reported and never folded into success or into noise, because some are real bugs you did not plant. Repros run `--reps` times per side, since one flaky test that fails before the patch and passes after is enough to make the headline number a lie.

Known limitation: equivalent mutants. Some injected faults do not change behaviour, so no repro can discriminate them, and they depress the score through no fault of the hunter. Treat surviving-mutant scores as a lower bound and spot-check a sample by hand before quoting a number.

## Tuning the swarm

`--swarm N` runs N hunters per instance, each with a different lens (`boundary`, `state`, `errors`, `contract`, `resource`, `data`). A thousand identical agents explore the same region a thousand times. A thousand agents with different priors explore a thousand regions. Diversity of hypothesis is what makes a swarm worth more than one run, so raise `--swarm` before you raise `--effort`.

## Layout

```
bench/workspace.py   build, install and run. Leak prevention lives here
bench/mine.py        mine a repo's own fixes into instances
bench/curate.py      CVE advisory into an instance
bench/scan.py        hunt HEAD with no oracle: gates, clustering, adversarial review
bench/hunter.py      the agent, the prompt, and the swarm's diversity lenses
bench/validate.py    the differential oracle
bench/score.py       aggregation
bench/mutate.py      fault injection
bench/report.py      evidence reports for replay and scan
bench/runner.py      orchestration
fixtures/            a toy repo and planted findings used by selftest
instances/cve/       the five curated instances, their patches and witnesses
```

Run outputs (`results/`), generated mutants and the repo cache are not in this repo.
