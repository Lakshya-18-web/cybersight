# Week 2, Day 6 handoff: three DEV runs of the locked baseline, mean/spread, cross-run error analysis

Status: the Day 6 tooling is written and tested with mocks. **No Gemini call was made, no real run was made, nothing was committed, and the Day 3 run,
the Day 5 run and the Week 1 files were not touched.** The three real runs are for you to execute with the commands below.

Roadmap scope (Week 2, Day 6): three DEV runs of the locked baseline, then mean and spread, then error analysis. Nothing else.

## 1. What is in the package

| File | New or changed | Purpose |
|---|---|---|
| `src/day6_replicates.py` | new | Checked wrapper around the existing runner: `check`, `run --replicate N` / `run --all`, `status` |
| `src/day6_aggregate.py` | new | Mean, spread and cross-run error analysis from the three Day 4 evaluations; writes the Day 6 report |
| `tests/test_week2_day6.py` | new | 80 tests (mocks and synthetic data only) |
| `WEEK2_DAY6_HANDOFF.md` | new | This file |

No existing file is changed: `run_baseline_dev.py`, `prompt_registry.py`, `baseline_prompt.py`, the parser, the schema, the Day 4 evaluator, the cost and
tracing modules are exactly as in Day 5. No new dependency: only the standard library, pandas (already used) and the project's own modules (a test checks this).
`tests/test_week2_day6.py` reuses test helpers from `tests/test_week2_day3.py` and `tests/test_week2_day5.py`, so those two files must stay in `tests/`.

## 2. What is locked

- Prompt: `baseline_v3`, sha256 `9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7`. (The hash in your Day 6 request is missing six characters
  in the middle, `...f0f4b4b58efa...`; the value above is the one computed from the repo and pinned by the Day 6 tests. Its first and last characters match yours.)
- Baseline v1 hash is unchanged: `0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172`.
- Model, temperature, seed, max output tokens, parse retries, alert list and dev inputs are the ones the reference run `dev_flash_lite_v3_final` used. The wrapper
  reads them from that run's `run_meta.json` and refuses to run if anything differs. No hash is hard-coded in the wrapper, so it cannot drift from what was evaluated.
- The settings are **not** varied between replicates. The spread you measure is therefore how repeatable the model service is for the same request, not a sweep.
  It may turn out very small, or zero; that is a valid result and the report says so.

## 3. Before anything: install and test (no model calls)

Unzip over the repo root (it adds three files and one handoff; it overwrites nothing from earlier days). Then:

```
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 -v
```

Expected: every test passes. Count to expect: your Day 1-4 total (172) + 76 (Day 5) + 80 (Day 6) = **328**, if your Day 5 test file is the delivered one. In the sandbox
the Day 1, 2, 3, 5 and 6 files ran together: 278 tests, all OK (Day 4 could not be run there because your committed Day 4 files were not available).

Then the preflight (no model call, writes nothing):
```
python src/day6_replicates.py check
```
Expected: `Locked prompt: baseline_v3 sha256 9403e7ea...`, the reference run and its model, the three replicate names each `[absent]`, and `Preflight OK. Nothing was run and nothing was written.`
If it prints `PROBLEM:` lines, stop and read them: the usual causes are a changed prompt, model, setting or dev input file, or `SOC_FROZEN_UNLOCK` set in the shell.

## 4. The exact three-run procedure

Run one replicate at a time (recommended; each is about the size of the Day 5 run: about 300 alerts, about 310 calls, about 670,000 tokens, and about half an hour at the
default 10 calls per minute). Keep the laptop awake. Use a fresh terminal command for each replicate.

```
python src/day6_replicates.py run --replicate 1
python src/evaluate.py --run-name dev_flash_lite_v3_d6_rep1

python src/day6_replicates.py run --replicate 2
python src/evaluate.py --run-name dev_flash_lite_v3_d6_rep2

python src/day6_replicates.py run --replicate 3
python src/evaluate.py --run-name dev_flash_lite_v3_d6_rep3
```
(`python src/day6_replicates.py run --all` runs the replicates that are not complete, one after another; it stops at the first one that needs attention.)

What each `run` does: preflight; refuses if the replicate is already complete (it is never run again or overwritten); starts a fresh run folder
`runs/week2_baseline_v1/dev_flash_lite_v3_d6_repN` with its own client and session through the unchanged runner (`--prompt-version baseline_v3`); afterwards verifies that the
run is complete, dev only, the locked prompt, the reference alert list, the locked settings, with no model errors and with the frozen-log and Week 1 guard flags true; and records the replicate in
`runs/week2_day6/replicates_manifest.json` (prompt hash, protected-run hashes, frozen log line count at the start, per-file hashes of each replicate).

If a replicate is interrupted (laptop slept, quota, network): `python src/day6_replicates.py run --replicate N --resume`. A resumed run keeps its own prompt and settings.
A sleep gap is a wall-clock gap and is not a latency; do not exclude anything with `--exclude-latency-seconds` unless an actually recorded latency needs it.

Optional: `--langsmith` (metadata-only tracing as in Day 5; needs `LANGSMITH_API_KEY`), `--rpm N` (call rate). Neither changes model behavior. Cost, if you want it, with your own verified prices:
`python src/cost_tracking.py --run-name dev_flash_lite_v3_d6_rep1 --pricing-file pricing.json` (or `evaluate.py --pricing-file pricing.json`).

## 5. Evaluation of each run

`python src/evaluate.py --run-name <replicate>` is the unchanged Day 4 harness. It writes `reports/week2_eval/<replicate>/` (`EVALUATION_REPORT.md`, `evaluation.json`, `per_alert.csv`, ...)
and checks that the run files, the protected Week 1 files and the frozen access log did not change. All three replicates must be evaluated before aggregation, none with `--allow-partial`.

## 6. Aggregation: mean, spread, error analysis

```
python src/day6_aggregate.py
```
Reads, for each replicate, `reports/week2_eval/<replicate>/evaluation.json`, `.../per_alert.csv` and `runs/week2_baseline_v1/<replicate>/run_meta.json`, plus the Day 5 run as an extra
reference column (`--no-reference` to leave it out). It reads no label file, no MITRE key and nothing frozen; the labels and accepted ids in the report come from the Day 4 per-alert output.
It stops, and writes nothing, unless the three runs are comparable: same prompt hash (baseline_v3, optionally `--expected-sha256`), model, settings (except call rate), inputs, alert list and protected
files; all complete, dev, not partial; all integrity flags true; and the per-alert counts it rebuilds agree with the numbers in each evaluation.json.

Output folder `reports/week2_day6/` (it refuses to overwrite without `--force`):
- `DAY6_THREE_RUN_REPORT.md`: the Day 6 report (what was run, per-run results with mean and spread, variation between runs, persistent / recurring / one-off errors, conclusions, limits)
- `three_run_metrics.csv`: every metric, per run, mean, sd, min, max, range, reference
- `three_run_summary.json`: the same plus error-category counts, method and the sha256 of every input file read
- `per_alert_across_runs.csv`: one row per alert, each run's status, decision, attack type and technique, and the error category per kind
- `error_patterns.csv`: one row per alert and error kind where an error occurred, so every statement in the report can be traced to alert ids

The report is named `DAY6_THREE_RUN_REPORT.md` on purpose. `WEEK2_REPORT.md` is the Day 7 deliverable and is not created.

### How mean and spread are calculated
For each metric the three run values are listed, then: **mean** = arithmetic mean; **sd** = sample standard deviation with n-1 in the denominator; **min**, **max**; **range** = max - min.
Percent metrics show sd and range in percentage points. A metric that cannot be read from an evaluation is shown as n/a, left out of the statistics and listed in the report. With three runs the sd is a rough
estimate, which is why min and max are shown. Metrics covered: coverage, final parse-failure rate, first-try malformed rate, precision, recall, F1, specificity, FP reduction and attacks missed (under each of the three
Day 4 denominator policies: valid only, failures escalated, failures counted wrong), attack-type accuracy, MITRE accepted accuracy (valid verdicts and all attacks), model calls, tokens (total, prompt, output, thinking)
and latency (per alert and per call: mean, median, p95, max). The Day 5 run, if shown, is a reference column only and is not in the mean or spread; baseline_v3 was chosen after looking at that run, so it is not an
independent confirmation.

### Error-analysis procedure
Per alert and error kind (false positive, missed attack, attack-type error, MITRE error, no verdict), let k = runs in which the alert was wrong and m = runs in which it could be judged (a parse failure is a missing
answer, not a wrong one):
- k = m and m >= 2: **persistent** (wrong every time it could be judged)
- k = 1 and m >= 2: **one-off**
- 1 < k < m: **recurring** (wrong in some runs, not all)
- k = 0: never wrong; m < 2: insufficient, no pattern claimed

The report then gives, per kind, how many alerts fall in each category; per true class how many attack-type errors are persistent, recurring or one-off; the most common wrong answers among the persistent ones and whether the
wrong answer repeats; MITRE errors split by whether the attack type was right; parse failures by number of runs in which each alert failed; and the stochastic variation (alerts on which the runs disagree, and pairwise agreement),
kept separate from the persistent patterns. To dig in: open `error_patterns.csv`, filter `category = persistent` and a `kind`, and look at the per-run predictions; then `per_alert_across_runs.csv` for the full picture of one alert.

## 7. Integrity checks (all read-only)

```
python src/day6_replicates.py status
```
Expected: three replicates listed, `baseline_v3 hash unchanged since the first replicate: True`, `frozen access log unchanged ... True`, and `protected run dev_flash_lite_v1 unchanged: True` and
`protected run dev_flash_lite_v3_final unchanged: True` (the Day 3 and Day 5 run folders are hashed at the start of the first replicate and compared). Exit code 0 means all good, 1 means something changed.

Also: each `evaluate.py` run prints its own integrity lines (run files, protected Week 1 files, frozen access log); `day6_aggregate.py` prints `Inputs unchanged: True`; each replicate's `run_meta.json` has
`frozen_access_log_unchanged` and `week1_files_unchanged` true. Before committing anything, `git status` should show no change to `eval/`, `models/`, `reports/week1*`, `src/baseline_prompt.py`, `src/prompt_registry.py`,
`src/verdict_*.py`, and `eval/frozen_access.log`.

## 8. What is explicitly NOT part of Day 6
- No frozen-set access, no `SOC_FROZEN_UNLOCK` (the wrapper refuses if it is set), no change to Week 1 files.
- No edit to `baseline_v3`, the parser, the schema, the model or the settings; no tuning from these runs; no new prompt version. Persistent errors are findings for Week 3 design, not a reason to change the baseline.
- No Day 7 work: no `WEEK2_REPORT.md`, no `week2-baseline` tag, no baseline freeze.
- No agents, tools, memory, LangGraph, RAG or ChromaDB, no new dependency, no change to the Gemini and LangSmith setup (tracing stays optional and metadata-only).
- Nothing is committed. `runs/`, `diag.py` and `audit_day5_step1.py` stay untracked. After you have read the report, decide what to commit (suggested: the two `src/day6_*.py`, `tests/test_week2_day6.py`, this handoff and `reports/week2_day6/`).

## 9. Next step
Execute section 4, evaluate each replicate, run the aggregation, read `DAY6_THREE_RUN_REPORT.md`, and send it back before Day 7.
