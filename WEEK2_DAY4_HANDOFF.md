# Week 2, Day 4 hand-off: evaluation harness

Blueprint Day 4: precision, recall, F1, false-positive reduction versus the raw detector, MITRE accuracy, malformed rate, cost, latency. Output: `evaluate.py` and a metrics report.

## Status: read this first

- **The evaluation has NOT been run on your real `dev_flash_lite_v1` run.** That run and the real dev labels exist only in your repo; they are not available to me. Everything below was tested on canned fixtures and on a synthetic 300-alert run written in your Day 3 file format (`results.jsonl`, `raw_responses.jsonl`, `run_meta.json`). So the package contains no real Day 4 numbers. Run the command below, then inspect `EVALUATION_REPORT.md`.
- Tests: 50 new Day 4 tests pass in my scratch project. With Day 1, 2 and 3 added, 172 tests pass (18 + 45 + 59 + 50).
- Not done, by design: no model call, no change to the Day 3 runner, prompt or parser, no prompt v2, no LangSmith/LangGraph, nothing from Day 5 onward. The frozen set is not reachable from the new code.

## Files (all new paths, nothing overwritten)

| path | role |
|---|---|
| `src/eval_metrics.py` | the metric calculations: pure functions on one table, no file access |
| `src/evaluate.py` | the harness: loads the run, the dev labels and answer key, joins them, writes the outputs |
| `tests/test_week2_day4.py` | 50 tests; the fixture is 20 alerts whose every expected number was worked out by hand |
| `week2_pricing.template.json` | empty price template for the cost estimate (no prices filled in) |
| `WEEK2_DAY4_HANDOFF.md` | this file |

## Commands

From the repo root, venv active, after `unzip week2-day4-files.zip`:

```
python -m unittest tests.test_week2_day4 -v
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4

python src/evaluate.py --run-name dev_flash_lite_v1
```

The last command needs no API key and makes no model call. It writes to `reports/week2_eval/dev_flash_lite_v1/` (refuses to overwrite; `--force` replaces it):

| file | content |
|---|---|
| `EVALUATION_REPORT.md` | the human-readable report, every ratio with numerator/denominator/population |
| `evaluation.json` | all metrics, run-file hashes, integrity results, the latency exclusion |
| `evaluation_metrics.csv` | the same metrics flattened: metric, value, numerator, denominator, 95% interval, population |
| `per_class.csv`, `attack_type_confusion.csv` | per-class table and true-class by predicted-class counts |
| `per_alert.csv` | one row per alert joining detector, labels and the baseline verdict (contains labels: for analysis only, never for a prompt) |

Exit codes: 0 done and integrity checks passed, 1 stopped on a problem with the inputs (the message says exactly which), 3 an integrity check failed (the run folder, a Week 1 file or the frozen access log changed while evaluating).

Cost, once you have the exact prices: copy `week2_pricing.template.json`, fill in every field (price per million input and output tokens, how thinking tokens are billed, the source and the date), and add `--pricing-file <file>`. Without it the report says cost is unavailable. No price is built into the code.

## What is measured, and on which denominator

**Positive class = malicious.** The detector's decision on every dev alert is "malicious", because every dev alert is a detector alert (the harness checks every score is at or above the accepted threshold, and stops if not).

**The 34 parse failures are never dropped.** Verdict metrics and the false-positive comparison are shown under three named views, side by side:

| view | population | an alert with no verdict is... |
|---|---|---|
| `valid_only` | alerts with a valid verdict (266 expected) | left out |
| `failures_escalated` | all 300 | kept as malicious, as a SOC queue would treat an untriaged alert |
| `failures_wrong` | all 300 | always wrong: an attack becomes a miss, a benign alert a false positive (worst case) |

I did not pick one of them as "the" result; which one is the right headline for the README is your decision. The report also has a table of what the baseline did with each kind of alert (kept, dismissed, no verdict), where every alert appears once.

- **Detector vs baseline.** Compared on the same alerts in each view. Reported: detector FP and baseline FP counts, FP removed, percentage reduction, FP share of raised alerts, alert-volume reduction, and the number of true attacks the baseline dismissed (the price of the reduction). The detector's FP rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the FP reduction equals the share of those the baseline dismissed; its Wilson interval is shown.
- **Detector precision.** On the dev set it is 195/300 = 0.65 *by construction*, since the dev set was sampled with 35% false positives. It is not the ~0.70 natural precision you mentioned; that figure applies to the full validation alerts (0.6993 from the Week 1 numbers) and is 0.7206 on the test split. The report prints both and states which is which.
- **Recall is detector-relative.** It is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so it is not end-to-end recall.
- **Attack type.** Exact class match, on attacks with a valid verdict, on attacks the baseline called malicious, and over all attacks with no-verdict counted wrong (lower bound), plus coverage.
- **MITRE accuracy.** Defined only for true attacks. A prediction is correct if its technique id is in the accepted ids for the true class in the answer key (`mitre_accepted_ids` in the dev labels): exact id match, no parent/child inference. A benign verdict gives NONE, which is never accepted for an attack, so it counts as wrong. Reported on attacks with a valid verdict, on attacks called malicious, and over all attacks (lower bound), with coverage. A stricter score against the single primary id is also given. For true benign alerts, "model said NONE" is reported separately and is not part of MITRE accuracy.
- **Reliability.** First-try malformed (66 expected), retry needed, recovered by a retry, final parse failure (34), model error, successful coverage (266), calls per alert, error codes on the first try and at the end, finish reasons (to see whether truncation, MAX_TOKENS, explains failures), and which true classes the failures fall in.
- **Cost.** Token totals as recorded (input, output, thinking, total) and whether they add up. Dollar cost only with a pricing file.
- **Latency.** Per alert (all calls of the alert added up, retries included) and per call: mean, median, p95, min, and max. The real Day 3 artifacts contain no recorded 5897.5-second latency; the sleep interruption appeared as a wall-clock gap, not as `latency_seconds`, so the real evaluation must run with **no latency exclusion**. `--exclude-latency-seconds <value>` remains available only for a documented value that actually occurs in exactly one recorded alert. The harness stops if it finds zero or more than one match. Raw files are never modified.
- **Intervals.** 95% Wilson intervals on the main rates. Classes have roughly 10 to 25 dev alerts each, so per-class rates are wide.

## Checks built in

- The Day 3 run folder is hashed before and after; the dev files, manifest, answer key, threshold, model and feature list are hashed before and after; the frozen access log line count is compared. Results are in the report and `evaluation.json`.
- Stops with a precise message (does not guess) when: results are missing for some dev alerts (`--allow-partial` to override), result ids are not dev ids, a label is not a Week 1 class, an attack has no accepted MITRE ids, the label file lacks a needed column, an alert is below the detector threshold.
- Repeated result lines for one alert: the last one wins, as in the Day 3 store.
- Source tests: `evaluate.py` and `eval_metrics.py` contain no frozen path, unlock value, model SDK or Gemini client; none of the Day 1 to 3 agent-side modules (prompt, client, runner, store, inputs, schemas, parser) imports the evaluation code or references labels, the answer key or the MITRE map.

## Things to check when you run it

1. The numbers the report must reproduce from your run: 300 alerts, 266 ok, 34 parse_failed, 0 model_error, 66 first-try malformed, 412 model calls, 466,071 total tokens. If any differ, stop and tell me.
2. `results.jsonl` field names were taken from the Day 3 hand-off and runner code (`status`, `verdict`, `attempts`, `malformed_first_try`, `attempt_log`, `error_code`, `model_calls`, token counts, `latency_seconds`, `finish_reasons`). If your actual run uses a different spelling, the harness stops or shows blanks; send me one line of the file.
3. The dev label columns used are `label`, `is_attack`, `mitre_technique_id`, `mitre_accepted_ids` (as built on Day 6).
4. The real run diagnostic found a largest recorded per-alert latency of 8.438 s and a separate 5886 s wall-clock gap during DEV-0226. The wall-clock sleep gap is not a recorded latency observation and must not be excluded from latency statistics.
5. `reports/week2_eval/` is a new output folder; commit it or not, your call. The `runs/` folder stays untracked as you decided.

## Exact next step (not started)

Week 2 Day 5: LangSmith tracing and cost tracking, then prompt v2 and v3 using the dev set only. I will not start it before you say so.
