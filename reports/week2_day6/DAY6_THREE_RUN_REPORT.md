# Week 2, Day 6: three DEV runs of the locked baseline (baseline_v3)

Generated 2026-10-08T03:26:03Z by `src/day6_aggregate.py`. DEV set only. The frozen set was not used. Nothing was tuned from these runs: the prompt, parser and schema are the ones used for the first run.

## 1. What was run

- Prompt: `baseline_v3`, sha256 `9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7`
- Model: `gemini-3.5-flash-lite`; settings identical in every run: {"max_output_tokens": 1024, "parse_retries": 2, "seed": 42, "temperature": 0.0, "timeout_seconds": 60, "transport_retries": 4}
- Alerts: 300 DEV alerts (195 true attacks, 105 true benign), the same list in every run
- Runs: `dev_flash_lite_v3_d6_rep1`, `dev_flash_lite_v3_d6_rep2`, `dev_flash_lite_v3_d6_rep3`
- Every run was scored with the Day 4 evaluator and passed its integrity checks (run files, protected files and frozen access log unchanged).
- Reference column: `dev_flash_lite_v3_final` (the Day 5 run). It is shown for comparison only and is **not** in the mean or spread. baseline_v3 was chosen after looking at that run's dev results, so it is not an independent confirmation.

**What the spread means.** The settings are identical (temperature and seed are fixed), so the differences between runs show only how much the model service varies when asked the same thing again. They do not measure how sensitive the result is to the prompt, and they say nothing about sampling uncertainty from having only 300 alerts; the Wilson intervals in each run's evaluation report cover that. With 3 runs the standard deviation is a rough estimate, so the minimum and maximum are shown too.

## 2. Results per run, mean and spread

mean = arithmetic mean of the 3 runs; sd = sample standard deviation (n-1); range = max - min. Percent metrics: sd and range in percentage points.

### Reliability

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Successful verdict coverage | 99.00% | 99.33% | 99.00% | 99.11% | 0.19 pp | 99.00% | 99.33% | 0.33 pp | 99.00% |
| Final parse-failure rate | 1.00% | 0.67% | 1.00% | 0.89% | 0.19 pp | 0.67% | 1.00% | 0.33 pp | 1.00% |
| Final parse failures (alerts) | 3 | 2 | 3 | 2.67 | 0.58 | 2 | 3 | 1 | 3 |
| First-try malformed rate | 1.67% | 1.67% | 1.67% | 1.67% | 0.00 pp | 1.67% | 1.67% | 0.00 pp | 1.67% |
| Model errors (alerts) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### Detector-relative verdict quality, valid verdicts only (primary)

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Precision [valid_only] | 89.86% | 89.90% | 89.32% | 89.69% | 0.32 pp | 89.32% | 89.90% | 0.58 pp | 89.86% |
| Recall [valid_only] | 95.88% | 95.90% | 95.83% | 95.87% | 0.03 pp | 95.83% | 95.90% | 0.06 pp | 95.88% |
| F1 [valid_only] | 0.9277 | 0.9280 | 0.9246 | 0.9268 | 0.0019 | 0.9246 | 0.9280 | 0.0034 | 0.9277 |
| Specificity (benign dismissed) [valid_only] | 79.61% | 79.61% | 79.05% | 79.42% | 0.33 pp | 79.05% | 79.61% | 0.56 pp | 79.61% |
| FP reduction [valid_only] | 79.61% | 79.61% | 79.05% | 79.42% | 0.33 pp | 79.05% | 79.61% | 0.56 pp | 79.61% |
| Attacks missed by the LLM [valid_only] | 8 | 8 | 8 | 8 | 0 | 8 | 8 | 0 | 8 |

### Failures escalated (an alert with no verdict stays raised)

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Precision [failures_escalated] | 89.05% | 89.05% | 89.47% | 89.19% | 0.25 pp | 89.05% | 89.47% | 0.43 pp | 89.05% |
| Recall [failures_escalated] | 95.90% | 95.90% | 95.90% | 95.90% | 0.00 pp | 95.90% | 95.90% | 0.00 pp | 95.90% |
| F1 [failures_escalated] | 0.9235 | 0.9235 | 0.9257 | 0.9242 | 0.0013 | 0.9235 | 0.9257 | 0.0023 | 0.9235 |
| Specificity (benign dismissed) [failures_escalated] | 78.10% | 78.10% | 79.05% | 78.41% | 0.55 pp | 78.10% | 79.05% | 0.95 pp | 78.10% |
| FP reduction [failures_escalated] | 78.10% | 78.10% | 79.05% | 78.41% | 0.55 pp | 78.10% | 79.05% | 0.95 pp | 78.10% |
| Attacks missed by the LLM [failures_escalated] | 8 | 8 | 8 | 8 | 0 | 8 | 8 | 0 | 8 |

### Failures counted wrong (a failed alert is always an error)

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Precision [failures_wrong] | 89.00% | 89.05% | 89.32% | 89.12% | 0.17 pp | 89.00% | 89.32% | 0.33 pp | 89.00% |
| Recall [failures_wrong] | 95.38% | 95.90% | 94.36% | 95.21% | 0.78 pp | 94.36% | 95.90% | 1.54 pp | 95.38% |
| F1 [failures_wrong] | 0.9208 | 0.9235 | 0.9177 | 0.9207 | 0.0029 | 0.9177 | 0.9235 | 0.0058 | 0.9208 |
| Specificity (benign dismissed) [failures_wrong] | 78.10% | 78.10% | 79.05% | 78.41% | 0.55 pp | 78.10% | 79.05% | 0.95 pp | 78.10% |
| FP reduction [failures_wrong] | 78.10% | 78.10% | 79.05% | 78.41% | 0.55 pp | 78.10% | 79.05% | 0.95 pp | 78.10% |
| Attacks missed by the LLM [failures_wrong] | 9 | 8 | 11 | 9.33 | 1.53 | 8 | 11 | 3 | 9 |

### Attack type and MITRE

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Attack-type accuracy (attacks with a valid verdict) | 36.60% | 36.92% | 35.42% | 36.31% | 0.79 pp | 35.42% | 36.92% | 1.51 pp | 36.60% |
| Attack-type accuracy (all attacks, no-verdict = wrong) | 36.41% | 36.92% | 34.87% | 36.07% | 1.07 pp | 34.87% | 36.92% | 2.05 pp | 36.41% |
| MITRE accepted accuracy (attacks with a valid verdict) | 57.22% | 57.44% | 53.12% | 55.93% | 2.43 pp | 53.12% | 57.44% | 4.31 pp | 57.73% |
| MITRE accepted accuracy (all attacks, no-verdict = wrong) | 56.92% | 57.44% | 52.31% | 55.56% | 2.82 pp | 52.31% | 57.44% | 5.13 pp | 57.44% |

### Cost drivers

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Model calls | 309 | 308 | 308 | 308.33 | 0.58 | 308 | 309 | 1 | 309 |
| Model calls per alert | 1.0300 | 1.0267 | 1.0267 | 1.0278 | 0.0019 | 1.0267 | 1.0300 | 0.0033 | 1.0300 |
| Total tokens | 673,495 | 670,960 | 670,927 | 671,794 | 1,473 | 670,927 | 673,495 | 2,568 | 673,476 |
| Prompt tokens | 647,292 | 644,882 | 644,880 | 645,685 | 1,392 | 644,880 | 647,292 | 2,412 | 647,292 |
| Output tokens | 26,203 | 26,078 | 26,047 | 26,109 | 83 | 26,047 | 26,203 | 156 | 26,184 |
| Thinking tokens | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

### Latency (recorded call latencies; sleep gaps are not latency)

| Metric | dev_flash_lite_v3_d6_rep1 | dev_flash_lite_v3_d6_rep2 | dev_flash_lite_v3_d6_rep3 | mean | sd | min | max | range | reference |
|---|---|---|---|---|---|---|---|---|---|
| Latency per alert, mean (s) | 3.352 | 3.650 | 1.906 | 2.969 | 0.933 | 1.906 | 3.650 | 1.744 | 2.150 |
| Latency per alert, median (s) | 1.250 | 1.781 | 1.640 | 1.557 | 0.275 | 1.250 | 1.781 | 0.531 | 1.718 |
| Latency per alert, p95 (s) | 15.625 | 12.830 | 2.964 | 10.473 | 6.651 | 2.964 | 15.625 | 12.661 | 4.577 |
| Latency per alert, max (s) | 66.125 | 17.594 | 34.562 | 39.427 | 24.629 | 17.594 | 66.125 | 48.531 | 31.016 |
| Latency per call, mean (s) | 3.229 | 3.555 | 1.856 | 2.880 | 0.901 | 1.856 | 3.555 | 1.699 | 2.087 |
| Latency per call, max (s) | 40.359 | 17.594 | 34.562 | 30.838 | 11.830 | 17.594 | 40.359 | 22.765 | 31.016 |

**Metrics that could not be read from at least one evaluation.json (shown as n/a, left out of the statistics):** thinking_tokens. If a core metric is listed here, the evaluation.json layout differs from what this script expects; check the file before trusting the table.

Notes on reading the table: on this dev set the detector alerts are 35% false alarms by construction, so precision is a property of the sample, and recall is relative to the detector (the detector raised every attack here). Specificity is the share of benign alerts the model dismissed. Cost is not computed in this report; use `python src/cost_tracking.py --run-name <run> --pricing-file pricing.json` with your own verified prices.

## 3. Variation between the runs (stochastic)

Alerts where the runs disagree with each other, regardless of the truth. Among alerts with at least two valid verdicts (298):

| Disagreement | Alerts | Share of those alerts |
|---|---|---|
| is_malicious decision differs | 5 | 1.7% |
| attack_type differs | 21 | 7.0% |
| mitre_technique differs | 48 | 16.1% |
| any of the three differs | 52 | 17.4% |

Pairwise agreement between two runs (mean over run pairs, alerts valid in both): decision 98.9%, attack_type 95.3%, technique 89.2%. Alerts whose final status differs between runs (ok in one, failed in another): 6. Alerts with a malformed first reply in some runs but not all: 8.

## 4. Persistent, recurring and one-off errors

Definitions are in the module docstring: k = runs with the error, m = runs in which the alert could be judged. **Persistent** = wrong every time it could be judged (m >= 2). **One-off** = wrong in one run only. **Recurring** = wrong in some runs, not all. Insufficient = fewer than two judgeable runs, no pattern claimed.

| Error kind | Alerts it applies to | Persistent | Recurring | One-off | Never wrong | Insufficient | Wrong in at least one run |
|---|---|---|---|---|---|---|---|
| False positive (benign called malicious) | 105 | 18 | 3 | 2 | 80 | 2 | 23 |
| Missed attack (attack called benign) | 195 | 8 | 0 | 0 | 187 | 0 | 8 |
| Attack-type error (true attacks) | 195 | 123 | 0 | 2 | 70 | 0 | 125 |
| MITRE error (true attacks) | 195 | 72 | 13 | 15 | 95 | 0 | 100 |
| No verdict (parse failure or model error) | 300 | 0 | 2 | 4 | 294 | 0 | 6 |

### Parse failures across runs

Alerts that ended without a verdict in at least one run: 6. By number of runs in which they failed: 1 run(s): 4, 2 run(s): 2. Final error codes (run-alert pairs): {"extra_fields": 3, "invalid_json": 5}. Alerts by number of runs with a malformed first reply: {"0": 291, "1": 4, "2": 4, "3": 1}.

### Attack type, by true class

| True class | Attacks | Never wrong | Persistent | Recurring | One-off | Insufficient |
|---|---|---|---|---|---|---|
| DoS GoldenEye | 18 | 0 | 17 | 0 | 1 | 0 |
| Web Attack - Brute Force | 17 | 0 | 17 | 0 | 0 | 0 |
| DoS slowloris | 18 | 17 | 0 | 0 | 1 | 0 |
| PortScan | 18 | 18 | 0 | 0 | 0 | 0 |
| Bot | 18 | 0 | 18 | 0 | 0 | 0 |
| SSH-Patator | 17 | 17 | 0 | 0 | 0 | 0 |
| DoS Slowhttptest | 18 | 0 | 18 | 0 | 0 | 0 |
| Web Attack - XSS/SQLi | 17 | 0 | 17 | 0 | 0 | 0 |
| DDoS | 18 | 0 | 18 | 0 | 0 | 0 |
| FTP-Patator | 18 | 18 | 0 | 0 | 0 | 0 |
| DoS Hulk | 18 | 0 | 18 | 0 | 0 | 0 |

Most common wrong answers among persistent attack-type errors (true class -> predicted class: alerts):

| True class | Predicted class | Alerts |
|---|---|---|
| Web Attack - XSS/SQLi | DoS slowloris | 17 |
| DoS Hulk | DoS slowloris | 17 |
| Web Attack - Brute Force | DoS slowloris | 16 |
| DoS GoldenEye | DoS slowloris | 15 |
| DoS Slowhttptest | DoS slowloris | 15 |
| DDoS | DoS slowloris | 10 |
| DoS GoldenEye | DoS Slowhttptest | 7 |
| Bot | BENIGN | 6 |
| Bot | PortScan | 6 |
| DDoS | DoS Hulk | 5 |
| DoS Hulk | DoS Slowhttptest | 4 |
| Bot | Web Attack - Brute Force | 4 |
| DDoS | DoS Slowhttptest | 3 |
| Bot | DoS Hulk | 3 |
| DoS Slowhttptest | DoS Hulk | 2 |

When an attack-type error is persistent: 109 alerts had the same wrong type every run, 14 alerts had the different wrong types across runs.

### MITRE

Persistent MITRE errors: 70 alerts: technique wrong and attack type wrong in at least one run, 2 alerts: technique wrong while attack type right in every run. A predicted technique counts as correct only if it is one of the accepted ids in the evaluation mapping, which is the evaluation contract, so a rejected technique is not necessarily wrong in an absolute sense.

Most common persistent technique choices (true class, technique(s) chosen every run: alerts):

| True class | Technique(s) chosen | Alerts |
|---|---|---|
| Web Attack - XSS/SQLi | T1499 | 13 |
| Web Attack - Brute Force | T1499 | 11 |
| Bot | NONE | 6 |
| DoS GoldenEye | T1499.003 | 6 |
| DoS Hulk | T1499.003 | 5 |
| Bot | T1046 | 4 |
| DDoS | T1499.003 | 4 |
| Web Attack - Brute Force | T1499, T1499.003 | 4 |
| Bot | T1110 | 2 |
| Web Attack - XSS/SQLi | T1499, T1499.003 | 2 |
| DoS slowloris | T1499.003 | 2 |
| Web Attack - XSS/SQLi | T1499.003 | 2 |

The per-alert detail is in `per_alert_across_runs.csv` and `error_patterns.csv`, so any row in this report can be traced to alert ids.

## 5. Conclusions

- The F1 (valid verdicts only) averaged 0.9268 with a range of 0.0034 (0.9246 to 0.9280).
- The precision (valid verdicts only) averaged 89.69% with a range of 0.58 pp (89.32% to 89.90%).
- The recall (valid verdicts only) averaged 95.87% with a range of 0.06 pp (95.83% to 95.90%).
- The false-positive reduction (valid verdicts only) averaged 79.42% with a range of 0.56 pp (79.05% to 79.61%).
- The attack-type accuracy averaged 36.31% with a range of 1.51 pp (35.42% to 36.92%).
- The MITRE accepted accuracy averaged 55.93% with a range of 4.31 pp (53.12% to 57.44%).
- The final parse-failure rate averaged 0.89% with a range of 0.33 pp (0.67% to 1.00%).
- Of the 125 alerts with an attack-type error in at least one run, 123 (98.4%) were persistent, 0 recurring and 2 one-off.
- Of the 100 alerts with a MITRE error in at least one run, 72 (72.0%) were persistent, 13 recurring and 15 one-off.
- Of the 23 alerts with a false positive in at least one run, 18 (78.3%) were persistent, 3 recurring and 2 one-off.
- Of the 8 alerts with a missed attack in at least one run, 8 (100.0%) were persistent, 0 recurring and 0 one-off.
- 6 alerts ended without a verdict in at least one run (0 in every run, 4 in one run only); parse failures are mostly intermittent: different alerts fail in different runs.
- The runs disagreed on attack_type for 21 of 298 alerts with at least two valid verdicts, and on the is_malicious decision for 5; 123 alerts had an attack-type error in every run in which they could be judged.
- Persistent attack-type errors are concentrated in: Bot (18 of 18), DDoS (18 of 18), DoS Hulk (18 of 18).
- These patterns are descriptive. They are the input for Week 3 design decisions and are not a reason to edit baseline_v3 on Day 6.

## 6. Limits

- Three runs with identical settings measure repeatability of the service, not robustness to prompt changes or to new data.
- The dev set has 300 alerts; per-class counts are small, so class-level patterns are indicative.
- Nothing in this report was used to change the prompt, parser or schema. Any change would be a new, separately evaluated version.
- No frozen-set number is in this report, and none should be inferred from it.
- Labels and the MITRE accepted ids reached this report only through the Day 4 evaluator outputs; they were never in a prompt or a trace.
