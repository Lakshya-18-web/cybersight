# Week 2 report: single-LLM baseline, locked as baseline_v3

Generated 2026-10-08T14:19:23Z by `src/week2_report.py` from the project's own run and evaluation files. Every number below is read from those files; none was typed in. All results are on the 300-alert **dev** set. The frozen evaluation set was not used.

## 1. Summary

- **Selected baseline: `baseline_v3`**, prompt sha256 `9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7`. It is **locked** as of this report.
- Model: `gemini-3.5-flash-lite` (provider: gemini), settings {"max_output_tokens": 1024, "parse_retries": 2, "seed": 42, "temperature": 0.0}.
- Day 5 run `dev_flash_lite_v3_final`: 99.00% valid verdicts, F1 (valid verdicts only) 0.9277, false-positive reduction 79.61%, attack-type accuracy 36.60%, MITRE accepted accuracy 57.73%.
- Day 6, three fresh runs: F1 (valid verdicts only) mean 0.9268, range 0.0034; attack-type accuracy mean 36.31%, range 1.51 pp. Per-run values and the error analysis are in section 7.
- Frozen evaluation set: **closed**. Week 1 artifacts: **unchanged**. See section 8.
- Known limits: attack-type classification is weak, MITRE accepted accuracy is imperfect, Bot, DDoS and DoS Hulk are persistently confused, and parse failures remain possible (section 9).

## 2. What Week 2 built

| Day | Commit | Delivered |
|---|---|---|
| 1 | n/a | Verdict-input and label separation modules, model configuration for Gemini (no calls) |
| 2 | ee44800 | Five-field verdict schema (`is_malicious`, `attack_type`, `mitre_technique`, `severity`, `evidence`) and the strict parser with retries |
| 3 | 30ab792 | Baseline runner: one plain Gemini call per dev alert, raw responses and results stored per run |
| 4 | cbb690f | Evaluation harness: detector-relative metrics under three denominator policies, Wilson intervals, per-alert output, integrity checks |
| 5 | 21a560d | Prompt registry (`baseline_v1`, `baseline_v2`, `baseline_v3`), cost tracking, optional metadata-only LangSmith tracing |
| 6 | c78ec4a | Three fresh `baseline_v3` runs, mean and spread, cross-run error analysis |
| 7 | (this commit) | Baseline lock record, this report, the `week2-baseline` tag |

Commit ids are as reported by the project owner; this script does not read the git history.

## 3. The locked baseline

| Item | Value |
|---|---|
| Prompt version | `baseline_v3` |
| Prompt sha256 | `9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7` |
| `baseline_v1` sha256 (Day 3 reference) | `0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172` |
| `baseline_v2` sha256 | `2b9a14acb3e281db0d9e23ec636e6fa1761004f1592acf3cc0ca02fb4793aa46` |
| Provider and model | gemini, `gemini-3.5-flash-lite` |
| Settings | {"max_output_tokens": 1024, "parse_retries": 2, "seed": 42, "temperature": 0.0} |
| Alerts | 300 dev alerts (195 true attacks, 105 true benign) |
| Tools, memory, agents | none: one plain model call per alert |

Locked source files (sha256 of the text with line endings normalized), recorded in `reports/week2_baseline_lock.json`:

| File | sha256 |
|---|---|
| src/baseline_prompt.py | `dce06065b4e0a6d53bf2323507fa5d2cb88ddadcf1aced2b7a6f0f1fb49a15a3` |
| src/prompt_registry.py | `c8595e631b0f1c01f501e691726f4a66f6539896b1b6f825878346cc0e19c237` |
| src/verdict_schema.py | `9dd2390c3874ac22c49c145d18a6fa139e7d16d5f04df75a1405d18f83d5c59a` |
| src/verdict_parser.py | `26027ee0b3bcfd7921e243f170208bbb95507f85b666ab955b0ece617b0852f1` |
| src/gemini_client.py | `605bb2815398fecaaed478700631b6891d21911a55af4165d2a6c83ef22d5f9c` |

`python src/week2_report.py verify` recomputes these hashes, the reference run hashes, the frozen access log and the Week 1 files, and fails if anything differs from the lock record. The test `tests/test_week2_day7.py` runs the same check, so an edit to a locked file fails the test suite.

## 4. How the numbers are defined

- The detector flagged every alert in the dev set, so the model's job is to dismiss false alarms and classify real attacks. Recall and precision are therefore relative to the detector (the detector raised every attack here) and precision is a property of this sample, which holds 35.0% false alarms by construction.
- Three denominator policies from the Day 4 harness: **valid only** (alerts with a valid verdict), **failures escalated** (an alert with no verdict stays raised) and **failures counted wrong** (a failed alert is always an error). The valid-only figures are the primary ones; the other two show what parse failures cost.
- Attack-type accuracy is an exact match with the true class. MITRE accepted accuracy counts a technique as correct if it is one of the accepted ids in the evaluation mapping; that mapping is the evaluation contract, so a rejected technique is not necessarily wrong in an absolute sense.
- 95% Wilson intervals describe sampling uncertainty on the 300 alerts within one run. Differences between runs are shown separately (section 7).

## 5. Day 3 baseline (`baseline_v1`)

Run `dev_flash_lite_v1`, evaluated with the Day 4 harness. This is the reference every later change is compared with.

| Metric | baseline_v1 |
|---|---|
| Successful verdict coverage | 88.67% |
| Final parse-failure rate | 11.33% |
| First-try malformed rate | 22.00% |
| Precision [valid_only] | 85.94% |
| Recall [valid_only] | 97.06% |
| F1 [valid_only] | 0.9116 |
| Specificity (benign dismissed) [valid_only] | 71.88% |
| FP reduction [valid_only] | 71.88% |
| F1 [failures_escalated] | 0.9026 |
| FP reduction [failures_escalated] | 65.71% |
| F1 [failures_wrong] | 0.8333 |
| Attack-type accuracy (attacks with a valid verdict) | 35.29% |
| Attack-type accuracy (all attacks, no-verdict = wrong) | 30.77% |
| MITRE accepted accuracy (attacks with a valid verdict) | 44.12% |
| MITRE accepted accuracy (all attacks, no-verdict = wrong) | 38.46% |
| Model calls | 412 |
| Total tokens | 466,071 |
| Latency per alert, mean (s) | 1.579 |
| Latency per alert, max (s) | 8.438 |

## 6. Day 5: `baseline_v1` vs `baseline_v2` vs `baseline_v3`

One dev run of each (`dev_flash_lite_v1`, `dev_flash_lite_v2`, `dev_flash_lite_v3_final`) on the same 300 alerts. v2 adds an output-format contract to v1; v3 adds general attack-class and MITRE guidance on top. Differences are shown as computed, not as claims: a single run cannot show that a small difference is real (see the intervals below and section 7).

| Metric | v1 | v2 | v3 | v3 - v1 | v3 - v2 |
|---|---|---|---|---|---|
| Successful verdict coverage | 88.67% | 98.67% | 99.00% | +10.33 pp | +0.33 pp |
| Final parse-failure rate | 11.33% | 1.33% | 1.00% | -10.33 pp | -0.33 pp |
| First-try malformed rate | 22.00% | 9.00% | 1.67% | -20.33 pp | -7.33 pp |
| Precision [valid_only] | 85.94% | 85.71% | 89.86% | +3.92 pp | +4.14 pp |
| Recall [valid_only] | 97.06% | 96.88% | 95.88% | -1.18 pp | -1.00 pp |
| F1 [valid_only] | 0.9116 | 0.9095 | 0.9277 | +0.0161 | +0.0181 |
| Specificity (benign dismissed) [valid_only] | 71.88% | 70.19% | 79.61% | +7.74 pp | +9.42 pp |
| FP reduction [valid_only] | 71.88% | 70.19% | 79.61% | +7.74 pp | +9.42 pp |
| F1 [failures_escalated] | 0.9026 | 0.9087 | 0.9235 | +0.0208 | +0.0148 |
| FP reduction [failures_escalated] | 65.71% | 69.52% | 78.10% | +12.38 pp | +8.57 pp |
| F1 [failures_wrong] | 0.8333 | 0.9007 | 0.9208 | +0.0875 | +0.0201 |
| Attack-type accuracy (attacks with a valid verdict) | 35.29% | 35.94% | 36.60% | +1.30 pp | +0.66 pp |
| Attack-type accuracy (all attacks, no-verdict = wrong) | 30.77% | 35.38% | 36.41% | +5.64 pp | +1.03 pp |
| MITRE accepted accuracy (attacks with a valid verdict) | 44.12% | 50.52% | 57.73% | +13.61 pp | +7.21 pp |
| MITRE accepted accuracy (all attacks, no-verdict = wrong) | 38.46% | 49.74% | 57.44% | +18.97 pp | +7.69 pp |
| Model calls | 412 | 336 | 309 | -103 | -27 |
| Total tokens | 466,071 | 443,055 | 673,476 | +207,405 | +230,421 |
| Latency per alert, mean (s) | 1.579 | 3.542 | 2.150 | +0.570 | -1.392 |
| Latency per alert, max (s) | 8.438 | 26.891 | 31.016 | +22.578 | +4.125 |

95% Wilson intervals for the primary rates, one run each (an overlap check is a rough guide, not a significance test):

| Rate | v1 | v2 | v3 | v1 vs v3 |
|---|---|---|---|---|
| Precision (valid only) | 85.94% (80.3-90.2) | 85.71% (80.4-89.7) | 89.86% (85.0-93.3) | intervals overlap |
| Recall (valid only) | 97.06% (93.3-98.7) | 96.88% (93.4-98.6) | 95.88% (92.1-97.9) | intervals overlap |
| Specificity (valid only) | 71.88% (62.2-79.9) | 70.19% (60.8-78.1) | 79.61% (70.8-86.3) | intervals overlap |
| Attack-type accuracy (valid verdicts) | 35.29% (28.5-42.7) | 35.94% (29.5-42.9) | 36.60% (30.1-43.6) | intervals overlap |
| MITRE accepted accuracy (valid verdicts) | 44.12% (36.9-51.6) | 50.52% (43.5-57.5) | 57.73% (50.7-64.5) | intervals overlap |
| Final parse-failure rate | 11.33% (8.2-15.4) | 1.33% (0.5-3.4) | 1.00% (0.3-2.9) | intervals do not overlap |

`baseline_v3` was selected from these dev results. Run `dev_flash_lite_v3_final` is the run the choice was made on, so it is not an independent confirmation; that is why Day 6 repeated v3 in three fresh runs.

## 7. Day 6: three fresh runs of `baseline_v3`

Runs `dev_flash_lite_v3_d6_rep1`, `dev_flash_lite_v3_d6_rep2`, `dev_flash_lite_v3_d6_rep3`. Same prompt, model, settings, alert list and inputs; each run is its own folder and session. The settings were not varied, so the spread is how repeatable the service is for the same request. sd is the sample standard deviation (n-1); with three runs it is a rough estimate, so min and max are shown too.

| Metric | d6_rep1 | d6_rep2 | d6_rep3 | mean | sd | min | max | range | Day 5 run |
|---|---|---|---|---|---|---|---|---|---|
| Successful verdict coverage | 99.00% | 99.33% | 99.00% | 99.11% | 0.19 pp | 99.00% | 99.33% | 0.33 pp | 99.00% |
| Final parse-failure rate | 1.00% | 0.67% | 1.00% | 0.89% | 0.19 pp | 0.67% | 1.00% | 0.33 pp | 1.00% |
| First-try malformed rate | 1.67% | 1.67% | 1.67% | 1.67% | 0.00 pp | 1.67% | 1.67% | 0.00 pp | 1.67% |
| Precision [valid_only] | 89.86% | 89.90% | 89.32% | 89.69% | 0.32 pp | 89.32% | 89.90% | 0.58 pp | 89.86% |
| Recall [valid_only] | 95.88% | 95.90% | 95.83% | 95.87% | 0.03 pp | 95.83% | 95.90% | 0.06 pp | 95.88% |
| F1 [valid_only] | 0.9277 | 0.9280 | 0.9246 | 0.9268 | 0.0019 | 0.9246 | 0.9280 | 0.0034 | 0.9277 |
| Specificity (benign dismissed) [valid_only] | 79.61% | 79.61% | 79.05% | 79.42% | 0.33 pp | 79.05% | 79.61% | 0.56 pp | 79.61% |
| FP reduction [valid_only] | 79.61% | 79.61% | 79.05% | 79.42% | 0.33 pp | 79.05% | 79.61% | 0.56 pp | 79.61% |
| F1 [failures_escalated] | 0.9235 | 0.9235 | 0.9257 | 0.9242 | 0.0013 | 0.9235 | 0.9257 | 0.0023 | 0.9235 |
| F1 [failures_wrong] | 0.9208 | 0.9235 | 0.9177 | 0.9207 | 0.0029 | 0.9177 | 0.9235 | 0.0058 | 0.9208 |
| Attack-type accuracy (attacks with a valid verdict) | 36.60% | 36.92% | 35.42% | 36.31% | 0.79 pp | 35.42% | 36.92% | 1.51 pp | 36.60% |
| Attack-type accuracy (all attacks, no-verdict = wrong) | 36.41% | 36.92% | 34.87% | 36.07% | 1.07 pp | 34.87% | 36.92% | 2.05 pp | 36.41% |
| MITRE accepted accuracy (attacks with a valid verdict) | 57.22% | 57.44% | 53.12% | 55.93% | 2.43 pp | 53.12% | 57.44% | 4.31 pp | 57.73% |
| MITRE accepted accuracy (all attacks, no-verdict = wrong) | 56.92% | 57.44% | 52.31% | 55.56% | 2.82 pp | 52.31% | 57.44% | 5.13 pp | 57.44% |
| Model calls | 309 | 308 | 308 | 308.33 | 0.58 | 308 | 309 | 1 | 309 |
| Total tokens | 673,495 | 670,960 | 670,927 | 671,794 | 1,473 | 670,927 | 673,495 | 2,568 | 673,476 |
| Latency per alert, mean (s) | 3.352 | 3.650 | 1.906 | 2.969 | 0.933 | 1.906 | 3.650 | 1.744 | 2.150 |
| Latency per alert, p95 (s) | 15.625 | 12.830 | 2.964 | 10.473 | 6.651 | 2.964 | 15.625 | 12.661 | 4.577 |
| Latency per alert, max (s) | 66.125 | 17.594 | 34.562 | 39.427 | 24.629 | 17.594 | 66.125 | 48.531 | 31.016 |

Each run's counts: `d6_rep1`: 297 valid, 3 parse failed, 0 model errors, 309 model calls, 673,495 tokens; `d6_rep2`: 298 valid, 2 parse failed, 0 model errors, 308 model calls, 670,960 tokens; `d6_rep3`: 297 valid, 3 parse failed, 0 model errors, 308 model calls, 670,927 tokens.

### Key error-analysis findings

An alert is **persistent** if it was wrong in every run in which it could be judged, **one-off** if wrong in one run only, and **recurring** if wrong in some runs but not all. A run with no verdict is a missing answer, not a wrong one.

| Error kind | Alerts it applies to | Wrong in at least one run | Persistent | Recurring | One-off |
|---|---|---|---|---|---|
| False positive (benign called malicious) | 105 | 23 | 18 | 3 | 2 |
| Missed attack (attack called benign) | 195 | 8 | 8 | 0 | 0 |
| Attack-type error (true attacks) | 195 | 125 | 123 | 0 | 2 |
| MITRE error (true attacks) | 195 | 100 | 72 | 13 | 15 |
| No verdict (parse failure) | 300 | 6 | 0 | 2 | 4 |

- **Run-to-run variation versus repeated errors.** Among alerts with at least two valid verdicts (298), the runs disagreed on attack_type for 21, on mitre_technique for 48 and on the is_malicious decision for 5 alerts. Of the 125 alerts with an attack-type error in any run, 123 were persistent.
- **Persistent attack-type errors by true class** (persistent alerts of attacks in the class): Bot 18 of 18; DDoS 18 of 18; DoS Hulk 18 of 18; DoS Slowhttptest 18 of 18; Web Attack - Brute Force 17 of 17; Web Attack - XSS/SQLi 17 of 17; DoS GoldenEye 17 of 18.
- **Most common persistent confusions** (true class to predicted class, alerts): Web Attack - XSS/SQLi to DoS slowloris 17; DoS Hulk to DoS slowloris 17; Web Attack - Brute Force to DoS slowloris 16; DoS GoldenEye to DoS slowloris 15; DoS Slowhttptest to DoS slowloris 15; DDoS to DoS slowloris 10; DoS GoldenEye to DoS Slowhttptest 7; Bot to BENIGN 6; Bot to PortScan 6; DDoS to DoS Hulk 5; DoS Hulk to DoS Slowhttptest 4; Bot to Web Attack - Brute Force 4.
- When an attack-type error is persistent: 109 alerts had the same wrong type every run, 14 alerts had the different wrong types across runs.
- **Persistent MITRE errors:** 70 alerts: technique wrong and attack type wrong in at least one run, 2 alerts: technique wrong while attack type right in every run.
- **Parse failures:** 6 alerts ended without a verdict in at least one run; by number of runs in which they failed: 1 run(s): 4, 2 run(s): 2. Final error codes (run-alert pairs): {"extra_fields": 3, "invalid_json": 5}.
- The per-alert detail behind these counts is in `reports/week2_day6/error_patterns.csv` and `reports/week2_day6/per_alert_across_runs.csv`.

## 8. Closure statements and the checks behind them

- **The frozen evaluation set remains CLOSED.** It was not opened in Week 2. Evidence: the frozen access log has 1 lines now and the same count was recorded by every Day 4 evaluation and every run; the unlock variable is not set; no Week 2 module reads a frozen path. The frozen set is opened only through `eval_io.py` for the final evaluation.
- **Week 1 artifacts remain UNCHANGED.** The protected Week 1 files hash the same now as in every Day 4 evaluation of the runs above (the `week1-freeze` tag is the reference point).
- **`baseline_v3` is LOCKED after Day 7.** Its prompt hash, the baseline source files and the reference runs are recorded in `reports/week2_baseline_lock.json`. Any change to the baseline is a new, separately named and separately evaluated version, never an edit of `baseline_v3`.
- **Resumed replicate.** `dev_flash_lite_v3_d6_rep1` was interrupted and resumed (2 sessions in its `run_meta.json`; the project owner reports the interruption was an API failure). The Day 6 manifest recorded it before the resume finished (manifest status `needs_attention`), so that entry is kept unchanged as historical evidence. Its final integrity is verified from the `run_file_sha256` in its post-completion `evaluation.json`, which matches the run folder now.

| Check | Result | Detail |
|---|---|---|
| baseline_v3 is the selected baseline and its registry hash is the pinned hash | PASS | 9403e7ea1937ff0f |
| baseline_v1 registry hash is the pinned hash | PASS | 0208c856dc1063ef |
| the Day 5 baseline_v3 run used the pinned hash | PASS |  |
| the Day 3 baseline run used the pinned v1 hash | PASS |  |
| the baseline_v2 run used the registered baseline_v2 hash | PASS |  |
| all three Day 6 runs used the pinned baseline_v3 hash | PASS |  |
| the Day 6 summary records the pinned hash | PASS |  |
| baseline_v3 runs (Day 5 and Day 6) used one model | PASS | gemini-3.5-flash-lite |
| baseline_v3 runs used identical settings | PASS |  |
| baseline_v3 runs used the same alert list and inputs | PASS |  |
| every run is a complete dev run | PASS |  |
| every Day 4 evaluation passed its integrity checks (run, protected files, frozen log) | PASS |  |
| no evaluation was partial | PASS |  |
| no run recorded a changed frozen access log or Week 1 file | PASS |  |
| the frozen access log has the same number of lines now as in every evaluation (frozen set not opened) | PASS | lines now 1, in evaluations [1] |
| the frozen unlock variable is not set in this shell | PASS |  |
| the Week 1 files hash the same now as in every evaluation | PASS | 30 hash comparisons |
| the replicates match the run_file_sha256 recorded by their own post-completion Day 4 evaluation | PASS | 3 of 3 match |
| the Day 6 manifest holds the pinned hash and three replicate entries | PASS |  |
| the Day 3 and Day 5 run folders are unchanged since the Day 6 manifest was written | PASS |  |
| the replicates are unchanged since the Day 6 manifest recorded them | PASS | dev_flash_lite_v3_d6_rep1 entry predates its resume (manifest status needs_attention, 2 sessions), kept as historical |
| the Day 6 summary lists exactly the three runs given | PASS |  |
| the Day 6 summary confirms its inputs were unchanged | PASS |  |

## 9. Known limitations

- **Attack-type classification remains weak.** Exact attack-type accuracy on alerts with a valid verdict averaged 36.31% over the three Day 6 runs (range 1.51 pp), and the errors repeat: 123 of 125 alerts with an error were wrong in every run.
- **MITRE accepted accuracy remains imperfect.** It averaged 55.93% (range 4.31 pp). The evaluation accepts only the ids in its mapping, so the figure measures agreement with that mapping.
- **Persistent Bot, DDoS and DoS Hulk confusion.** Persistent attack-type errors: Bot 18 of 18; DDoS 18 of 18; DoS Hulk 18 of 18. Section 7 lists the confusions. The data do not show why; with flow-level inputs these classes may not be separable, which these runs cannot settle.
- **Parse failures remain possible.** The final parse-failure rate averaged 0.89% (range 0.33 pp). Alerts without a verdict are reported under all three policies and are never dropped.
- **One dev set, 300 alerts.** Class-level counts are small. Results say nothing about the frozen set and no frozen-set number exists yet. Recall is detector-relative, and precision reflects the dev set's false-alarm share.
- **Three runs with fixed settings** measure repeatability of the service, not robustness to prompt changes or to new data.
- **Selection on dev.** `baseline_v3` was chosen using dev results; the Day 6 fresh runs check repeatability, not generalization.
- **Cost** is not stated: no verified pricing file was used. Token counts are in section 7.

## 10. Reproduction

```
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 tests.test_week2_day7 -v
python src/evaluate.py --run-name <run>            # per run, Day 4 harness
python src/day6_aggregate.py                        # three-run mean, spread and error analysis
python src/week2_report.py verify                   # nothing in the baseline changed since the lock
```

## 11. Provenance

Inputs read to build this report (sha256 of the evaluation files; run files are in the lock record):

| Evaluation file | sha256 |
|---|---|
| reports/week2_eval/dev_flash_lite_v1/evaluation.json | `c061d5ab913b77701261a7bbf64b5935525aa22500fe338cf77db244898b02ff` |
| reports/week2_eval/dev_flash_lite_v2/evaluation.json | `de86b19ce43b565ed2422a69ac44b3ce38fb4a292d724be6a632480d5c8f0d04` |
| reports/week2_eval/dev_flash_lite_v3_final/evaluation.json | `a5092154cb8e4a95fa6461fe3572caac6c1283f04252888dbde31bd8e1a2215b` |
| reports/week2_eval/dev_flash_lite_v3_d6_rep1/evaluation.json | `f96cc1af7848f6b59e49e0b59d0320552be35bf8d0accbfc0a7ff2b30e47a257` |
| reports/week2_eval/dev_flash_lite_v3_d6_rep2/evaluation.json | `1c02e32e24eec46a2229198e57248491fb987e7a661ae06dc6cf4c3d9f0a1f99` |
| reports/week2_eval/dev_flash_lite_v3_d6_rep3/evaluation.json | `8eb66d16af9a9a94b5e0a2bdae05b48fbe26f19937ab9ac08c89eb4e39dca1f3` |

Day 6 summary: `reports/week2_day6/three_run_summary.json` (`f3a1e7e7267d2894091e46445ce647c999cb61a960a5f3f9c6e40fcb09c94100`).
