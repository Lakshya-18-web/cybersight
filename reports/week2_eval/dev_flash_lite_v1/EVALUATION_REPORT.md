# Week 2 Day 4: evaluation of baseline run `dev_flash_lite_v1` on the DEV set

Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.

Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.

## 1. Population and run

| item | value |
|---|---|
| dev alerts evaluated | 300 (195 true attacks, 105 detector false positives) |
| valid verdicts | 266 |
| parse_failed (no valid verdict after retries) | 34 |
| model_error | 0 |
| not run | 0 |
| run_meta: run_name | dev_flash_lite_v1 |
| run_meta: model | gemini-3.5-flash-lite |
| run_meta: provider | gemini |
| run_meta: prompt_version | baseline_v1 |
| run_meta: prompt_sha256 | 0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172 |
| run_meta: sessions | 1 |
| results.jsonl lines / alerts | 300 / 300 |

The detector's decision on every dev alert is "malicious" (every dev alert is a detector alert; checked against the accepted threshold). The dev set was sampled with 35.0% false positives, so the detector's precision on it is 0.6500 by construction. Its natural precision is 0.6993 on all validation alerts (threshold.json) and 0.7206 on the test split (test_metrics.json).

## 2. Output reliability

| metric | value | population |
|---|---|---|
| first-try malformed | 0.2200 (66/300, 95% CI 0.177 to 0.270) | alerts that received at least one reply |
| first-try malformed, over all alerts | 0.2200 (66/300, 95% CI 0.177 to 0.270) | all alerts |
| retry needed | 0.2200 (66/300, 95% CI 0.177 to 0.270) | alerts that received at least one reply |
| recovered by a retry | 0.4848 (32/66, 95% CI 0.368 to 0.603) | alerts whose first reply was malformed |
| final parse failure | 0.1133 (34/300, 95% CI 0.082 to 0.154) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 0.8867 (266/300, 95% CI 0.846 to 0.918) | all alerts |

Model calls: 412 in total, 1.373 per alert.

First-try error codes: {"extra_fields": 57, "invalid_json": 9}. Final error codes: {"extra_fields": 20, "invalid_json": 14}. Finish reasons over all calls: {"STOP": 412}.

Alerts with no verdict, by true label: {"BENIGN": 9, "Bot": 7, "DDoS": 1, "DoS GoldenEye": 1, "DoS Hulk": 1, "FTP-Patator": 2, "PortScan": 9, "SSH-Patator": 1, "Web Attack - Brute Force": 1, "Web Attack - XSS/SQLi": 2}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 165 | 5 | 25 | 195 |
| detector false positives | 27 | 69 | 9 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 34 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 266 | 0.8594 (165/192, 95% CI 0.803 to 0.902) | 0.9706 (165/170, 95% CI 0.933 to 0.987) | 0.9116 | 0.7188 (69/96, 95% CI 0.622 to 0.799) |
| detector, same alerts | 266 | 0.6391 (170/266, 95% CI 0.580 to 0.694) | 1.0000 (170/170, 95% CI 0.978 to 1.000) | 0.7798 | 0.0000 (0/96, 95% CI 0.000 to 0.038) |
| baseline, failures_escalated | 300 | 0.8407 (190/226, 95% CI 0.787 to 0.883) | 0.9744 (190/195, 95% CI 0.941 to 0.989) | 0.9026 | 0.6571 (69/105, 95% CI 0.562 to 0.741) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.8209 (165/201, 95% CI 0.762 to 0.868) | 0.8462 (165/195, 95% CI 0.789 to 0.890) | 0.8333 | 0.6571 (69/105, 95% CI 0.562 to 0.741) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 96 | 27 | 69 | 71.88% | 0.3609 | 0.1406 | 27.82% | 5 of 170 |
| failures_escalated | 105 | 36 | 69 | 65.71% | 0.3500 | 0.1593 | 24.67% | 5 of 195 |
| failures_wrong | 105 | 36 | 69 | 65.71% | 0.3500 | 0.1791 | 33.00% | 30 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.7188 (69/96, 95% CI 0.622 to 0.799)
- failures_escalated: benign dismissal rate 0.6571 (69/105, 95% CI 0.562 to 0.741)
- failures_wrong: benign dismissal rate 0.6571 (69/105, 95% CI 0.562 to 0.741)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3529 (60/170, 95% CI 0.285 to 0.427) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3636 (60/165, 95% CI 0.294 to 0.439) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3077 (60/195, 95% CI 0.247 to 0.376) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 0.8718 (170/195, 95% CI 0.818 to 0.912) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.4412 (75/170, 95% CI 0.369 to 0.516) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.4545 (75/165, 95% CI 0.380 to 0.531) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.3846 (75/195, 95% CI 0.319 to 0.455) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.1706 (29/170, 95% CI 0.121 to 0.234) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 0.8718 (170/195, 95% CI 0.818 to 0.912) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.7188 (69/96, 95% CI 0.622 to 0.799) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 96 | 9 | 0.7188 (69/96) | 0.62 to 0.80 | n/a | n/a |
| Bot | 18 | 11 | 7 | 0.6364 (7/11) | 0.35 to 0.85 | 0.0000 | 0.0000 |
| DDoS | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.9412 |
| DoS GoldenEye | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.1765 |
| DoS Hulk | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.2941 |
| DoS Slowhttptest | 18 | 18 | 0 | 0.9444 (17/18) | 0.74 to 0.99 | 0.3889 | 0.3333 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.6667 | 0.2222 |
| FTP-Patator | 18 | 16 | 2 | 1.0000 (16/16) | 0.81 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 9 | 9 | 1.0000 (9/9) | 0.70 to 1.00 | 1.0000 | 1.0000 |
| SSH-Patator | 17 | 16 | 1 | 1.0000 (16/16) | 0.81 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 16 | 1 | 1.0000 (16/16) | 0.81 to 1.00 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 15 | 2 | 1.0000 (15/15) | 0.80 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 427359 |
| output_tokens | 38712 |
| thinking_tokens | None |
| total_tokens | 466071 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 1553.6 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 1.58 | 1.12 | 3.56 | 0.89 | 8.44 |
| per alert excluding anomaly | 300 | 1.58 | 1.12 | 3.56 | 0.89 | 8.44 |
| per call all observations | 412 | 1.15 | 1.08 | 1.54 | 0.88 | 6.53 |
| per call excluding anomaly | 412 | 1.15 | 1.08 | 1.54 | 0.88 | 6.53 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 5886.0 | DEV-0226 | DEV-0226 |
| 11.0 | DEV-0008 | DEV-0009 |
| 7.0 | DEV-0009 | DEV-0010 |
| 7.0 | DEV-0016 | DEV-0016 |
| 7.0 | DEV-0019 | DEV-0020 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.

