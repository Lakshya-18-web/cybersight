# Week 2 Day 4: evaluation of baseline run `day6_arm_B` on the DEV set

Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.

Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.

## 1. Population and run

| item | value |
|---|---|
| dev alerts evaluated | 300 (195 true attacks, 105 detector false positives) |
| valid verdicts | 296 |
| parse_failed (no valid verdict after retries) | 4 |
| model_error | 0 |
| not run | 0 |
| run_meta: run_name | day6_arm_B |
| run_meta: model | gemini-3.5-flash-lite |
| run_meta: provider | gemini |
| run_meta: prompt_version | agent_v1 |
| run_meta: prompt_sha256 | 8df5e3fee15280d6b409e2a1fd1d01a505cfbe449421d9dafa1f8a30ee99f4c7 |
| run_meta: sessions | 2 |
| results.jsonl lines / alerts | 301 / 300 |

The detector's decision on every dev alert is "malicious" (every dev alert is a detector alert; checked against the accepted threshold). The dev set was sampled with 35.0% false positives, so the detector's precision on it is 0.6500 by construction. Its natural precision is 0.6993 on all validation alerts (threshold.json) and 0.7206 on the test split (test_metrics.json).

## 2. Output reliability

| metric | value | population |
|---|---|---|
| first-try malformed | 0.0367 (11/300, 95% CI 0.021 to 0.064) | alerts that received at least one reply |
| first-try malformed, over all alerts | 0.0367 (11/300, 95% CI 0.021 to 0.064) | all alerts |
| retry needed | 0.0367 (11/300, 95% CI 0.021 to 0.064) | alerts that received at least one reply |
| recovered by a retry | 0.6364 (7/11, 95% CI 0.354 to 0.848) | alerts whose first reply was malformed |
| final parse failure | 0.0133 (4/300, 95% CI 0.005 to 0.034) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 0.9867 (296/300, 95% CI 0.966 to 0.995) | all alerts |

Model calls: 317 in total, 1.057 per alert.

First-try error codes: {"extra_fields": 6, "invalid_field": 1, "invalid_json": 4}. Final error codes: {"extra_fields": 4}. Finish reasons over all calls: {"STOP": 317}.

Alerts with no verdict, by true label: {"BENIGN": 1, "Bot": 1, "FTP-Patator": 1, "PortScan": 1}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 185 | 7 | 3 | 195 |
| detector false positives | 2 | 102 | 1 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 4 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 296 | 0.9893 (185/187, 95% CI 0.962 to 0.997) | 0.9635 (185/192, 95% CI 0.927 to 0.982) | 0.9763 | 0.9808 (102/104, 95% CI 0.933 to 0.995) |
| detector, same alerts | 296 | 0.6486 (192/296, 95% CI 0.593 to 0.701) | 1.0000 (192/192, 95% CI 0.980 to 1.000) | 0.7869 | 0.0000 (0/104, 95% CI 0.000 to 0.036) |
| baseline, failures_escalated | 300 | 0.9843 (188/191, 95% CI 0.955 to 0.995) | 0.9641 (188/195, 95% CI 0.928 to 0.983) | 0.9741 | 0.9714 (102/105, 95% CI 0.919 to 0.990) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.9840 (185/188, 95% CI 0.954 to 0.995) | 0.9487 (185/195, 95% CI 0.908 to 0.972) | 0.9661 | 0.9714 (102/105, 95% CI 0.919 to 0.990) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 104 | 2 | 102 | 98.08% | 0.3514 | 0.0107 | 36.82% | 7 of 192 |
| failures_escalated | 105 | 3 | 102 | 97.14% | 0.3500 | 0.0157 | 36.33% | 7 of 195 |
| failures_wrong | 105 | 3 | 102 | 97.14% | 0.3500 | 0.0160 | 37.33% | 10 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.9808 (102/104, 95% CI 0.933 to 0.995)
- failures_escalated: benign dismissal rate 0.9714 (102/105, 95% CI 0.919 to 0.990)
- failures_wrong: benign dismissal rate 0.9714 (102/105, 95% CI 0.919 to 0.990)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3698 (71/192, 95% CI 0.305 to 0.440) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3838 (71/185, 95% CI 0.317 to 0.456) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3641 (71/195, 95% CI 0.300 to 0.434) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.5521 (106/192, 95% CI 0.481 to 0.621) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.5730 (106/185, 95% CI 0.501 to 0.642) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.5436 (106/195, 95% CI 0.474 to 0.612) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.2396 (46/192, 95% CI 0.185 to 0.305) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.9808 (102/104, 95% CI 0.933 to 0.995) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 104 | 1 | 0.9808 (102/104) | 0.93 to 0.99 | n/a | n/a |
| Bot | 18 | 17 | 1 | 0.5882 (10/17) | 0.36 to 0.78 | 0.0000 | 0.0000 |
| DDoS | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.8333 |
| DoS GoldenEye | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.2222 | 0.8333 |
| DoS Hulk | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.2778 |
| DoS Slowhttptest | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.7222 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.8889 | 0.3889 |
| FTP-Patator | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| SSH-Patator | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 927501 |
| output_tokens | 26288 |
| thinking_tokens | None |
| total_tokens | 953789 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 3179.3 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 1.81 | 1.56 | 2.83 | 1.02 | 18.66 |
| per alert excluding anomaly | 300 | 1.81 | 1.56 | 2.83 | 1.02 | 18.66 |
| per call all observations | 318 | 1.71 | 1.54 | 2.36 | 0.78 | 18.66 |
| per call excluding anomaly | 318 | 1.71 | 1.54 | 2.36 | 0.78 | 18.66 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 738.0 | DEV-0163 | DEV-0163 |
| 68.0 | DEV-0162 | DEV-0163 |
| 24.0 | DEV-0245 | DEV-0246 |
| 19.0 | DEV-0203 | DEV-0204 |
| 13.0 | DEV-0214 | DEV-0215 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.
