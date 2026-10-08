# Week 2 Day 4: evaluation of baseline run `dev_flash_lite_v3_d6_rep3` on the DEV set

Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.

Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.

## 1. Population and run

| item | value |
|---|---|
| dev alerts evaluated | 300 (195 true attacks, 105 detector false positives) |
| valid verdicts | 297 |
| parse_failed (no valid verdict after retries) | 3 |
| model_error | 0 |
| not run | 0 |
| run_meta: run_name | dev_flash_lite_v3_d6_rep3 |
| run_meta: model | gemini-3.5-flash-lite |
| run_meta: provider | gemini |
| run_meta: prompt_version | baseline_v3 |
| run_meta: prompt_sha256 | 9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7 |
| run_meta: sessions | 1 |
| results.jsonl lines / alerts | 300 / 300 |

The detector's decision on every dev alert is "malicious" (every dev alert is a detector alert; checked against the accepted threshold). The dev set was sampled with 35.0% false positives, so the detector's precision on it is 0.6500 by construction. Its natural precision is 0.6993 on all validation alerts (threshold.json) and 0.7206 on the test split (test_metrics.json).

## 2. Output reliability

| metric | value | population |
|---|---|---|
| first-try malformed | 0.0167 (5/300, 95% CI 0.007 to 0.038) | alerts that received at least one reply |
| first-try malformed, over all alerts | 0.0167 (5/300, 95% CI 0.007 to 0.038) | all alerts |
| retry needed | 0.0167 (5/300, 95% CI 0.007 to 0.038) | alerts that received at least one reply |
| recovered by a retry | 0.4000 (2/5, 95% CI 0.118 to 0.769) | alerts whose first reply was malformed |
| final parse failure | 0.0100 (3/300, 95% CI 0.003 to 0.029) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 0.9900 (297/300, 95% CI 0.971 to 0.997) | all alerts |

Model calls: 308 in total, 1.027 per alert.

First-try error codes: {"extra_fields": 5}. Final error codes: {"extra_fields": 2, "invalid_json": 1}. Finish reasons over all calls: {"STOP": 308}.

Alerts with no verdict, by true label: {"FTP-Patator": 1, "PortScan": 2}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 184 | 8 | 3 | 195 |
| detector false positives | 22 | 83 | 0 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 3 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 297 | 0.8932 (184/206, 95% CI 0.844 to 0.928) | 0.9583 (184/192, 95% CI 0.920 to 0.979) | 0.9246 | 0.7905 (83/105, 95% CI 0.703 to 0.857) |
| detector, same alerts | 297 | 0.6465 (192/297, 95% CI 0.591 to 0.699) | 1.0000 (192/192, 95% CI 0.980 to 1.000) | 0.7853 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_escalated | 300 | 0.8947 (187/209, 95% CI 0.846 to 0.929) | 0.9590 (187/195, 95% CI 0.921 to 0.979) | 0.9257 | 0.7905 (83/105, 95% CI 0.703 to 0.857) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.8932 (184/206, 95% CI 0.844 to 0.928) | 0.9436 (184/195, 95% CI 0.902 to 0.968) | 0.9177 | 0.7905 (83/105, 95% CI 0.703 to 0.857) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 105 | 22 | 83 | 79.05% | 0.3535 | 0.1068 | 30.64% | 8 of 192 |
| failures_escalated | 105 | 22 | 83 | 79.05% | 0.3500 | 0.1053 | 30.33% | 8 of 195 |
| failures_wrong | 105 | 22 | 83 | 79.05% | 0.3500 | 0.1068 | 31.33% | 11 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.7905 (83/105, 95% CI 0.703 to 0.857)
- failures_escalated: benign dismissal rate 0.7905 (83/105, 95% CI 0.703 to 0.857)
- failures_wrong: benign dismissal rate 0.7905 (83/105, 95% CI 0.703 to 0.857)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3542 (68/192, 95% CI 0.290 to 0.424) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3696 (68/184, 95% CI 0.303 to 0.441) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3487 (68/195, 95% CI 0.285 to 0.418) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.5312 (102/192, 95% CI 0.461 to 0.601) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.5543 (102/184, 95% CI 0.482 to 0.624) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.5231 (102/195, 95% CI 0.453 to 0.592) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.2812 (54/192, 95% CI 0.222 to 0.349) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.7905 (83/105, 95% CI 0.703 to 0.857) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 105 | 0 | 0.7905 (83/105) | 0.70 to 0.86 | n/a | n/a |
| Bot | 18 | 18 | 0 | 0.6667 (12/18) | 0.44 to 0.84 | 0.0000 | 0.0000 |
| DDoS | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.6667 |
| DoS GoldenEye | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0556 | 0.5000 |
| DoS Hulk | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.5000 |
| DoS Slowhttptest | 18 | 18 | 0 | 0.9444 (17/18) | 0.74 to 0.99 | 0.0000 | 0.6111 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.9444 | 0.6111 |
| FTP-Patator | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 16 | 2 | 1.0000 (16/16) | 0.81 to 1.00 | 1.0000 | 1.0000 |
| SSH-Patator | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 17 | 0 | 0.9412 (16/17) | 0.73 to 0.99 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 644880 |
| output_tokens | 26047 |
| thinking_tokens | None |
| total_tokens | 670927 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 2236.4 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 1.91 | 1.64 | 2.96 | 1.12 | 34.56 |
| per alert excluding anomaly | 300 | 1.91 | 1.64 | 2.96 | 1.12 | 34.56 |
| per call all observations | 308 | 1.86 | 1.62 | 2.59 | 1.12 | 34.56 |
| per call excluding anomaly | 308 | 1.86 | 1.62 | 2.59 | 1.12 | 34.56 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 39.0 | DEV-0183 | DEV-0184 |
| 12.0 | DEV-0184 | DEV-0185 |
| 11.0 | DEV-0055 | DEV-0056 |
| 9.0 | DEV-0009 | DEV-0009 |
| 9.0 | DEV-0066 | DEV-0067 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.

