# Week 2 Day 4: evaluation of baseline run `dev_flash_lite_v2` on the DEV set

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
| run_meta: run_name | dev_flash_lite_v2 |
| run_meta: model | gemini-3.5-flash-lite |
| run_meta: provider | gemini |
| run_meta: prompt_version | baseline_v2 |
| run_meta: prompt_sha256 | 2b9a14acb3e281db0d9e23ec636e6fa1761004f1592acf3cc0ca02fb4793aa46 |
| run_meta: sessions | 1 |
| results.jsonl lines / alerts | 300 / 300 |

The detector's decision on every dev alert is "malicious" (every dev alert is a detector alert; checked against the accepted threshold). The dev set was sampled with 35.0% false positives, so the detector's precision on it is 0.6500 by construction. Its natural precision is 0.6993 on all validation alerts (threshold.json) and 0.7206 on the test split (test_metrics.json).

## 2. Output reliability

| metric | value | population |
|---|---|---|
| first-try malformed | 0.0900 (27/300, 95% CI 0.063 to 0.128) | alerts that received at least one reply |
| first-try malformed, over all alerts | 0.0900 (27/300, 95% CI 0.063 to 0.128) | all alerts |
| retry needed | 0.0900 (27/300, 95% CI 0.063 to 0.128) | alerts that received at least one reply |
| recovered by a retry | 0.8519 (23/27, 95% CI 0.675 to 0.941) | alerts whose first reply was malformed |
| final parse failure | 0.0133 (4/300, 95% CI 0.005 to 0.034) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 0.9867 (296/300, 95% CI 0.966 to 0.995) | all alerts |

Model calls: 336 in total, 1.120 per alert.

First-try error codes: {"extra_fields": 24, "invalid_json": 3}. Final error codes: {"extra_fields": 4}. Finish reasons over all calls: {"STOP": 336}.

Alerts with no verdict, by true label: {"BENIGN": 1, "Bot": 1, "DoS GoldenEye": 1, "FTP-Patator": 1}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 186 | 6 | 3 | 195 |
| detector false positives | 31 | 73 | 1 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 4 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 296 | 0.8571 (186/217, 95% CI 0.804 to 0.897) | 0.9688 (186/192, 95% CI 0.934 to 0.986) | 0.9095 | 0.7019 (73/104, 95% CI 0.608 to 0.781) |
| detector, same alerts | 296 | 0.6486 (192/296, 95% CI 0.593 to 0.701) | 1.0000 (192/192, 95% CI 0.980 to 1.000) | 0.7869 | 0.0000 (0/104, 95% CI 0.000 to 0.036) |
| baseline, failures_escalated | 300 | 0.8552 (189/221, 95% CI 0.803 to 0.896) | 0.9692 (189/195, 95% CI 0.935 to 0.986) | 0.9087 | 0.6952 (73/105, 95% CI 0.602 to 0.775) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.8532 (186/218, 95% CI 0.800 to 0.894) | 0.9538 (186/195, 95% CI 0.915 to 0.976) | 0.9007 | 0.6952 (73/105, 95% CI 0.602 to 0.775) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 104 | 31 | 73 | 70.19% | 0.3514 | 0.1429 | 26.69% | 6 of 192 |
| failures_escalated | 105 | 32 | 73 | 69.52% | 0.3500 | 0.1448 | 26.33% | 6 of 195 |
| failures_wrong | 105 | 32 | 73 | 69.52% | 0.3500 | 0.1468 | 27.33% | 9 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.7019 (73/104, 95% CI 0.608 to 0.781)
- failures_escalated: benign dismissal rate 0.6952 (73/105, 95% CI 0.602 to 0.775)
- failures_wrong: benign dismissal rate 0.6952 (73/105, 95% CI 0.602 to 0.775)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3594 (69/192, 95% CI 0.295 to 0.429) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3710 (69/186, 95% CI 0.305 to 0.442) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3538 (69/195, 95% CI 0.290 to 0.423) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.5052 (97/192, 95% CI 0.435 to 0.575) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.5215 (97/186, 95% CI 0.450 to 0.592) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.4974 (97/195, 95% CI 0.428 to 0.567) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.2760 (53/192, 95% CI 0.218 to 0.343) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 0.9846 (192/195, 95% CI 0.956 to 0.995) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.7019 (73/104, 95% CI 0.608 to 0.781) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 104 | 1 | 0.7019 (73/104) | 0.61 to 0.78 | n/a | n/a |
| Bot | 18 | 17 | 1 | 0.7647 (13/17) | 0.53 to 0.90 | 0.0000 | 0.0000 |
| DDoS | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0556 | 0.9444 |
| DoS GoldenEye | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.2941 |
| DoS Hulk | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0556 | 0.6111 |
| DoS Slowhttptest | 18 | 18 | 0 | 0.9444 (17/18) | 0.74 to 0.99 | 0.1667 | 0.2778 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.6667 | 0.3889 |
| FTP-Patator | 18 | 17 | 1 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| SSH-Patator | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 17 | 0 | 0.9412 (16/17) | 0.73 to 0.99 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 414700 |
| output_tokens | 28355 |
| thinking_tokens | None |
| total_tokens | 443055 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 1476.8 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 3.54 | 2.00 | 12.54 | 1.11 | 26.89 |
| per alert excluding anomaly | 300 | 3.54 | 2.00 | 12.54 | 1.11 | 26.89 |
| per call all observations | 336 | 3.16 | 1.97 | 10.62 | 1.11 | 21.08 |
| per call excluding anomaly | 336 | 3.16 | 1.97 | 10.62 | 1.11 | 21.08 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 22.0 | DEV-0282 | DEV-0283 |
| 21.0 | DEV-0073 | DEV-0074 |
| 21.0 | DEV-0295 | DEV-0296 |
| 19.0 | DEV-0072 | DEV-0072 |
| 19.0 | DEV-0269 | DEV-0269 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.

