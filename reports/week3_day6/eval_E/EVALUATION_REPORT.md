# Week 2 Day 4: evaluation of baseline run `day6_arm_E` on the DEV set

Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.

Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.

## 1. Population and run

| item | value |
|---|---|
| dev alerts evaluated | 300 (195 true attacks, 105 detector false positives) |
| valid verdicts | 300 |
| parse_failed (no valid verdict after retries) | 0 |
| model_error | 0 |
| not run | 0 |
| run_meta: run_name | day6_arm_E |
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
| first-try malformed | 0.0033 (1/300, 95% CI 0.001 to 0.019) | alerts that received at least one reply |
| first-try malformed, over all alerts | 0.0033 (1/300, 95% CI 0.001 to 0.019) | all alerts |
| retry needed | 0.0033 (1/300, 95% CI 0.001 to 0.019) | alerts that received at least one reply |
| recovered by a retry | 1.0000 (1/1, 95% CI 0.207 to 1.000) | alerts whose first reply was malformed |
| final parse failure | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 1.0000 (300/300, 95% CI 0.987 to 1.000) | all alerts |

Model calls: 301 in total, 1.003 per alert.

First-try error codes: {"extra_fields": 1}. Final error codes: {}. Finish reasons over all calls: {"STOP": 301}.

Alerts with no verdict, by true label: {}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 166 | 29 | 0 | 195 |
| detector false positives | 1 | 104 | 0 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 0 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 300 | 0.9940 (166/167, 95% CI 0.967 to 0.999) | 0.8513 (166/195, 95% CI 0.795 to 0.894) | 0.9171 | 0.9905 (104/105, 95% CI 0.948 to 0.998) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_escalated | 300 | 0.9940 (166/167, 95% CI 0.967 to 0.999) | 0.8513 (166/195, 95% CI 0.795 to 0.894) | 0.9171 | 0.9905 (104/105, 95% CI 0.948 to 0.998) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.9940 (166/167, 95% CI 0.967 to 0.999) | 0.8513 (166/195, 95% CI 0.795 to 0.894) | 0.9171 | 0.9905 (104/105, 95% CI 0.948 to 0.998) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 105 | 1 | 104 | 99.05% | 0.3500 | 0.0060 | 44.33% | 29 of 195 |
| failures_escalated | 105 | 1 | 104 | 99.05% | 0.3500 | 0.0060 | 44.33% | 29 of 195 |
| failures_wrong | 105 | 1 | 104 | 99.05% | 0.3500 | 0.0060 | 44.33% | 29 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.9905 (104/105, 95% CI 0.948 to 0.998)
- failures_escalated: benign dismissal rate 0.9905 (104/105, 95% CI 0.948 to 0.998)
- failures_wrong: benign dismissal rate 0.9905 (104/105, 95% CI 0.948 to 0.998)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3026 (59/195, 95% CI 0.242 to 0.370) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3554 (59/166, 95% CI 0.287 to 0.431) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3026 (59/195, 95% CI 0.242 to 0.370) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 1.0000 (195/195, 95% CI 0.981 to 1.000) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.6154 (120/195, 95% CI 0.545 to 0.681) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.7229 (120/166, 95% CI 0.650 to 0.785) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.6154 (120/195, 95% CI 0.545 to 0.681) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.1949 (38/195, 95% CI 0.145 to 0.256) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 1.0000 (195/195, 95% CI 0.981 to 1.000) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.9905 (104/105, 95% CI 0.948 to 0.998) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 105 | 0 | 0.9905 (104/105) | 0.95 to 1.00 | n/a | n/a |
| Bot | 18 | 18 | 0 | 0.5000 (9/18) | 0.29 to 0.71 | 0.0000 | 0.0000 |
| DDoS | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.9444 |
| DoS GoldenEye | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.1111 | 0.8889 |
| DoS Hulk | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.9444 |
| DoS Slowhttptest | 18 | 18 | 0 | 0.7222 (13/18) | 0.49 to 0.88 | 0.0000 | 0.7222 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| FTP-Patator | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 18 | 0 | 0.2778 (5/18) | 0.12 to 0.51 | 0.2222 | 0.2222 |
| SSH-Patator | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 17 | 0 | 0.8824 (15/17) | 0.66 to 0.97 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 739253 |
| output_tokens | 23943 |
| thinking_tokens | None |
| total_tokens | 763196 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 2544.0 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 1.92 | 1.17 | 6.56 | 0.94 | 10.92 |
| per alert excluding anomaly | 300 | 1.92 | 1.17 | 6.56 | 0.94 | 10.92 |
| per call all observations | 302 | 1.91 | 1.17 | 6.54 | 0.75 | 10.92 |
| per call excluding anomaly | 302 | 1.91 | 1.17 | 6.54 | 0.75 | 10.92 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 327.0 | DEV-0213 | DEV-0213 |
| 70.0 | DEV-0212 | DEV-0213 |
| 15.0 | DEV-0242 | DEV-0243 |
| 12.0 | DEV-0245 | DEV-0246 |
| 11.0 | DEV-0229 | DEV-0230 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.
