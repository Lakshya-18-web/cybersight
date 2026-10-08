# Week 2 Day 4: evaluation of baseline run `dev_flash_lite_v3_d6_rep2` on the DEV set

Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.

Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.

## 1. Population and run

| item | value |
|---|---|
| dev alerts evaluated | 300 (195 true attacks, 105 detector false positives) |
| valid verdicts | 298 |
| parse_failed (no valid verdict after retries) | 2 |
| model_error | 0 |
| not run | 0 |
| run_meta: run_name | dev_flash_lite_v3_d6_rep2 |
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
| recovered by a retry | 0.6000 (3/5, 95% CI 0.231 to 0.882) | alerts whose first reply was malformed |
| final parse failure | 0.0067 (2/300, 95% CI 0.002 to 0.024) | all alerts |
| model error | 0.0000 (0/300, 95% CI 0.000 to 0.013) | all alerts |
| successful verdict coverage | 0.9933 (298/300, 95% CI 0.976 to 0.998) | all alerts |

Model calls: 308 in total, 1.027 per alert.

First-try error codes: {"extra_fields": 5}. Final error codes: {"invalid_json": 2}. Finish reasons over all calls: {"STOP": 308}.

Alerts with no verdict, by true label: {"BENIGN": 2}.

## 3. What the baseline did with each detector alert

| true kind | kept as malicious | dismissed as benign | no verdict | total |
|---|---|---|---|---|
| true attacks | 187 | 8 | 0 | 195 |
| detector false positives | 21 | 82 | 2 | 105 |

## 4. Verdict metrics (positive class = malicious)

Three denominators, because 2 alerts have no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

| view | alerts | precision | recall | F1 | specificity |
|---|---|---|---|---|---|
| baseline, valid_only | 298 | 0.8990 (187/208, 95% CI 0.851 to 0.933) | 0.9590 (187/195, 95% CI 0.921 to 0.979) | 0.9280 | 0.7961 (82/103, 95% CI 0.708 to 0.863) |
| detector, same alerts | 298 | 0.6544 (195/298, 95% CI 0.599 to 0.706) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7911 | 0.0000 (0/103, 95% CI 0.000 to 0.036) |
| baseline, failures_escalated | 300 | 0.8905 (187/210, 95% CI 0.841 to 0.926) | 0.9590 (187/195, 95% CI 0.921 to 0.979) | 0.9235 | 0.7810 (82/105, 95% CI 0.693 to 0.849) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |
| baseline, failures_wrong | 300 | 0.8905 (187/210, 95% CI 0.841 to 0.926) | 0.9590 (187/195, 95% CI 0.921 to 0.979) | 0.9235 | 0.7810 (82/105, 95% CI 0.693 to 0.849) |
| detector, same alerts | 300 | 0.6500 (195/300, 95% CI 0.594 to 0.702) | 1.0000 (195/195, 95% CI 0.981 to 1.000) | 0.7879 | 0.0000 (0/105, 95% CI 0.000 to 0.035) |

Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.

## 5. False positives against the detector

| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |
|---|---|---|---|---|---|---|---|---|
| valid_only | 103 | 21 | 82 | 79.61% | 0.3456 | 0.1010 | 30.20% | 8 of 195 |
| failures_escalated | 105 | 23 | 82 | 78.10% | 0.3500 | 0.1095 | 30.00% | 8 of 195 |
| failures_wrong | 105 | 23 | 82 | 78.10% | 0.3500 | 0.1095 | 30.00% | 8 of 195 |

The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.

- valid_only: benign dismissal rate 0.7961 (82/103, 95% CI 0.708 to 0.863)
- failures_escalated: benign dismissal rate 0.7810 (82/105, 95% CI 0.693 to 0.849)
- failures_wrong: benign dismissal rate 0.7810 (82/105, 95% CI 0.693 to 0.849)

## 6. Attack type (exact class match)

Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.

| measure | value | population |
|---|---|---|
| on_attacks_with_valid_verdict | 0.3692 (72/195, 95% CI 0.305 to 0.439) | true attacks with a valid verdict |
| on_attacks_flagged_malicious | 0.3850 (72/187, 95% CI 0.318 to 0.456) | true attacks the baseline called malicious |
| all_attacks_failures_wrong | 0.3692 (72/195, 95% CI 0.305 to 0.439) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| coverage | 1.0000 (195/195, 95% CI 0.981 to 1.000) | true attacks with a valid verdict |

## 7. MITRE technique accuracy

A predicted technique is correct if it is one of the accepted ids for the true class in the answer key (exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, which is never accepted for an attack, so it counts as wrong.

| measure | value | population |
|---|---|---|
| accepted_on_attacks_with_valid_verdict | 0.5744 (112/195, 95% CI 0.504 to 0.642) | true attacks with a valid verdict |
| accepted_on_attacks_flagged_malicious | 0.5989 (112/187, 95% CI 0.527 to 0.667) | true attacks the baseline called malicious |
| accepted_all_attacks_failures_wrong | 0.5744 (112/195, 95% CI 0.504 to 0.642) | all true attacks (no-verdict attacks count as wrong; lower bound) |
| primary_on_attacks_with_valid_verdict | 0.2974 (58/195, 95% CI 0.238 to 0.365) | true attacks with a valid verdict (strict: the single primary id) |
| coverage | 1.0000 (195/195, 95% CI 0.981 to 1.000) | true attacks with a valid verdict |
| benign_alerts_given_NONE | 0.7961 (82/103, 95% CI 0.708 to 0.863) | true benign alerts with a valid verdict (reported apart from MITRE accuracy) |

## 8. Per class

| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |
|---|---|---|---|---|---|---|---|
| BENIGN | 105 | 103 | 2 | 0.7961 (82/103) | 0.71 to 0.86 | n/a | n/a |
| Bot | 18 | 18 | 0 | 0.6667 (12/18) | 0.44 to 0.84 | 0.0000 | 0.0000 |
| DDoS | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.7222 |
| DoS GoldenEye | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0556 | 0.5556 |
| DoS Hulk | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 0.0000 | 0.5556 |
| DoS Slowhttptest | 18 | 18 | 0 | 0.9444 (17/18) | 0.74 to 0.99 | 0.0000 | 0.6667 |
| DoS slowloris | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 0.7778 |
| FTP-Patator | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| PortScan | 18 | 18 | 0 | 1.0000 (18/18) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| SSH-Patator | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 1.0000 | 1.0000 |
| Web Attack - Brute Force | 17 | 17 | 0 | 0.9412 (16/17) | 0.73 to 0.99 | 0.0000 | 0.0000 |
| Web Attack - XSS/SQLi | 17 | 17 | 0 | 1.0000 (17/17) | 0.82 to 1.00 | 0.0000 | 0.0000 |

Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.

## 9. Tokens and cost

| item | value |
|---|---|
| prompt_tokens | 644882 |
| output_tokens | 26078 |
| thinking_tokens | None |
| total_tokens | 670960 |
| alerts with token counts / without | 300 / 0 |
| mean total tokens per alert (alerts with counts) | 2236.5 |
| prompt + output + thinking equals total | True |

Cost: **unavailable.** No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.

## 10. Latency (seconds)

Per alert = all model calls of that alert added up (including retries). Per call = one model request.

No observation was excluded.

| scope | n | mean | median | p95 | min | max |
|---|---|---|---|---|---|---|
| per alert all observations | 300 | 3.65 | 1.78 | 12.83 | 1.14 | 17.59 |
| per alert excluding anomaly | 300 | 3.65 | 1.78 | 12.83 | 1.14 | 17.59 |
| per call all observations | 308 | 3.55 | 1.78 | 12.82 | 1.14 | 17.59 |
| per call excluding anomaly | 308 | 3.55 | 1.78 | 12.82 | 1.14 | 17.59 |

p95 uses linear interpolation between ranked values.

### Wall-clock gaps between consecutive model calls

These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.

| seconds | from alert | to alert |
|---:|---|---|
| 37.0 | DEV-0107 | DEV-0108 |
| 36.0 | DEV-0254 | DEV-0255 |
| 22.0 | DEV-0093 | DEV-0094 |
| 22.0 | DEV-0256 | DEV-0257 |
| 21.0 | DEV-0286 | DEV-0287 |

## 11. Integrity

- Day 3 run folder unchanged during evaluation: True (5 files hashed before and after).
- Week 1 protected files unchanged during evaluation: True (7 files).
- Frozen access log line count unchanged: True (1 lines).
- All dev alerts are detector alerts (score at or above the accepted threshold): checked.
- Labels and the answer key were used only in this evaluation; no model was called.

