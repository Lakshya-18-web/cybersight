# Threshold report

Day 5: threshold chosen on validation only, then alert files for validation and test.
Target: validation recall of at least 0.95 over all attack classes pooled.

## Model checks

- PASS: feature_list.json matches the features the saved model was trained on (53 features)
- Model uses Destination Port: False. Trees used: 346.
- PASS: scores from the loaded model reproduce the saved validation PR-AUC (recomputed 0.999592, saved 0.999592)

## Threshold selection (validation only)

Validation rows: 478687, attack flows: 80748
Rule: highest score threshold whose validation recall is at least 0.95
Alerts are flows with detector score >= threshold.

**Chosen threshold: 0.9775605201721191**
- PASS: validation recall at the chosen threshold is at least 0.95 (recall 0.9501)

## Validation metrics at the chosen threshold

| metric | chosen threshold | provisional 0.5 |
|---|---|---|
| threshold | 0.977561 | 0.500000 |
| recall | 0.9501 | 0.9944 |
| precision | 1.0000 | 0.9971 |
| F1 | 0.9744 | 0.9957 |
| false positive rate | 0.00001 | 0.00059 |
| alerts | 76720 | 80526 |
| true positives | 76718 | 80292 |
| false positives | 2 | 234 |
| missed attacks (false negatives) | 4030 | 456 |
| false positive share of alerts | 0.0000 | 0.0029 |

## Per-class rate on validation

Attack classes show recall. BENIGN shows specificity (share left unflagged).

| class | validation rows | alerts | rate at chosen threshold | rate at 0.5 |
|---|---|---|---|---|
| BENIGN | 397939 | 2 | 1.0000 | 0.9994 |
| Bot | 370 | 2 | 0.0054 | 0.7027 |
| DDoS | 24322 | 23490 | 0.9658 | 0.9988 |
| DoS GoldenEye | 1954 | 1250 | 0.6397 | 0.9611 |
| DoS Hulk | 32816 | 32315 | 0.9847 | 0.9944 |
| DoS Slowhttptest | 993 | 117 | 0.1178 | 0.9537 |
| DoS slowloris | 1023 | 686 | 0.6706 | 1.0000 |
| FTP-Patator | 1127 | 1089 | 0.9663 | 1.0000 |
| PortScan | 17125 | 16854 | 0.9842 | 1.0000 |
| SSH-Patator | 612 | 596 | 0.9739 | 0.9967 |
| Web Attack - Brute Force | 279 | 204 | 0.7312 | 0.9713 |
| Web Attack - XSS/SQLi | 127 | 115 | 0.9055 | 0.9764 |

Worst attack class at the chosen threshold: Bot with recall 0.0054.
Attack classes under 0.95 recall: Bot, DoS GoldenEye, DoS Slowhttptest, DoS slowloris, Web Attack - Brute Force, Web Attack - XSS/SQLi. The rule only fixes pooled recall, so a small class can sit well below it.

## Sensitivity: other thresholds on validation

| threshold | recall | precision | alerts | false positives | FP share | worst attack class | its recall |
|---|---|---|---|---|---|---|---|
| 0.050000 | 0.9982 | 0.9566 | 84266 | 3661 | 0.0434 | Bot | 0.7243 |
| 0.100000 | 0.9978 | 0.9744 | 82683 | 2114 | 0.0256 | Bot | 0.7135 |
| 0.200000 | 0.9972 | 0.9911 | 81238 | 719 | 0.0089 | Bot | 0.7054 |
| 0.300000 | 0.9965 | 0.9947 | 80895 | 429 | 0.0053 | Bot | 0.7027 |
| 0.500000 | 0.9944 | 0.9971 | 80526 | 234 | 0.0029 | Bot | 0.7027 |
| 0.700000 | 0.9921 | 0.9981 | 80263 | 149 | 0.0019 | Bot | 0.6703 |
| 0.900000 | 0.9807 | 0.9991 | 79267 | 74 | 0.0009 | Bot | 0.3514 |
| 0.950000 | 0.9711 | 0.9995 | 78454 | 42 | 0.0005 | Bot | 0.3243 |
| 0.977561 (chosen) | 0.9501 | 1.0000 | 76720 | 2 | 0.0000 | Bot | 0.0054 |
| 0.990000 | 0.8861 | 1.0000 | 71549 | 2 | 0.0000 | Bot | 0.0000 |
| 0.999000 | 0.5476 | 1.0000 | 44218 | 0 | 0.0000 | Bot | 0.0000 |

## False-positive share check

Target range for the evaluation sets: 0.3 to 0.5 of alerts being false positives.
False positive share of validation alerts at the chosen threshold: 0.0000 -> BELOW

Highest threshold that keeps recall at or above 0.95 and reaches FP share 0.3: 0.004594 (recall 1.0000, precision 0.6993, alerts 115466, false positives 34721, FP share 0.3007, worst class Bot 0.9946).
To use it: python src/make_alerts.py --threshold 0.00459436746314168

A low natural share is expected for a strong detector. The agent needs enough false positives to be tested on, so Day 6 either samples false positives at a higher rate or uses a lower threshold. This is a decision for you, not the script.

## Feasibility for the Day 6 evaluation sets (preview, not built today)

- Dev set from validation alerts (cap 25 per attack class): about 252 attack alerts. For FP share 0.3 it needs at least 108 false positives. Validation has 2 at this threshold: NOT enough.
- Frozen set from test alerts (cap 200 per attack class, if every class has that many): up to 2200 attack alerts. For FP share 0.3 it needs at least 943 false positives. Test has a similar size to validation, so compare with the 2 false positives validation has. Test metrics are not computed today.

## Alert files

- PASS: validation alerts equal true positives plus false positives (76720)
- PASS: validation: alert count equals the number of rows at or above the threshold (76720 vs 76720)
- PASS: validation: alert ids are unique
- PASS: validation: alert file and label file have the same ids in the same order
- PASS: validation: alert file has no label, source file or row number column ([])
- PASS: validation: every detector score is at or above the threshold (lowest score 0.977561)
- PASS: validation: no missing values in the alert file ([])
- PASS: validation label file agrees with the confusion matrix (TP 76718, FP 2)
- PASS: test: alert count equals the number of rows at or above the threshold (62726 vs 62726)
- PASS: test: alert ids are unique
- PASS: test: alert file and label file have the same ids in the same order
- PASS: test: alert file has no label, source file or row number column ([])
- PASS: test: every detector score is at or above the threshold (lowest score 0.977561)
- PASS: test: no missing values in the alert file ([])

| file | rows | content hash (sha256, first 16) |
|---|---|---|
| alerts_val.parquet | 76720 | 5da3f351cdf7760b |
| alerts_val_labels.parquet | 76720 | b9333044b847d0d9 |
| alerts_test.parquet | 62726 | 389cf9022d61e072 |
| alerts_test_labels.parquet | 62726 | 52ecb2ff6efcb077 |

Test set: 478692 rows scored, 62726 alerts. No test metrics were computed or printed. The test label file exists for the Day 7 run and for building the frozen set on Day 6.

Alert columns: alert_id, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Flow Bytes/s, Flow Packets/s, Fwd Packet Length Mean, Bwd Packet Length Mean, Flow IAT Mean, SYN Flag Count, ACK Flag Count
The alert files contain no label, source file name or row number. Those are only in the label files.

Saved C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\models\threshold.json
