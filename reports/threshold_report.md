# Threshold report

Day 5: threshold chosen on validation only, then alert files for validation and test.
Target: validation recall of at least 0.95 over all attack classes pooled.

## Model checks

- PASS: feature_list.json matches the features the saved model was trained on (53 features)
- Model uses Destination Port: False. Trees used: 346.
- PASS: scores from the loaded model reproduce the saved validation PR-AUC (recomputed 0.999592, saved 0.999592)

## Threshold selection (validation only)

Validation rows: 478687, attack flows: 80748
Rule: manual override from the command line
Alerts are flows with detector score >= threshold.

**Chosen threshold: 0.00459436746314168**
- PASS: validation recall at the chosen threshold is at least 0.95 (recall 1.0000)

## Validation metrics at the chosen threshold

| metric | chosen threshold | provisional 0.5 |
|---|---|---|
| threshold | 0.004594 | 0.500000 |
| recall | 1.0000 | 0.9944 |
| precision | 0.6993 | 0.9971 |
| F1 | 0.8230 | 0.9957 |
| false positive rate | 0.08725 | 0.00059 |
| alerts | 115466 | 80526 |
| true positives | 80745 | 80292 |
| false positives | 34721 | 234 |
| missed attacks (false negatives) | 3 | 456 |
| false positive share of alerts | 0.3007 | 0.0029 |

## Per-class rate on validation

Attack classes show recall. BENIGN shows specificity (share left unflagged).

| class | validation rows | alerts | rate at chosen threshold | rate at 0.5 |
|---|---|---|---|---|
| BENIGN | 397939 | 34721 | 0.9127 | 0.9994 |
| Bot | 370 | 368 | 0.9946 | 0.7027 |
| DDoS | 24322 | 24322 | 1.0000 | 0.9988 |
| DoS GoldenEye | 1954 | 1954 | 1.0000 | 0.9611 |
| DoS Hulk | 32816 | 32816 | 1.0000 | 0.9944 |
| DoS Slowhttptest | 993 | 992 | 0.9990 | 0.9537 |
| DoS slowloris | 1023 | 1023 | 1.0000 | 1.0000 |
| FTP-Patator | 1127 | 1127 | 1.0000 | 1.0000 |
| PortScan | 17125 | 17125 | 1.0000 | 1.0000 |
| SSH-Patator | 612 | 612 | 1.0000 | 0.9967 |
| Web Attack - Brute Force | 279 | 279 | 1.0000 | 0.9713 |
| Web Attack - XSS/SQLi | 127 | 127 | 1.0000 | 0.9764 |

Worst attack class at the chosen threshold: Bot with recall 0.9946.
Every attack class is at or above 0.95 recall.

## Sensitivity: other thresholds on validation

| threshold | recall | precision | alerts | false positives | FP share | worst attack class | its recall |
|---|---|---|---|---|---|---|---|
| 0.004594 (chosen) | 1.0000 | 0.6993 | 115466 | 34721 | 0.3007 | Bot | 0.9946 |
| 0.050000 | 0.9982 | 0.9566 | 84266 | 3661 | 0.0434 | Bot | 0.7243 |
| 0.100000 | 0.9978 | 0.9744 | 82683 | 2114 | 0.0256 | Bot | 0.7135 |
| 0.200000 | 0.9972 | 0.9911 | 81238 | 719 | 0.0089 | Bot | 0.7054 |
| 0.300000 | 0.9965 | 0.9947 | 80895 | 429 | 0.0053 | Bot | 0.7027 |
| 0.500000 | 0.9944 | 0.9971 | 80526 | 234 | 0.0029 | Bot | 0.7027 |
| 0.700000 | 0.9921 | 0.9981 | 80263 | 149 | 0.0019 | Bot | 0.6703 |
| 0.900000 | 0.9807 | 0.9991 | 79267 | 74 | 0.0009 | Bot | 0.3514 |
| 0.950000 | 0.9711 | 0.9995 | 78454 | 42 | 0.0005 | Bot | 0.3243 |
| 0.990000 | 0.8861 | 1.0000 | 71549 | 2 | 0.0000 | Bot | 0.0000 |
| 0.999000 | 0.5476 | 1.0000 | 44218 | 0 | 0.0000 | Bot | 0.0000 |

## False-positive share check

Target range for the evaluation sets: 0.3 to 0.5 of alerts being false positives.
False positive share of validation alerts at the chosen threshold: 0.3007 -> IN RANGE

A low natural share is expected for a strong detector. The agent needs enough false positives to be tested on, so Day 6 either samples false positives at a higher rate or uses a lower threshold. This is a decision for you, not the script.

## Feasibility for the Day 6 evaluation sets (preview, not built today)

- Dev set from validation alerts (cap 25 per attack class): about 275 attack alerts. For FP share 0.3 it needs at least 118 false positives. Validation has 34721 at this threshold: enough.
- Frozen set from test alerts (cap 200 per attack class, if every class has that many): up to 2200 attack alerts. For FP share 0.3 it needs at least 943 false positives. Test has a similar size to validation, so compare with the 34721 false positives validation has. Test metrics are not computed today.

## Alert files

- PASS: validation alerts equal true positives plus false positives (115466)
- PASS: validation: alert count equals the number of rows at or above the threshold (115466 vs 115466)
- PASS: validation: alert ids are unique
- PASS: validation: alert file and label file have the same ids in the same order
- PASS: validation: alert file has no label, source file or row number column ([])
- PASS: validation: every detector score is at or above the threshold (lowest score 0.004594)
- PASS: validation: no missing values in the alert file ([])
- PASS: validation label file agrees with the confusion matrix (TP 80745, FP 34721)
- PASS: test: alert count equals the number of rows at or above the threshold (111903 vs 111903)
- PASS: test: alert ids are unique
- PASS: test: alert file and label file have the same ids in the same order
- PASS: test: alert file has no label, source file or row number column ([])
- PASS: test: every detector score is at or above the threshold (lowest score 0.004595)
- PASS: test: no missing values in the alert file ([])

| file | rows | content hash (sha256, first 16) |
|---|---|---|
| alerts_val.parquet | 115466 | 0e4eb01b1317ff89 |
| alerts_val_labels.parquet | 115466 | 2e91a72d420dd251 |
| alerts_test.parquet | 111903 | 81872dbb9de6911e |
| alerts_test_labels.parquet | 111903 | b18dc6445c4e228c |

Test set: 478692 rows scored, 111903 alerts. No test metrics were computed or printed. The test label file exists for the Day 7 run and for building the frozen set on Day 6.

Alert columns: alert_id, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Flow Bytes/s, Flow Packets/s, Fwd Packet Length Mean, Bwd Packet Length Mean, Flow IAT Mean, SYN Flag Count, ACK Flag Count
The alert files contain no label, source file name or row number. Those are only in the label files.

Saved C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\models\threshold.json
