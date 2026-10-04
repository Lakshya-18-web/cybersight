# Detector report (validation)

Features: 54. Trees used: 121. Weighting: class_sqrt.
Precision, recall and the confusion matrix use a provisional threshold of 0.5. The real threshold is chosen on Day 5.

| metric | value |
|---|---|
| PR-AUC | 0.99960 |
| ROC-AUC | 0.99991 |
| Brier score | 0.00255 |
| precision | 0.9983 |
| recall | 0.9856 |
| F1 | 0.9919 |
| false positive rate | 0.00035 |
| alerts per 1,000 flows | 166.55 |
| false positive share of alerts | 0.0017 |

Confusion matrix: TP 79587, FP 139, TN 397800, FN 1161

## Per-class rate at threshold 0.5

| class | validation rows | rate |
|---|---|---|
| BENIGN (specificity) | 397939 | 0.9997 |
| Bot (recall) | 370 | 0.3946 |
| DDoS (recall) | 24322 | 0.9939 |
| DoS GoldenEye (recall) | 1954 | 0.8833 |
| DoS Hulk (recall) | 32816 | 0.9921 |
| DoS Slowhttptest (recall) | 993 | 0.9235 |
| DoS slowloris (recall) | 1023 | 1.0000 |
| FTP-Patator (recall) | 1127 | 1.0000 |
| PortScan (recall) | 17125 | 0.9906 |
| SSH-Patator (recall) | 612 | 0.9804 |
| Web Attack - Brute Force (recall) | 279 | 0.8351 |
| Web Attack - XSS/SQLi (recall) | 127 | 0.9528 |

Worst attack class: Bot with recall 0.3946

## Top 15 features by gain

| feature | share of total gain |
|---|---|
| Bwd Packet Length Std | 0.1966 |
| PSH Flag Count | 0.0792 |
| Bwd Packet Length Mean | 0.0514 |
| Fwd IAT Std | 0.0483 |
| Packet Length Std | 0.0435 |
| Packet Length Variance | 0.0430 |
| act_data_pkt_fwd | 0.0406 |
| Fwd Packet Length Mean | 0.0339 |
| Bwd IAT Std | 0.0270 |
| Fwd Header Length | 0.0267 |
| Bwd Packet Length Min | 0.0264 |
| Destination Port | 0.0251 |
| min_seg_size_forward | 0.0232 |
| Idle Mean | 0.0227 |
| Total Fwd Packets | 0.0217 |

## Gate: beat both baselines on validation PR-AUC

- PASS: XGBoost PR-AUC 0.99960 versus logistic_regression 0.90799
- PASS: XGBoost PR-AUC 0.99960 versus decision_tree 0.99358
