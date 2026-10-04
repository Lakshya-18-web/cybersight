# Detector report (validation) - without Destination Port

Features: 53. Trees used: 346. Weighting: class_sqrt.
Precision, recall and the confusion matrix use a provisional threshold of 0.5. The real threshold is chosen on Day 5.

| metric | value |
|---|---|
| PR-AUC | 0.99959 |
| ROC-AUC | 0.99990 |
| Brier score | 0.00123 |
| precision | 0.9971 |
| recall | 0.9944 |
| F1 | 0.9957 |
| false positive rate | 0.00059 |
| alerts per 1,000 flows | 168.22 |
| false positive share of alerts | 0.0029 |

Confusion matrix: TP 80292, FP 234, TN 397705, FN 456

## Per-class rate at threshold 0.5

| class | validation rows | rate |
|---|---|---|
| BENIGN (specificity) | 397939 | 0.9994 |
| Bot (recall) | 370 | 0.7027 |
| DDoS (recall) | 24322 | 0.9988 |
| DoS GoldenEye (recall) | 1954 | 0.9611 |
| DoS Hulk (recall) | 32816 | 0.9944 |
| DoS Slowhttptest (recall) | 993 | 0.9537 |
| DoS slowloris (recall) | 1023 | 1.0000 |
| FTP-Patator (recall) | 1127 | 1.0000 |
| PortScan (recall) | 17125 | 1.0000 |
| SSH-Patator (recall) | 612 | 0.9967 |
| Web Attack - Brute Force (recall) | 279 | 0.9713 |
| Web Attack - XSS/SQLi (recall) | 127 | 0.9764 |

Worst attack class: Bot with recall 0.7027

## Top 15 features by gain

| feature | share of total gain |
|---|---|
| Bwd Packet Length Std | 0.2034 |
| PSH Flag Count | 0.1394 |
| Packet Length Std | 0.0621 |
| Bwd Packet Length Mean | 0.0580 |
| Fwd IAT Mean | 0.0469 |
| Bwd Header Length | 0.0337 |
| ACK Flag Count | 0.0303 |
| Bwd IAT Std | 0.0273 |
| act_data_pkt_fwd | 0.0270 |
| Fwd Packet Length Max | 0.0269 |
| Bwd Packet Length Min | 0.0258 |
| Fwd Packet Length Mean | 0.0248 |
| min_seg_size_forward | 0.0244 |
| Fwd Header Length | 0.0234 |
| Flow Packets/s | 0.0189 |

## Gate: beat both baselines on validation PR-AUC

- PASS: XGBoost PR-AUC 0.99959 versus logistic_regression 0.90799
- PASS: XGBoost PR-AUC 0.99959 versus decision_tree 0.99358
