# Baseline results (validation)

Logistic regression: features scaled with a scaler fitted on train, max_iter 300.
Decision tree: max_depth 12, no tuning. Both are fitted on the full train split.
Precision, recall and F1 use a provisional threshold of 0.5. The real threshold is chosen on Day 5.

| model | PR-AUC | ROC-AUC | Brier | precision | recall | F1 | worst attack class | its recall |
|---|---|---|---|---|---|---|---|---|
| logistic_regression | 0.9080 | 0.9794 | 0.0410 | 0.7954 | 0.8598 | 0.8264 | Web Attack - Brute Force | 0.0000 |
| decision_tree | 0.9936 | 0.9966 | 0.0027 | 0.9935 | 0.9867 | 0.9901 | Bot | 0.3432 |

## Per-class rate at threshold 0.5

Attack classes show recall. BENIGN shows specificity (share correctly left unflagged).

| class | logistic regression | decision tree |
|---|---|---|
| BENIGN | 0.9551 | 0.9987 |
| Bot | 0.2730 | 0.3432 |
| DDoS | 0.7641 | 0.9990 |
| DoS GoldenEye | 0.7047 | 0.7738 |
| DoS Hulk | 0.9678 | 0.9995 |
| DoS Slowhttptest | 0.7976 | 0.7875 |
| DoS slowloris | 0.9804 | 1.0000 |
| FTP-Patator | 0.6770 | 1.0000 |
| PortScan | 0.8786 | 0.9957 |
| SSH-Patator | 0.0016 | 0.9804 |
| Web Attack - Brute Force | 0.0000 | 0.8351 |
| Web Attack - XSS/SQLi | 0.0000 | 0.9764 |
