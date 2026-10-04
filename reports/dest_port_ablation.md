# Destination Port ablation (validation, threshold 0.5)

Same tuned parameters, same train data. Only Destination Port is removed from the features.

| | with Destination Port | without | change (points, with minus without) |
|---|---|---|---|
| PR-AUC | 0.99960 | 0.99959 | 0.001 |
| worst attack class recall | 0.3946 (Bot) | 0.7027 (Bot) | -30.811 |
| overall recall | 0.9856 | 0.9944 | -0.873 |
| overall precision | 0.9983 | 0.9971 | 0.116 |

## Per-class rate

| class | with | without | change (points) |
|---|---|---|---|
| BENIGN | 0.9997 | 0.9994 | 0.02 |
| Bot | 0.3946 | 0.7027 | -30.81 |
| DDoS | 0.9939 | 0.9988 | -0.49 |
| DoS GoldenEye | 0.8833 | 0.9611 | -7.78 |
| DoS Hulk | 0.9921 | 0.9944 | -0.23 |
| DoS Slowhttptest | 0.9235 | 0.9537 | -3.02 |
| DoS slowloris | 1.0000 | 1.0000 | 0.00 |
| FTP-Patator | 1.0000 | 1.0000 | 0.00 |
| PortScan | 0.9906 | 1.0000 | -0.94 |
| SSH-Patator | 0.9804 | 0.9967 | -1.63 |
| Web Attack - Brute Force | 0.8351 | 0.9713 | -13.62 |
| Web Attack - XSS/SQLi | 0.9528 | 0.9764 | -2.36 |

## Rule

Drop Destination Port if it costs under 1 point of PR-AUC and under 2 points of recall on the worst class.

**Decision: DROP Destination Port.** Run: python src/train_detector.py --adopt-no-dest-port

Small classes have few validation rows, so one or two points of recall on them is only a handful of flows. Look at the per-class table before deciding.
