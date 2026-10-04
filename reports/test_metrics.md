# Test split results (reported once)

Final detector on the held-out test split at the accepted threshold 0.00459436746314168. Nothing was tuned on these numbers.
The frozen evaluation set was not opened.

## Pooled

| metric | validation | test |
|---|---|---|
| recall | 1.0000 | 0.9986 |
| precision | 0.6993 | 0.7206 |
| F1 | 0.8230 | 0.8371 |
| false positive rate | 0.08725 | 0.07857 |
| alerts | 115466 | 111903 |
| false positives | 34721 | 31265 |
| missed attacks | 3 | 114 |
| false positive share of alerts | 0.3007 | 0.2794 |

Threshold-free on test: PR-AUC 0.99695, ROC-AUC 0.99925, Brier 0.01320.
At the provisional 0.5: recall 0.8759, precision 0.9968 (for comparison with Day 4).

Recall target 0.95: met on test (0.9986).

## Per class (test)

Attack classes show recall, BENIGN shows specificity. The interval is a 95% Wilson interval.

| class | test rows | flagged | rate | 95% interval | validation rate |
|---|---|---|---|---|---|
| BENIGN | 397940 | 31265 | 0.9214 | 0.921 to 0.922 | 0.9127 |
| Bot | 371 | 371 | 1.0000 | 0.990 to 1.000 | 0.9946 |
| DDoS | 24322 | 24303 | 0.9992 | 0.999 to 0.999 | 1.0000 |
| DoS GoldenEye | 1954 | 1954 | 1.0000 | 0.998 to 1.000 | 1.0000 |
| DoS Hulk | 32817 | 32734 | 0.9975 | 0.997 to 0.998 | 1.0000 |
| DoS Slowhttptest | 994 | 993 | 0.9990 | 0.994 to 1.000 | 0.9990 |
| DoS slowloris | 1023 | 1020 | 0.9971 | 0.991 to 0.999 | 1.0000 |
| FTP-Patator | 1127 | 1127 | 1.0000 | 0.997 to 1.000 | 1.0000 |
| PortScan | 17125 | 17119 | 0.9996 | 0.999 to 1.000 | 1.0000 |
| SSH-Patator | 612 | 611 | 0.9984 | 0.991 to 1.000 | 1.0000 |
| Web Attack - Brute Force | 279 | 279 | 1.0000 | 0.986 to 1.000 | 1.0000 |
| Web Attack - XSS/SQLi | 128 | 127 | 0.9922 | 0.957 to 0.999 | 1.0000 |

Worst attack class on test: Web Attack - XSS/SQLi with recall 0.9922.
