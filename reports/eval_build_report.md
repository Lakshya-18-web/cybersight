# Evaluation set build report

Output folder: C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\eval

## Inputs from Day 5

- PASS: threshold.json holds the accepted threshold 0.00459436746314168 (0.00459436746314168)
- PASS: validation alert count is 115466 (115466)
- PASS: validation false positive count is 34721 (34721)
- PASS: threshold.json recall target was met
- PASS: the four Day 5 alert files match the hashes recorded in threshold.json
- PASS: Day 5 alert counts match threshold.json (115466 validation, 111903 test)
- PASS: alert and label files join one to one

## Sampling

Seed 42. Targets: dev 300, frozen 2500, false positive share 0.35.
- PASS: sampling is deterministic (two draws give the same alerts in the same order)

## Flow stores

Dev flow store (validation split): 478687 flows. Frozen flow store (test split): 478692 flows.
- PASS: flow stores have no label, file name or row number column ([])
- PASS: flow stores are 'flow_row' indexed 0..n-1 in time order
- PASS: every selected alert found its flow in the flow store

## Checks: dev set

- PASS: dev: size is 300 (300)
- PASS: dev: every attack class could be filled to its share (attack shortfall 0, FP available 34721 needed 105)
- PASS: dev: false positive share is inside 0.3 to 0.5 (0.3500 (105 of 300))
- PASS: dev: all 11 attack classes are present ([])
- PASS: dev: every attack class has at least 10 alerts ([])
- PASS: dev: no class is above its cap of 25 ([])
- PASS: dev: alert ids are unique
- PASS: dev: alert file and label file have the same ids in the same order
- PASS: dev: alert file has no label, file name, row number or source alert id ([])
- PASS: dev: rows are shuffled, not in time order
- PASS: dev: every label has a MITRE entry
- PASS: dev: every alert points to the matching row in the flow store
- PASS: dev: no missing values in the alert file ([])

## Checks: frozen set

- PASS: frozen: size is 2500 (2500)
- PASS: frozen: every attack class could be filled to its share (attack shortfall 0, FP available 31265 needed 875)
- PASS: frozen: false positive share is inside 0.3 to 0.5 (0.3500 (875 of 2500))
- PASS: frozen: all 11 attack classes are present ([])
- PASS: frozen: every attack class has at least 50 alerts ([])
- PASS: frozen: no class is above its cap of 200 ([])
- PASS: frozen: alert ids are unique
- PASS: frozen: alert file and label file have the same ids in the same order
- PASS: frozen: alert file has no label, file name, row number or source alert id ([])
- PASS: frozen: rows are shuffled, not in time order
- PASS: frozen: every label has a MITRE entry
- PASS: frozen: every alert points to the matching row in the flow store
- PASS: frozen: no missing values in the alert file ([])

## Checks: dev versus frozen

- PASS: dev and frozen share no flow (0 shared)
- PASS: dev alerts all come from validation and frozen alerts all from test
- PASS: dev and frozen share no alert id
- Info: dev flows span 2017-07-03 13:14:13 to 2017-07-07 16:29:00; frozen flows span 2017-07-03 15:15:31 to 2017-07-07 17:02:00. Splits were made inside each (file, label) group, so the ranges overlap by design.

### Dev composition

| class | Day 5 alerts available | selected |
|---|---|---|
| Bot | 368 | 18 |
| DDoS | 24322 | 18 |
| DoS GoldenEye | 1954 | 18 |
| DoS Hulk | 32816 | 18 |
| DoS Slowhttptest | 992 | 18 |
| DoS slowloris | 1023 | 18 |
| FTP-Patator | 1127 | 18 |
| PortScan | 17125 | 18 |
| SSH-Patator | 612 | 17 |
| Web Attack - Brute Force | 279 | 17 |
| Web Attack - XSS/SQLi | 127 | 17 |
| BENIGN (false positives) | 34721 | 105 |

### Frozen composition

| class | Day 5 alerts available | selected |
|---|---|---|
| Bot | 371 | 150 |
| DDoS | 24303 | 150 |
| DoS GoldenEye | 1954 | 150 |
| DoS Hulk | 32734 | 150 |
| DoS Slowhttptest | 993 | 150 |
| DoS slowloris | 1020 | 150 |
| FTP-Patator | 1127 | 150 |
| PortScan | 17119 | 150 |
| SSH-Patator | 611 | 149 |
| Web Attack - Brute Force | 279 | 149 |
| Web Attack - XSS/SQLi | 127 | 127 |
| BENIGN (false positives) | 31265 | 875 |

## Written files

| file | rows | content hash (first 16) |
|---|---|---|
- PASS: dev_alerts: file reads back with the same row count
| dev_alerts.parquet | 300 | 1b55133d3fe787c7 |
- PASS: dev_labels: file reads back with the same row count
| dev_labels.parquet | 300 | 12321172ea022b38 |
- PASS: frozen_alerts: file reads back with the same row count
| frozen_alerts.parquet | 2500 | ca0efa87580cdb9d |
- PASS: frozen_labels: file reads back with the same row count
| frozen_labels.parquet | 2500 | c6bd07c77cd85b70 |
- PASS: flow_store_dev: file reads back with the same row count
| flow_store_dev.parquet | 478687 | f0527a8d809ca9bd |
- PASS: flow_store_frozen: file reads back with the same row count
| flow_store_frozen.parquet | 478692 | 37e77d65218dd346 |
| mitre_map.csv | 12 | sha256 3d11350faf04f079 |

Saved C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\eval\MANIFEST.json
Saved C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\eval\DATASET_CARD.md
