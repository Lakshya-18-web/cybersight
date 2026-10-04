# Week 1 report: data, detector and frozen evaluation sets

Generated 2026-10-04 from the run artifacts listed in each section. Numbers come from those files. Sections 10 and 11 and the notes are fixed text.

## 1. Outcome

| item | result | source |
|---|---|---|
| Cleaned data | 2519415 flows | reports/cleaning_log.md |
| Detector (validation PR-AUC) | 0.99959 | reports/detector_metrics.json |
| Accepted threshold | 0.00459436746314168 | models/threshold.json |
| Dev / frozen set sizes | 300 / 2500 | eval/MANIFEST.json |
| Reproducibility rerun | PASS (full) | reports/reproducibility_report.md |
| 30-alert dev spot check | PASS: 30 OK, 0 unsure, 0 problem | reports/spot_check_summary.json |
| Test recall (reported once) | 0.9986 - target met | reports/test_metrics.md |

## 2. Data and cleaning

- Dataset: CIC-IDS2017 labelled flows, 8 CSV files, captured 3 to 7 July 2017.
- Raw rows: 3119345. Rows after the 11 cleaning steps: 2519415.
- Infiltration and Heartbleed were dropped (too few flows). Web Attack XSS and SQL injection were merged into one class.
- Details and per-class counts after every step: reports/cleaning_log.md.

## 3. Split and features

- Time-ordered split inside every (source file, label) group: 60% train, 20% validation, 20% test, with 1% gap rows dropped at each boundary.
- Leakage checks (rows accounted for, no row in two splits, time order, no identical feature vector across splits, every class in every split, no NaN or inf) are in reports/split_report.md.
- Final model features: 53 (after the Destination Port ablation).

## 4. Detector

Validation PR-AUC (threshold-free):

| model | PR-AUC |
|---|---|
| logistic_regression | 0.90799 |
| decision_tree | 0.99358 |
| xgboost | 0.99959 |

XGBoost configuration chosen by random search on validation (25 configs, 25% train subsample): depth 4, learning rate 0.05, subsample 0.7, colsample 0.9, min child weight 20.0, lambda 0.1, weighting class_sqrt.
Trees after early stopping on the full train split: 346.
Destination Port ablation: DROP Destination Port. (reports/dest_port_ablation.md).

## 5. Threshold and alerts

Accepted threshold 0.00459436746314168. Rule: highest threshold with pooled validation recall at least 0.95 and validation false positive share at least 0.3.

| validation metric | value |
|---|---|
| recall | 1.0000 |
| precision | 0.6993 |
| alerts | 115466 |
| false positives | 34721 |
| false positive share of alerts | 0.3007 |
| worst attack class | Bot (0.9946) |

Note: the first Day 5 run used the rule 'highest threshold with pooled recall at least 0.95' and chose 0.9775605201721191. That kept pooled recall at 0.9501 but left almost no false positives (2 on validation) and missed most of Bot (recall 0.0054) and several other small classes. It was replaced by the rule above. Numbers from that first run are from the Day 5 report of that run.

## 6. Evaluation sets

Both sets are 35% detector false positives by design (BENIGN rows below). Built on Week 1, Day 6; seed 42.

| class | dev | frozen |
|---|---|---|
| BENIGN | 105 | 875 |
| Bot | 18 | 150 |
| DDoS | 18 | 150 |
| DoS GoldenEye | 18 | 150 |
| DoS Hulk | 18 | 150 |
| DoS Slowhttptest | 18 | 150 |
| DoS slowloris | 18 | 150 |
| FTP-Patator | 18 | 150 |
| PortScan | 18 | 150 |
| SSH-Patator | 17 | 149 |
| Web Attack - Brute Force | 17 | 149 |
| Web Attack - XSS/SQLi | 17 | 127 |
| total | 300 | 2500 |

Content hashes (first 16 characters):

| file | rows | content hash |
|---|---|---|
| dev_alerts.parquet | 300 | 1b55133d3fe787c7 |
| dev_labels.parquet | 300 | 12321172ea022b38 |
| frozen_alerts.parquet | 2500 | ca0efa87580cdb9d |
| frozen_labels.parquet | 2500 | c6bd07c77cd85b70 |
| flow_store_dev.parquet | 478687 | f0527a8d809ca9bd |
| flow_store_frozen.parquet | 478692 | 37e77d65218dd346 |
| mitre_map.csv | 12 | 3d11350faf04f079 |

The frozen set is closed to tuning and development. It is opened only through src/eval_io.py for final evaluation runs, and every read is logged.

## 7. Reproducibility

Result: **PASS** (full mode, isolated clone). The 25-config tuning search was not repeated; the clone reused models/best_params.json.

| check | result | required |
|---|---|---|
| flows_clean.parquet has identical content | PASS | yes |
| train.parquet has identical content | PASS | yes |
| val.parquet has identical content | PASS | yes |
| test.parquet has identical content | PASS | yes |
| feature_list.json is identical | PASS | yes |
| detector validation PR-AUC matches | PASS | yes |
| detector uses the same number of trees | PASS | yes |
| model file is byte-identical | PASS | no |
| reports/cleaning_log.md has the same text | PASS | no |
| reports/split_report.md has the same text | PASS | no |
| threshold is the accepted value | PASS | yes |
| Day 5 validation_alerts_hash is identical | PASS | yes |
| Day 5 validation_labels_hash is identical | PASS | yes |
| Day 5 test_alerts_hash is identical | PASS | yes |
| Day 5 test_labels_hash is identical | PASS | yes |
| validation confusion counts are identical | PASS | yes |
| rebuilt eval files match the real MANIFEST.json (verify_eval.py) | PASS | yes |

Environment: python 3.10.11, platform Windows-10-10.0.26200-SP0, pandas 2.3.3, numpy 2.2.6, sklearn 1.7.2, xgboost 3.2.0, pyarrow 25.0.1.

## 8. Spot check of 30 dev alerts

Result: **PASS**. 30 OK, 0 unsure, 0 problem. Automatic check failures (each explained in the notes): none. Cards: reports/spot_check_30.md.

## 9. Test split results (reported once)

Final detector on test.parquet at the accepted threshold. Nothing was tuned on these numbers. The frozen evaluation set was not opened.

| metric | test |
|---|---|
| recall | 0.9986 |
| precision | 0.7206 |
| F1 | 0.8371 |
| alerts | 111903 |
| false positives | 31265 |
| missed attacks | 114 |
| PR-AUC | 0.99695 |
| ROC-AUC | 0.99925 |

Recall target 0.95: met.

| class | test rows | flagged | rate | 95% interval |
|---|---|---|---|---|
| BENIGN | 397940 | 31265 | 0.9214 | 0.921 to 0.922 |
| Bot | 371 | 371 | 1.0000 | 0.990 to 1.000 |
| DDoS | 24322 | 24303 | 0.9992 | 0.999 to 0.999 |
| DoS GoldenEye | 1954 | 1954 | 1.0000 | 0.998 to 1.000 |
| DoS Hulk | 32817 | 32734 | 0.9975 | 0.997 to 0.998 |
| DoS Slowhttptest | 994 | 993 | 0.9990 | 0.994 to 1.000 |
| DoS slowloris | 1023 | 1020 | 0.9971 | 0.991 to 0.999 |
| FTP-Patator | 1127 | 1127 | 1.0000 | 0.997 to 1.000 |
| PortScan | 17125 | 17119 | 0.9996 | 0.999 to 1.000 |
| SSH-Patator | 612 | 611 | 0.9984 | 0.991 to 1.000 |
| Web Attack - Brute Force | 279 | 279 | 1.0000 | 0.986 to 1.000 |
| Web Attack - XSS/SQLi | 128 | 127 | 0.9922 | 0.957 to 0.999 |

## 10. Deviations from the blueprint and judgment calls

1. Threshold rule changed after the first Day 5 run (see section 5).
2. Set sizes: the plan says dev about 300 and frozen 2,000 to 3,000, with per-class caps of 25 and 200 and a 30 to 50% false positive share. These cannot all hold at once with 11 attack classes, so the totals (300 and 2,500) and a 35% false positive share were the targets and the caps stayed as upper limits.
3. One logged read of the frozen set during Day 6 QA. It was a loader test, not an evaluation.
4. MITRE mapping: one primary technique per class with accepted alternates. DDoS and the two slow-DoS classes are judgment calls (eval/mitre_map.csv).
5. The reproducibility rerun reused best_params.json instead of repeating the tuning search.
6. 'Test metrics once' means the detector on the test split. The frozen evaluation set was not used for it.

## 11. Limitations

- Lab traffic on a fixed weekly schedule. Attacker and victim IPs and attack times are well known for CIC-IDS2017, so a language model may recognise attacks from them rather than from the traffic.
- Known flow-construction and labelling problems in CIC-IDS2017 (for example Engelen, Rimmer, Joosen, 2021).
- The evaluation sets have a built-in false positive share. Report false positive reduction together with the detector's natural precision.
- The threshold is low, so the alert stream is large. It was chosen to keep small classes visible, not as an operating recommendation.
- Small classes have few alerts and wide intervals.
- Detector scores are given to the agent as part of each alert.

## 12. Numbers that are safe for a resume

Each number must be quoted with its source and with the caveats above. If a file is missing the number is not yet usable.

| number | value | source |
|---|---|---|
| Detector validation PR-AUC | 0.99959 | reports/detector_metrics.json |
| Detector test recall at accepted threshold | 0.9986 | reports/test_metrics.json |
| Detector test precision at accepted threshold | 0.7206 | reports/test_metrics.json |
| Detector test PR-AUC | 0.99695 | reports/test_metrics.json |
| Evaluation sets (dev / frozen alerts) | 300 / 2500 | eval/MANIFEST.json |

No LLM or agent numbers exist yet. They start in Week 2.
