# Reproducibility report

**Result: PASS**

Mode: full. Rerun in an isolated clone: C:\Users\laksh\Downloads\soc-triage-day1\soc-triage-repro
The 25-config tuning search was not repeated. The clone reused models/best_params.json.
Started 2026-10-04T09:58:07Z, finished 2026-10-04T10:06:38Z.

## Environment

- python: 3.10.11
- platform: Windows-10-10.0.26200-SP0
- pandas: 2.3.3
- numpy: 2.2.6
- sklearn: 1.7.2
- xgboost: 3.2.0
- pyarrow: 25.0.1

## Steps

| # | step | exit | seconds |
|---|---|---|---|
| 1 | clean | 0 | 146.4 |
| 2 | split | 0 | 45.8 |
| 3 | features | 0 | 20.7 |
| 4 | baselines | 0 | 118.8 |
| 5 | detector_with_port | 0 | 39.0 |
| 6 | detector_no_port | 0 | 66.3 |
| 7 | adopt_no_port | 0 | 3.7 |
| 8 | alerts | 0 | 13.2 |
| 9 | eval_sets | 0 | 15.9 |

## Comparison with the real project

| check | result | required | detail |
|---|---|---|---|
| flows_clean.parquet has identical content | PASS | yes | 2519415 vs 2519415 rows |
| train.parquet has identical content | PASS | yes | 1511650 vs 1511650 rows |
| val.parquet has identical content | PASS | yes | 478687 vs 478687 rows |
| test.parquet has identical content | PASS | yes | 478692 vs 478692 rows |
| feature_list.json is identical | PASS | yes |  |
| detector validation PR-AUC matches | PASS | yes | real 0.99959203, clone 0.99959203 |
| detector uses the same number of trees | PASS | yes | 346 vs 346 |
| model file is byte-identical | PASS | no | different bytes are acceptable if the alerts below match |
| reports/cleaning_log.md has the same text | PASS | no | after replacing project paths |
| reports/split_report.md has the same text | PASS | no | after replacing project paths |
| threshold is the accepted value | PASS | yes | 0.00459436746314168 |
| Day 5 validation_alerts_hash is identical | PASS | yes |  |
| Day 5 validation_labels_hash is identical | PASS | yes |  |
| Day 5 test_alerts_hash is identical | PASS | yes |  |
| Day 5 test_labels_hash is identical | PASS | yes |  |
| validation confusion counts are identical | PASS | yes |  |
| rebuilt eval files match the real MANIFEST.json (verify_eval.py) | PASS | yes | exit 0 |

## Real project left untouched

Checked 20 protected files (Day 5 and Day 6 outputs, model, threshold, manifest) by SHA-256 before and after: all unchanged.
