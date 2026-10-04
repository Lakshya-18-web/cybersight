# soc-triage

Multi-agent triage of network security alerts, evaluated on CIC-IDS2017.

## Status

Week 1 of 5 is done: cleaned data, an XGBoost detector, a chosen alert threshold and frozen dev and frozen evaluation sets. No LLM or agent code exists yet (Week 2 starts with a single-LLM baseline). See WEEK1_REPORT.md for results and HANDOFF.md for what Week 2 builds on.

## Layout

```
src/        pipeline scripts, one per step
data/raw/   CIC-IDS2017 CSVs (not in git)
data/processed/   cleaned data, splits, alert files (not in git)
models/     feature list, tuned parameters, detector, threshold
reports/    a report from every step
eval/       dev and frozen sets, MITRE answer key, manifest, dataset card
notebooks/  audit and detector analysis
```

## Reproduce Week 1

1. pip install -r requirements.txt, put the 8 CSVs in data/raw/.
2. Pipeline order: clean.py, split.py, features.py, train_baselines.py, tune_detector.py, train_detector.py (plus --no-dest-port and --adopt-no-dest-port), make_alerts.py --threshold 0.00459436746314168, build_eval_sets.py.
3. Check the evaluation sets: python src/verify_eval.py.
4. Rerun everything in an isolated clone and compare hashes: python src/reproduce_week1.py --mode full.

## Evaluation rules

- The frozen set is closed to tuning and development. It is opened only through src/eval_io.py for final evaluation runs, and each read is logged to eval/frozen_access.log.
- Labels live in separate files read only by the evaluation harness.

## Data

CIC-IDS2017 from the Canadian Institute for Cybersecurity, University of New Brunswick. Sharafaldin, Lashkari, Ghorbani, ICISSP 2018. The dataset has known labelling issues; see eval/DATASET_CARD.md.

