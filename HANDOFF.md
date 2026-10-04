# Week 2 hand-off

## What is frozen
- Threshold 0.00459436746314168, detector models/detector_xgb.json, features models/feature_list.json.
- Evaluation sets in eval/ with hashes in eval/MANIFEST.json. Check them any time with: python src/verify_eval.py.
- Git tag week1-freeze marks this state.

## Rules that continue
- All tuning uses the dev set only. The frozen set is closed to tuning and development and is opened only through src/eval_io.py for final evaluation runs. Every frozen read is logged.
- Labels and the MITRE answer key are for the evaluation harness only. Agent code must never import them. The Week 3 MITRE lookup tool needs its own ATT&CK reference.
- Incident memory (Week 4) may be seeded from the train split only.
- Every number on the resume must come from a run you can reproduce.

## How to load the data
```python
import eval_io
alerts = eval_io.load_alerts('dev')        # no labels, no file names
flows = eval_io.load_flow_store('dev')     # unlabelled flows; alerts link by flow_row
labels = eval_io.load_labels('dev')        # evaluation harness only
```
Alert columns: alert_id, flow_row, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score and 12 flow features.

## Things to plan for in Week 2
- Leakage through IP addresses and timestamps: run an ablation that masks them.
- Detector score is visible in each alert: run an ablation that hides it.
- Report per-class results and intervals, not only pooled numbers. Small classes have few alerts.
- The evaluation sets are 35% false positives by design. Compare against the raw detector on the same sets and quote the detector's natural precision beside any reduction claim.
- Keep the dev-only rule when iterating on prompts.

## Where things are
- WEEK1_REPORT.md: results. eval/DATASET_CARD.md: how the sets were built. reports/: every step's report. DAY7_RUNBOOK.md: how Week 1 was closed.
