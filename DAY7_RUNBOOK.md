# Day 7 runbook: close Week 1

Run from the project root, in your normal virtual environment. Do the steps in order. Each step says when to stop.
Nothing here changes the threshold, the detector or the Day 6 evaluation sets, and nothing is tuned on test results.

Time estimate: about 2 hours of your attention. The full reproducibility run mostly waits on clean.py and train_detector.py.

## 0. Before you start

1. Unzip the Day 7 files into the project root. `src/config.py` is replaced; it only has a block appended at the end (the Day 1 to 6 lines are unchanged).
2. Delete the unused draft `build_eval.py` if it is in `src/` (it was an interrupted attempt and is not part of the pipeline).
3. Confirm nothing in `eval/`, `models/threshold.json` or `models/detector_xgb.json` has changed since Day 6: `python src/verify_eval.py`. Stop if it fails.

## 1. Reproducibility rerun (about 45 to 90 minutes, several GB of disk)

```
python src/reproduce_week1.py --mode full --dry-run
python src/reproduce_week1.py --mode full
```

- The rerun happens in `../soc-triage-repro`, a separate folder. Your project is not touched. Use `--clean-force` only if you ran `clean.py --force` on Day 2.
- It reuses `models/best_params.json`; the 25-config search is not repeated.
- If a step fails, the log is in `../soc-triage-repro/repro_logs/`. Fix the cause, then resume with `--from-step N`.
- Result: `reports/reproducibility_report.md`. **Stop here if it says FAIL** and send the report. A model file that differs in bytes is acceptable if the alert hashes match; anything else is not.
- Quick variant that only rebuilds the Day 6 sets from the real Day 5 outputs: `--mode eval-only`. It is faster but does not satisfy the end-to-end requirement, and the test evaluation will refuse it unless you pass `--allow-eval-only-repro`.
- Do not rebuild the evaluation sets in your project with `build_eval_sets.py --out-dir ...`: it still overwrites `reports/eval_build_report.md`.

## 2. Spot check of 30 dev alerts (about 30 minutes)

```
python src/spot_check_alerts.py
```

Read `reports/spot_check_30.md`. For each card decide whether the alert, its label and the context make sense together. Then open `reports/spot_check_30.csv`, fill `human_verdict` (OK, PROBLEM or UNSURE) and `notes` (required for UNSURE, PROBLEM and any automatic check failure). Then:

```
python src/spot_check_alerts.py --finalize
```

Dev alerts only. The frozen set is not opened. **Stop if a PROBLEM is found**: tell me what you saw before doing anything else.

## 3. Test split results, once

```
python src/final_test_eval.py --yes-run-once
```

- Refuses to run unless steps 1 and 2 passed and `verify_eval.py` passes.
- Writes `reports/test_metrics.md`, `.json` and `reports/test_eval.lock`. After that it will not run again.
- Evaluates the detector on `test.parquet` at the accepted threshold. The frozen evaluation set is not opened.
- If recall is below 0.95 it is reported as it is. Do not change the threshold, the detector or any set.

## 4. Report and README

```
python src/week1_report.py
```

Writes `WEEK1_REPORT.md`, `HANDOFF.md` and `reports/README_proposed.md`. Read them. If you like the README, run it again with `--write-readme`. Missing inputs show as NOT AVAILABLE and the script exits with code 2.

## 5. Commit and tag (Days 2 to 6 are not committed yet)

```
python src/tag_week1_freeze.py                          # checks only
python src/tag_week1_freeze.py --stage-and-commit --yes
python src/tag_week1_freeze.py --tag --yes
```

- The commit adds only `src`, `notebooks`, `reports`, `models`, `eval`, the three Markdown files, `requirements.txt` and `.gitignore`. It never adds `data/` or `eval/flow_store_*.parquet`, and it appends any missing lines to `.gitignore` first.
- Run the commit and the tag as two separate commands.
- Nothing is pushed. To publish: `git push origin week1-freeze`.

## Rules that stay in force

- The frozen set is closed to tuning and development. It is opened only through `src/eval_io.py` for final evaluation runs, and every read is logged.
- Labels and the MITRE answer key are for the evaluation harness only.
- Every number on your resume must come from a run you can reproduce.
