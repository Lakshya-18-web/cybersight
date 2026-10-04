"""One-time evaluation of the final detector on the held-out TEST split.

This reports the Week 1 detector numbers on test.parquet at the accepted threshold, exactly once.
It does NOT open the frozen evaluation set (eval/frozen_*). That set is closed to tuning and development
and is opened only through eval_io.py for the final evaluation runs.

Nothing is tuned or changed here. If recall is below the 0.95 target, the number is reported as it is.

  python src/final_test_eval.py --yes-run-once

Refuses to run unless:
  - reports/reproducibility_report.json says PASS (full mode, unless --allow-eval-only-repro)
  - reports/spot_check_summary.json says PASS for 30 dev alerts
  - verify_eval.py passes
  - models/threshold.json holds the accepted threshold
  - it has not been run before (reports/test_eval.lock does not exist)
"""
import os
import sys
import json
import math
import hashlib
import argparse
import datetime
import subprocess
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import average_precision_score, roc_auc_score, brier_score_loss

import config
import detector_utils as du

parser = argparse.ArgumentParser()
parser.add_argument("--yes-run-once", action="store_true", help="confirm that the test metrics are reported once and never tuned on")
parser.add_argument("--allow-eval-only-repro", action="store_true", help="accept a reproducibility report made in eval-only mode")
args = parser.parse_args()


def read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


def gates():
    problems = []
    if os.path.exists(config.TEST_EVAL_LOCK):
        problems.append("test metrics were already reported (" + config.TEST_EVAL_LOCK + " exists). They are reported once. Read reports/test_metrics.md.")
    if not args.yes_run_once:
        problems.append("add --yes-run-once to confirm you understand this is the single reporting run")
    if not os.path.exists(config.THRESHOLD_PATH) or read_json(config.THRESHOLD_PATH)["threshold"] != config.ACCEPTED_THRESHOLD:
        problems.append("models/threshold.json does not hold the accepted threshold")
    if not os.path.exists(config.REPRO_REPORT_JSON):
        problems.append("reports/reproducibility_report.json is missing: run reproduce_week1.py first")
    else:
        repro = read_json(config.REPRO_REPORT_JSON)
        if repro.get("status") != "PASS":
            problems.append("reproducibility status is " + str(repro.get("status")) + ", not PASS")
        if repro.get("mode") != "full" and not args.allow_eval_only_repro:
            problems.append("the reproducibility run was " + str(repro.get("mode")) + ", not full (use --allow-eval-only-repro only if you accept that)")
    if not os.path.exists(config.SPOT_CHECK_SUMMARY):
        problems.append("reports/spot_check_summary.json is missing: finish the spot check first")
    else:
        spot = read_json(config.SPOT_CHECK_SUMMARY)
        if spot.get("status") != "PASS" or spot.get("alerts_checked") != config.SPOT_CHECK_TOTAL or spot.get("set") != "dev":
            problems.append("the spot check is not a passing 30-alert dev check")
    if len(problems) == 0:
        result = subprocess.run([sys.executable, os.path.join(config.PROJECT_ROOT, "src", "verify_eval.py"), "--skip-flow-stores"],
                                cwd=config.PROJECT_ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            problems.append("verify_eval.py failed:\n" + result.stdout[-1500:])
    return problems


def main():
    problems = gates()
    if len(problems) > 0:
        print("REFUSED. Nothing was computed or written:")
        for p in problems:
            print("- " + p)
        sys.exit(1)

    threshold_info = read_json(config.THRESHOLD_PATH)
    saved = read_json(config.DETECTOR_METRICS_PATH)
    threshold = float(threshold_info["threshold"])
    features = du.load_features()
    if list(saved["features"]) != list(features):
        print("REFUSED: feature_list.json does not match the model that was trained.")
        sys.exit(1)
    best_iteration = int(saved["best_iteration"])

    test = pd.read_parquet(config.TEST_PATH, columns=features + [config.LABEL_COLUMN])
    labels = test[config.LABEL_COLUMN].to_numpy()
    y = (labels != "BENIGN").astype(int)
    booster = xgb.Booster()
    booster.load_model(config.MODEL_PATH)
    score = np.asarray(booster.predict(xgb.DMatrix(test[features].astype("float32")), iteration_range=(0, best_iteration + 1))).astype("float64")
    del test

    alerts_now = int((score >= threshold).sum())
    if alerts_now != threshold_info["alerts"]["test"]:
        print("REFUSED: scoring the test split gives " + str(alerts_now) + " alerts but Day 5 recorded " + str(threshold_info["alerts"]["test"])
              + ". The model, features or threshold differ from Day 5. Nothing was written.")
        sys.exit(1)

    final = du.binary_metrics(y, score, threshold)
    provisional = du.binary_metrics(y, score, 0.5)
    rates = du.per_class_rates(labels, score, threshold)
    worst_name, worst_value = du.worst_attack_class(rates)
    result = {
        "split": "test", "threshold": threshold, "rows": int(len(y)), "attack_flows": int(y.sum()),
        "pr_auc": float(average_precision_score(y, score)), "roc_auc": float(roc_auc_score(y, score)), "brier": float(brier_score_loss(y, score)),
        "at_accepted_threshold": final, "at_0.5": provisional,
        "recall_target": config.TARGET_RECALL, "meets_recall_target": bool(final["recall"] >= config.TARGET_RECALL),
        "worst_attack_class": worst_name, "worst_attack_recall": worst_value,
        "alerts_match_day5_test_alert_count": True, "per_class": {},
        "done_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "frozen_evaluation_set_opened": False,
    }
    for name in sorted(pd.unique(labels)):
        mask = labels == name
        rows = int(mask.sum())
        flagged = int((score[mask] >= threshold).sum())
        k = rows - flagged if name == "BENIGN" else flagged
        low, high = wilson(k, rows)
        result["per_class"][name] = {"rows": rows, "flagged": flagged, "kind": "specificity" if name == "BENIGN" else "recall",
                                     "rate": rates[name], "wilson95_low": low, "wilson95_high": high,
                                     "validation_rate": threshold_info["validation"]["per_class_rate"].get(name)}

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(config.TEST_METRICS_JSON, "w") as f:
        json.dump(result, f, indent=2)

    v = threshold_info["validation"]
    lines = ["# Test split results (reported once)", "",
             "Final detector on the held-out test split at the accepted threshold " + repr(threshold) + ". Nothing was tuned on these numbers.",
             "The frozen evaluation set was not opened.", "",
             "## Pooled", "", "| metric | validation | test |", "|---|---|---|",
             "| recall | " + "%.4f" % v["recall"] + " | " + "%.4f" % final["recall"] + " |",
             "| precision | " + "%.4f" % v["precision"] + " | " + "%.4f" % final["precision"] + " |",
             "| F1 | " + "%.4f" % v["f1"] + " | " + "%.4f" % final["f1"] + " |",
             "| false positive rate | " + "%.5f" % v["false_positive_rate"] + " | " + "%.5f" % final["false_positive_rate"] + " |",
             "| alerts | " + str(v["alerts"]) + " | " + str(final["tp"] + final["fp"]) + " |",
             "| false positives | " + str(v["fp"]) + " | " + str(final["fp"]) + " |",
             "| missed attacks | " + str(v["fn"]) + " | " + str(final["fn"]) + " |",
             "| false positive share of alerts | " + "%.4f" % v["fp_share_of_alerts"] + " | " + "%.4f" % final["fp_share_of_alerts"] + " |",
             "", "Threshold-free on test: PR-AUC " + "%.5f" % result["pr_auc"] + ", ROC-AUC " + "%.5f" % result["roc_auc"] + ", Brier " + "%.5f" % result["brier"] + ".",
             "At the provisional 0.5: recall " + "%.4f" % provisional["recall"] + ", precision " + "%.4f" % provisional["precision"] + " (for comparison with Day 4).", ""]
    if result["meets_recall_target"]:
        lines.append("Recall target " + str(config.TARGET_RECALL) + ": met on test (" + "%.4f" % final["recall"] + ").")
    else:
        lines.append("Recall target " + str(config.TARGET_RECALL) + ": NOT met on test (" + "%.4f" % final["recall"] + "). Reported as it is; the threshold and detector were not changed.")
    lines += ["", "## Per class (test)", "", "Attack classes show recall, BENIGN shows specificity. The interval is a 95% Wilson interval.", "",
              "| class | test rows | flagged | rate | 95% interval | validation rate |", "|---|---|---|---|---|---|"]
    for name, e in result["per_class"].items():
        val_rate = "n/a" if e["validation_rate"] is None else "%.4f" % e["validation_rate"]
        lines.append("| " + name + " | " + str(e["rows"]) + " | " + str(e["flagged"]) + " | " + "%.4f" % e["rate"] + " | "
                     + "%.3f to %.3f" % (e["wilson95_low"], e["wilson95_high"]) + " | " + val_rate + " |")
    lines += ["", "Worst attack class on test: " + str(worst_name) + " with recall " + "%.4f" % worst_value + "."]
    with open(config.TEST_METRICS_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    with open(config.TEST_METRICS_JSON, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(config.TEST_EVAL_LOCK, "w") as f:
        json.dump({"reported_utc": result["done_utc"], "test_metrics_sha256": digest, "note": "Test metrics are reported once. Do not delete this file to run again."}, f, indent=2)

    print("Test recall " + "%.4f" % final["recall"] + ", precision " + "%.4f" % final["precision"] + ", PR-AUC " + "%.5f" % result["pr_auc"]
          + ", worst class " + str(worst_name) + " " + "%.4f" % worst_value)
    print("Target " + str(config.TARGET_RECALL) + ": " + ("met" if result["meets_recall_target"] else "NOT met (reported as is, no retuning)"))
    print("Wrote reports/test_metrics.md, reports/test_metrics.json and reports/test_eval.lock")


if __name__ == "__main__":
    main()
