import os
import sys
import json
import time
import shutil
import argparse
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve

import config
import detector_utils as du

BEST_PARAMS_PATH = os.path.join(config.MODELS_DIR, "best_params.json")
BASELINE_PATH = os.path.join(config.REPORTS_DIR, "baseline_metrics.json")
ABLATION_PATH = os.path.join(config.REPORTS_DIR, "dest_port_ablation.md")

parser = argparse.ArgumentParser()
parser.add_argument("--no-dest-port", action="store_true")
parser.add_argument("--adopt-no-dest-port", action="store_true")
args = parser.parse_args()

suffix = ""
if args.no_dest_port:
    suffix = "_no_dest_port"


def out_path(folder, name, extension):
    return os.path.join(folder, name + suffix + "." + extension)


def adopt():
    names = [
        os.path.join(config.MODELS_DIR, "detector_xgb.json"),
        os.path.join(config.REPORTS_DIR, "detector_metrics.json"),
        os.path.join(config.REPORTS_DIR, "detector_per_class_recall.csv"),
        os.path.join(config.REPORTS_DIR, "feature_importance.csv"),
        os.path.join(config.REPORTS_DIR, "pr_curve_val.csv"),
        os.path.join(config.REPORTS_DIR, "detector_report.md"),
    ]
    backup_list = os.path.join(config.MODELS_DIR, "feature_list_with_dest_port.json")
    if os.path.exists(backup_list):
        print("Already adopted once. The with-Destination-Port backups exist, so nothing was changed.")
        sys.exit(1)
    for path in names:
        base, extension = os.path.splitext(path)
        if not os.path.exists(base + "_no_dest_port" + extension):
            print("Missing", base + "_no_dest_port" + extension, "- run train_detector.py --no-dest-port first.")
            sys.exit(1)
    for path in names:
        base, extension = os.path.splitext(path)
        shutil.copy2(path, base + "_with_dest_port" + extension)
        shutil.copy2(base + "_no_dest_port" + extension, path)
    features = du.load_features()
    shutil.copy2(config.FEATURE_LIST_PATH, backup_list)
    reduced = [f for f in features if f != "Destination Port"]
    with open(config.FEATURE_LIST_PATH, "w") as f:
        json.dump(reduced, f, indent=2)
    print("Adopted the model without Destination Port.")
    print("feature_list.json now has", len(reduced), "features. Backups end in _with_dest_port.")


def write_ablation(with_port, without_port):
    pr_drop_points = 100.0 * (with_port["pr_auc"] - without_port["pr_auc"])
    worst_drop_points = 100.0 * (with_port["worst_attack_recall"] - without_port["worst_attack_recall"])
    drop_it = pr_drop_points < 1.0 and worst_drop_points < 2.0

    lines = []
    lines.append("# Destination Port ablation (validation, threshold 0.5)")
    lines.append("")
    lines.append("Same tuned parameters, same train data. Only Destination Port is removed from the features.")
    lines.append("")
    lines.append("| | with Destination Port | without | change (points, with minus without) |")
    lines.append("|---|---|---|---|")
    lines.append("| PR-AUC | " + "%.5f" % with_port["pr_auc"] + " | " + "%.5f" % without_port["pr_auc"] + " | " + "%.3f" % pr_drop_points + " |")
    lines.append("| worst attack class recall | " + "%.4f" % with_port["worst_attack_recall"] + " (" + str(with_port["worst_attack_class"]) + ") | "
                 + "%.4f" % without_port["worst_attack_recall"] + " (" + str(without_port["worst_attack_class"]) + ") | " + "%.3f" % worst_drop_points + " |")
    lines.append("| overall recall | " + "%.4f" % with_port["at_threshold"]["recall"] + " | " + "%.4f" % without_port["at_threshold"]["recall"]
                 + " | " + "%.3f" % (100.0 * (with_port["at_threshold"]["recall"] - without_port["at_threshold"]["recall"])) + " |")
    lines.append("| overall precision | " + "%.4f" % with_port["at_threshold"]["precision"] + " | " + "%.4f" % without_port["at_threshold"]["precision"]
                 + " | " + "%.3f" % (100.0 * (with_port["at_threshold"]["precision"] - without_port["at_threshold"]["precision"])) + " |")
    lines.append("")
    lines.append("## Per-class rate")
    lines.append("")
    lines.append("| class | with | without | change (points) |")
    lines.append("|---|---|---|---|")
    for name in with_port["per_class"]:
        a = with_port["per_class"][name]
        b = without_port["per_class"][name]
        lines.append("| " + name + " | " + "%.4f" % a + " | " + "%.4f" % b + " | " + "%.2f" % (100.0 * (a - b)) + " |")
    lines.append("")
    lines.append("## Rule")
    lines.append("")
    lines.append("Drop Destination Port if it costs under 1 point of PR-AUC and under 2 points of recall on the worst class.")
    lines.append("")
    if drop_it:
        lines.append("**Decision: DROP Destination Port.** Run: python src/train_detector.py --adopt-no-dest-port")
    else:
        lines.append("**Decision: KEEP Destination Port.** Nothing more to do.")
    lines.append("")
    lines.append("Small classes have few validation rows, so one or two points of recall on them is only a handful of flows. Look at the per-class table before deciding.")
    with open(ABLATION_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")
    return drop_it, pr_drop_points, worst_drop_points


def main():
    if args.adopt_no_dest_port:
        adopt()
        return

    with open(BEST_PARAMS_PATH, "r") as f:
        params = json.load(f)

    features = du.load_features()
    if args.no_dest_port:
        if "Destination Port" not in features:
            print("Destination Port is not in feature_list.json, nothing to remove.")
            sys.exit(1)
        features = [name for name in features if name != "Destination Port"]
    print("features:", len(features), "weighting:", params["weighting"])

    x_train, y_train, labels_train = du.load_split(config.TRAIN_PATH, features)
    x_val, y_val, labels_val = du.load_split(config.VAL_PATH, features)
    print("train rows:", len(y_train), "validation rows:", len(y_val))

    start = time.time()
    model = du.fit_model(params, x_train, y_train, labels_train, x_val, y_val)
    seconds = round(time.time() - start, 1)
    score = du.predict_scores(model, x_val)
    metrics = du.evaluate(y_val, score, labels_val, 0.5)
    metrics["best_iteration"] = int(model.best_iteration)
    metrics["trees"] = int(model.best_iteration) + 1
    metrics["seconds"] = seconds
    metrics["features"] = features
    metrics["params"] = params
    metrics["uses_destination_port"] = "Destination Port" in features
    print("validation PR-AUC:", round(metrics["pr_auc"], 5), "trees:", metrics["trees"], "seconds:", seconds)

    os.makedirs(config.MODELS_DIR, exist_ok=True)
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    model.save_model(out_path(config.MODELS_DIR, "detector_xgb", "json"))
    with open(out_path(config.REPORTS_DIR, "detector_metrics", "json"), "w") as f:
        json.dump(metrics, f, indent=2)

    rows = []
    for name in labels_val_names(labels_val):
        count = int((labels_val == name).sum())
        kind = "specificity" if name == "BENIGN" else "recall"
        rows.append({"label": name, "kind": kind, "validation_rows": count, "rate_at_0.5": metrics["per_class"][name]})
    pd.DataFrame(rows).to_csv(out_path(config.REPORTS_DIR, "detector_per_class_recall", "csv"), index=False)

    gains = model.get_booster().get_score(importance_type="gain")
    importance_rows = []
    for name in features:
        importance_rows.append({"feature": name, "gain": float(gains.get(name, 0.0))})
    importance = pd.DataFrame(importance_rows).sort_values("gain", ascending=False)
    total_gain = float(importance["gain"].sum())
    importance["share"] = importance["gain"] / total_gain if total_gain > 0 else 0.0
    importance.to_csv(out_path(config.REPORTS_DIR, "feature_importance", "csv"), index=False)

    precision, recall, thresholds = precision_recall_curve(y_val, score)
    picks = np.unique(np.linspace(0, len(precision) - 1, 2000).astype(int))
    pd.DataFrame({"precision": precision[picks], "recall": recall[picks]}).to_csv(
        out_path(config.REPORTS_DIR, "pr_curve_val", "csv"), index=False)

    gate_lines = []
    gate_ok = True
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH, "r") as f:
            baselines = json.load(f)
        for name in baselines:
            baseline_ap = baselines[name]["pr_auc"]
            passed = metrics["pr_auc"] > baseline_ap
            if not passed:
                gate_ok = False
            gate_lines.append("- " + ("PASS" if passed else "FAIL") + ": XGBoost PR-AUC " + "%.5f" % metrics["pr_auc"]
                              + " versus " + name + " " + "%.5f" % baseline_ap)
    else:
        gate_ok = False
        gate_lines.append("- FAIL: reports/baseline_metrics.json not found. Run train_baselines.py first.")

    m = metrics["at_threshold"]
    lines = []
    lines.append("# Detector report (validation)" + (" - without Destination Port" if args.no_dest_port else ""))
    lines.append("")
    lines.append("Features: " + str(len(features)) + ". Trees used: " + str(metrics["trees"]) + ". Weighting: " + params["weighting"] + ".")
    lines.append("Precision, recall and the confusion matrix use a provisional threshold of 0.5. The real threshold is chosen on Day 5.")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append("| PR-AUC | " + "%.5f" % metrics["pr_auc"] + " |")
    lines.append("| ROC-AUC | " + "%.5f" % metrics["roc_auc"] + " |")
    lines.append("| Brier score | " + "%.5f" % metrics["brier"] + " |")
    lines.append("| precision | " + "%.4f" % m["precision"] + " |")
    lines.append("| recall | " + "%.4f" % m["recall"] + " |")
    lines.append("| F1 | " + "%.4f" % m["f1"] + " |")
    lines.append("| false positive rate | " + "%.5f" % m["false_positive_rate"] + " |")
    lines.append("| alerts per 1,000 flows | " + "%.2f" % m["alerts_per_1000_flows"] + " |")
    lines.append("| false positive share of alerts | " + "%.4f" % m["fp_share_of_alerts"] + " |")
    lines.append("")
    lines.append("Confusion matrix: TP " + str(m["tp"]) + ", FP " + str(m["fp"]) + ", TN " + str(m["tn"]) + ", FN " + str(m["fn"]))
    lines.append("")
    lines.append("## Per-class rate at threshold 0.5")
    lines.append("")
    lines.append("| class | validation rows | rate |")
    lines.append("|---|---|---|")
    for row in rows:
        lines.append("| " + row["label"] + " (" + row["kind"] + ") | " + str(row["validation_rows"]) + " | " + "%.4f" % row["rate_at_0.5"] + " |")
    lines.append("")
    lines.append("Worst attack class: " + str(metrics["worst_attack_class"]) + " with recall " + "%.4f" % metrics["worst_attack_recall"])
    lines.append("")
    lines.append("## Top 15 features by gain")
    lines.append("")
    lines.append("| feature | share of total gain |")
    lines.append("|---|---|")
    for i in range(min(15, len(importance))):
        lines.append("| " + importance.iloc[i]["feature"] + " | " + "%.4f" % importance.iloc[i]["share"] + " |")
    lines.append("")
    lines.append("## Gate: beat both baselines on validation PR-AUC")
    lines.append("")
    lines.extend(gate_lines)
    with open(out_path(config.REPORTS_DIR, "detector_report", "md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")

    print("")
    for line in gate_lines:
        print(line)

    if args.no_dest_port:
        with_path = os.path.join(config.REPORTS_DIR, "detector_metrics.json")
        if os.path.exists(with_path):
            with open(with_path, "r") as f:
                with_port = json.load(f)
            drop_it, pr_points, worst_points = write_ablation(with_port, metrics)
            print("")
            print("Ablation: PR-AUC change", round(pr_points, 3), "points, worst-class recall change", round(worst_points, 3), "points")
            if drop_it:
                print("Decision: DROP Destination Port. Run: python src/train_detector.py --adopt-no-dest-port")
            else:
                print("Decision: KEEP Destination Port.")
            print("Saved", ABLATION_PATH)
        else:
            print("Run train_detector.py without flags first to compare.")

    if not gate_ok:
        print("")
        print("GATE FAILED: the detector does not beat both baselines.")
        sys.exit(1)


def labels_val_names(labels):
    return sorted(pd.unique(labels))


if __name__ == "__main__":
    main()
