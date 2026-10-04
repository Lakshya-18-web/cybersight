import os
import sys
import json
import math
import hashlib
import argparse
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import precision_recall_curve, average_precision_score

import config
import detector_utils as du

parser = argparse.ArgumentParser()
parser.add_argument("--threshold", type=float, default=None,
                    help="manual threshold instead of the blueprint rule (still must reach the target recall on validation)")
args = parser.parse_args()

report_lines = []
check_results = []


def log(text=""):
    print(text)
    report_lines.append(text)


def check(name, passed, detail=""):
    if passed:
        status = "PASS"
    else:
        status = "FAIL"
    line = "- " + status + ": " + name
    if detail != "":
        line = line + " (" + detail + ")"
    log(line)
    check_results.append(passed)


def write_report():
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(config.THRESHOLD_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
        f.write("\n")


def stop_here(message):
    log("")
    log("STOPPED: " + message)
    write_report()
    sys.exit(1)


def content_hash(df):
    row_hashes = pd.util.hash_pandas_object(df, index=False).values
    return hashlib.sha256(row_hashes.tobytes()).hexdigest()


def load_columns(path, features):
    wanted = list(features)
    extra = list(config.ALERT_ID_COLUMNS.keys()) + list(config.DISPLAY_FEATURES)
    extra = extra + [config.LABEL_COLUMN, "source_file", "original_row"]
    for col in extra:
        if col not in wanted:
            wanted.append(col)
    df = pd.read_parquet(path, columns=wanted)
    return df.reset_index(drop=True)


def score_frame(booster, best_iteration, df, features):
    x = df[features].astype("float32")
    matrix = xgb.DMatrix(x)
    score = booster.predict(matrix, iteration_range=(0, best_iteration + 1))
    return np.asarray(score).astype("float64")


def pick_threshold(y, score, target_recall, min_fp_share=None):
    precision, recall, thresholds = precision_recall_curve(y, score)
    good = recall[:-1] >= target_recall
    if min_fp_share is not None:
        good = good & ((1.0 - precision[:-1]) >= min_fp_share)
    positions = np.where(good)[0]
    if len(positions) == 0:
        return None
    return float(thresholds[positions[-1]])


def build_alerts(df, score, threshold, prefix):
    mask = score >= threshold
    flagged = df[mask].copy()
    flagged["detector_score"] = score[mask]
    flagged = flagged.sort_values(["Timestamp", "source_file", "original_row"], kind="stable").reset_index(drop=True)
    ids = [prefix + "-" + "%06d" % (i + 1) for i in range(len(flagged))]

    alerts = pd.DataFrame({"alert_id": ids})
    for column in config.ALERT_ID_COLUMNS:
        alerts[config.ALERT_ID_COLUMNS[column]] = flagged[column].values
    alerts["detector_score"] = flagged["detector_score"].values
    for column in config.DISPLAY_FEATURES:
        alerts[column] = flagged[column].values

    labels = pd.DataFrame({"alert_id": ids})
    labels["label"] = flagged[config.LABEL_COLUMN].values
    labels["is_attack"] = (flagged[config.LABEL_COLUMN].values != "BENIGN").astype(int)
    labels["source_file"] = flagged["source_file"].values
    labels["original_row"] = flagged["original_row"].values
    return alerts, labels


def write_and_verify(name, alerts, labels, alerts_path, labels_path, threshold, expected_count):
    os.makedirs(config.PROCESSED_DIR, exist_ok=True)
    alerts.to_parquet(alerts_path, index=False)
    labels.to_parquet(labels_path, index=False)
    back_alerts = pd.read_parquet(alerts_path)
    back_labels = pd.read_parquet(labels_path)

    check(name + ": alert count equals the number of rows at or above the threshold",
          len(back_alerts) == expected_count, str(len(back_alerts)) + " vs " + str(expected_count))
    check(name + ": alert ids are unique", back_alerts["alert_id"].is_unique)
    check(name + ": alert file and label file have the same ids in the same order",
          list(back_alerts["alert_id"]) == list(back_labels["alert_id"]))
    forbidden = [c for c in back_alerts.columns if c in config.FORBIDDEN_ALERT_COLUMNS]
    check(name + ": alert file has no label, source file or row number column", len(forbidden) == 0, str(forbidden))
    if len(back_alerts) > 0:
        check(name + ": every detector score is at or above the threshold",
              float(back_alerts["detector_score"].min()) >= threshold,
              "lowest score " + "%.6f" % float(back_alerts["detector_score"].min()))
    nan_cols = [c for c in back_alerts.columns if back_alerts[c].isna().any()]
    check(name + ": no missing values in the alert file", len(nan_cols) == 0, str(nan_cols))
    return content_hash(back_alerts), content_hash(back_labels)


def main():
    label = config.LABEL_COLUMN
    target = config.TARGET_RECALL

    log("# Threshold report")
    log("")
    log("Day 5: threshold chosen on validation only, then alert files for validation and test.")
    log("Target: validation recall of at least " + str(target) + " over all attack classes pooled.")

    features = du.load_features()
    if not os.path.exists(config.DETECTOR_METRICS_PATH) or not os.path.exists(config.MODEL_PATH):
        stop_here("models/detector_xgb.json or reports/detector_metrics.json is missing. Finish Day 4 first.")
    with open(config.DETECTOR_METRICS_PATH, "r") as f:
        saved = json.load(f)
    best_iteration = int(saved["best_iteration"])

    log("")
    log("## Model checks")
    log("")
    check("feature_list.json matches the features the saved model was trained on", list(saved["features"]) == list(features),
          str(len(features)) + " features")
    uses_port = "Destination Port" in features
    log("- Model uses Destination Port: " + str(uses_port) + ". Trees used: " + str(best_iteration + 1) + ".")

    booster = xgb.Booster()
    booster.load_model(config.MODEL_PATH)

    val = load_columns(config.VAL_PATH, features)
    val_labels = val[label].to_numpy()
    y_val = (val_labels != "BENIGN").astype(int)
    val_score = score_frame(booster, best_iteration, val, features)
    recomputed = float(average_precision_score(y_val, val_score))
    difference = abs(recomputed - float(saved["pr_auc"]))
    check("scores from the loaded model reproduce the saved validation PR-AUC", difference <= config.SCORE_CHECK_TOLERANCE,
          "recomputed " + "%.6f" % recomputed + ", saved " + "%.6f" % float(saved["pr_auc"]))
    if not all(check_results):
        stop_here("the loaded model does not reproduce its Day 4 validation PR-AUC. No threshold or alert files were written.")

    n_attack_val = int(y_val.sum())
    log("")
    log("## Threshold selection (validation only)")
    log("")
    log("Validation rows: " + str(len(y_val)) + ", attack flows: " + str(n_attack_val))
    if args.threshold is None:
        threshold = pick_threshold(y_val, val_score, target)
        rule = "highest score threshold whose validation recall is at least " + str(target)
        if threshold is None:
            stop_here("no threshold reaches recall " + str(target) + " on validation.")
    else:
        threshold = float(args.threshold)
        rule = "manual override from the command line"
    log("Rule: " + rule)
    log("Alerts are flows with detector score >= threshold.")
    log("")
    log("**Chosen threshold: " + repr(threshold) + "**")

    chosen = du.binary_metrics(y_val, val_score, threshold)
    rates = du.per_class_rates(val_labels, val_score, threshold)
    worst_name, worst_value = du.worst_attack_class(rates)
    rates_half = du.per_class_rates(val_labels, val_score, 0.5)
    half = du.binary_metrics(y_val, val_score, 0.5)

    check("validation recall at the chosen threshold is at least " + str(target), chosen["recall"] >= target,
          "recall " + "%.4f" % chosen["recall"])
    if not all(check_results):
        stop_here("the threshold does not reach the target recall on validation.")

    log("")
    log("## Validation metrics at the chosen threshold")
    log("")
    log("| metric | chosen threshold | provisional 0.5 |")
    log("|---|---|---|")
    log("| threshold | " + "%.6f" % threshold + " | 0.500000 |")
    log("| recall | " + "%.4f" % chosen["recall"] + " | " + "%.4f" % half["recall"] + " |")
    log("| precision | " + "%.4f" % chosen["precision"] + " | " + "%.4f" % half["precision"] + " |")
    log("| F1 | " + "%.4f" % chosen["f1"] + " | " + "%.4f" % half["f1"] + " |")
    log("| false positive rate | " + "%.5f" % chosen["false_positive_rate"] + " | " + "%.5f" % half["false_positive_rate"] + " |")
    log("| alerts | " + str(chosen["tp"] + chosen["fp"]) + " | " + str(half["tp"] + half["fp"]) + " |")
    log("| true positives | " + str(chosen["tp"]) + " | " + str(half["tp"]) + " |")
    log("| false positives | " + str(chosen["fp"]) + " | " + str(half["fp"]) + " |")
    log("| missed attacks (false negatives) | " + str(chosen["fn"]) + " | " + str(half["fn"]) + " |")
    log("| false positive share of alerts | " + "%.4f" % chosen["fp_share_of_alerts"] + " | " + "%.4f" % half["fp_share_of_alerts"] + " |")

    log("")
    log("## Per-class rate on validation")
    log("")
    log("Attack classes show recall. BENIGN shows specificity (share left unflagged).")
    log("")
    log("| class | validation rows | alerts | rate at chosen threshold | rate at 0.5 |")
    log("|---|---|---|---|---|")
    class_alerts = {}
    for name in sorted(pd.unique(val_labels)):
        in_class = val_labels == name
        flagged = int((in_class & (val_score >= threshold)).sum())
        class_alerts[name] = flagged
        log("| " + name + " | " + str(int(in_class.sum())) + " | " + str(flagged) + " | " + "%.4f" % rates[name]
            + " | " + "%.4f" % rates_half[name] + " |")
    below = [name for name in rates if name != "BENIGN" and rates[name] < target]
    log("")
    log("Worst attack class at the chosen threshold: " + str(worst_name) + " with recall " + "%.4f" % worst_value + ".")
    if len(below) > 0:
        log("Attack classes under " + str(target) + " recall: " + ", ".join(below)
            + ". The rule only fixes pooled recall, so a small class can sit well below it.")
    else:
        log("Every attack class is at or above " + str(target) + " recall.")

    log("")
    log("## Sensitivity: other thresholds on validation")
    log("")
    log("| threshold | recall | precision | alerts | false positives | FP share | worst attack class | its recall |")
    log("|---|---|---|---|---|---|---|---|")
    grid = sorted(set(config.THRESHOLD_GRID + [threshold]))
    for t in grid:
        m = du.binary_metrics(y_val, val_score, t)
        r = du.per_class_rates(val_labels, val_score, t)
        wn, wv = du.worst_attack_class(r)
        mark = ""
        if t == threshold:
            mark = " (chosen)"
        log("| " + "%.6f" % t + mark + " | " + "%.4f" % m["recall"] + " | " + "%.4f" % m["precision"] + " | " + str(m["tp"] + m["fp"])
            + " | " + str(m["fp"]) + " | " + "%.4f" % m["fp_share_of_alerts"] + " | " + str(wn) + " | " + "%.4f" % wv + " |")

    log("")
    log("## False-positive share check")
    log("")
    log("Target range for the evaluation sets: " + str(config.FP_SHARE_MIN) + " to " + str(config.FP_SHARE_MAX)
        + " of alerts being false positives.")
    share = chosen["fp_share_of_alerts"]
    if share < config.FP_SHARE_MIN:
        fp_status = "BELOW"
    elif share > config.FP_SHARE_MAX:
        fp_status = "ABOVE"
    else:
        fp_status = "IN RANGE"
    log("False positive share of validation alerts at the chosen threshold: " + "%.4f" % share + " -> " + fp_status)

    suggestion = None
    if fp_status == "BELOW":
        suggestion = pick_threshold(y_val, val_score, target, config.FP_SHARE_MIN)
        if suggestion is not None:
            s = du.binary_metrics(y_val, val_score, suggestion)
            sr = du.per_class_rates(val_labels, val_score, suggestion)
            sn, sv = du.worst_attack_class(sr)
            log("")
            log("Highest threshold that keeps recall at or above " + str(target) + " and reaches FP share " + str(config.FP_SHARE_MIN)
                + ": " + "%.6f" % suggestion + " (recall " + "%.4f" % s["recall"] + ", precision " + "%.4f" % s["precision"]
                + ", alerts " + str(s["tp"] + s["fp"]) + ", false positives " + str(s["fp"]) + ", FP share " + "%.4f" % s["fp_share_of_alerts"]
                + ", worst class " + str(sn) + " " + "%.4f" % sv + ").")
            log("To use it: python src/make_alerts.py --threshold " + repr(suggestion))
        else:
            log("")
            log("No threshold keeps recall at or above " + str(target) + " and reaches FP share " + str(config.FP_SHARE_MIN) + ".")
    log("")
    log("A low natural share is expected for a strong detector. The agent needs enough false positives to be tested on, "
        "so Day 6 either samples false positives at a higher rate or uses a lower threshold. This is a decision for you, not the script.")

    attack_classes = [name for name in class_alerts if name != "BENIGN"]
    dev_attacks = 0
    for name in attack_classes:
        true_alerts = int(((val_labels == name) & (val_score >= threshold)).sum())
        dev_attacks = dev_attacks + min(config.DEV_CAP_PER_CLASS, true_alerts)
    dev_fp_min = math.ceil(dev_attacks * config.FP_SHARE_MIN / (1.0 - config.FP_SHARE_MIN))
    frozen_attacks = len(attack_classes) * config.FROZEN_CAP_PER_CLASS
    frozen_fp_min = math.ceil(frozen_attacks * config.FP_SHARE_MIN / (1.0 - config.FP_SHARE_MIN))
    log("")
    log("## Feasibility for the Day 6 evaluation sets (preview, not built today)")
    log("")
    log("- Dev set from validation alerts (cap " + str(config.DEV_CAP_PER_CLASS) + " per attack class): about " + str(dev_attacks)
        + " attack alerts. For FP share " + str(config.FP_SHARE_MIN) + " it needs at least " + str(dev_fp_min)
        + " false positives. Validation has " + str(chosen["fp"]) + " at this threshold: "
        + ("enough." if chosen["fp"] >= dev_fp_min else "NOT enough."))
    log("- Frozen set from test alerts (cap " + str(config.FROZEN_CAP_PER_CLASS) + " per attack class, if every class has that many): up to "
        + str(frozen_attacks) + " attack alerts. For FP share " + str(config.FP_SHARE_MIN) + " it needs at least " + str(frozen_fp_min)
        + " false positives. Test has a similar size to validation, so compare with the " + str(chosen["fp"])
        + " false positives validation has. Test metrics are not computed today.")

    log("")
    log("## Alert files")
    log("")
    alerts_val, labels_val = build_alerts(val, val_score, threshold, "VAL")
    expected_val = int((val_score >= threshold).sum())
    check("validation alerts equal true positives plus false positives",
          expected_val == chosen["tp"] + chosen["fp"], str(expected_val))
    val_alert_hash, val_label_hash = write_and_verify("validation", alerts_val, labels_val, config.ALERTS_VAL_PATH,
                                                      config.ALERTS_VAL_LABELS_PATH, threshold, expected_val)
    check("validation label file agrees with the confusion matrix",
          int(labels_val["is_attack"].sum()) == chosen["tp"] and int((labels_val["is_attack"] == 0).sum()) == chosen["fp"],
          "TP " + str(int(labels_val["is_attack"].sum())) + ", FP " + str(int((labels_val["is_attack"] == 0).sum())))
    del val

    test = load_columns(config.TEST_PATH, features)
    test_score = score_frame(booster, best_iteration, test, features)
    expected_test = int((test_score >= threshold).sum())
    alerts_test, labels_test = build_alerts(test, test_score, threshold, "TEST")
    test_rows = len(test)
    del test
    test_alert_hash, test_label_hash = write_and_verify("test", alerts_test, labels_test, config.ALERTS_TEST_PATH,
                                                        config.ALERTS_TEST_LABELS_PATH, threshold, expected_test)

    log("")
    log("| file | rows | content hash (sha256, first 16) |")
    log("|---|---|---|")
    log("| alerts_val.parquet | " + str(len(alerts_val)) + " | " + val_alert_hash[:16] + " |")
    log("| alerts_val_labels.parquet | " + str(len(labels_val)) + " | " + val_label_hash[:16] + " |")
    log("| alerts_test.parquet | " + str(len(alerts_test)) + " | " + test_alert_hash[:16] + " |")
    log("| alerts_test_labels.parquet | " + str(len(labels_test)) + " | " + test_label_hash[:16] + " |")
    log("")
    log("Test set: " + str(test_rows) + " rows scored, " + str(len(alerts_test)) + " alerts. No test metrics were computed or printed. "
        "The test label file exists for the Day 7 run and for building the frozen set on Day 6.")
    log("")
    log("Alert columns: " + ", ".join(list(alerts_val.columns)))
    log("The alert files contain no label, source file name or row number. Those are only in the label files.")

    if not all(check_results):
        stop_here("at least one check failed. Review the report before using the alert files.")

    result = {
        "threshold": threshold,
        "rule": rule,
        "target_recall": target,
        "alert_condition": "detector_score >= threshold",
        "model_path": "models/detector_xgb.json",
        "trees_used": best_iteration + 1,
        "n_features": len(features),
        "uses_destination_port": uses_port,
        "validation": {
            "rows": int(len(y_val)),
            "attack_flows": n_attack_val,
            "recall": chosen["recall"],
            "precision": chosen["precision"],
            "f1": chosen["f1"],
            "false_positive_rate": chosen["false_positive_rate"],
            "tp": chosen["tp"],
            "fp": chosen["fp"],
            "fn": chosen["fn"],
            "tn": chosen["tn"],
            "alerts": chosen["tp"] + chosen["fp"],
            "fp_share_of_alerts": chosen["fp_share_of_alerts"],
            "per_class_rate": rates,
            "worst_attack_class": worst_name,
            "worst_attack_recall": worst_value,
            "attack_classes_under_target": below,
            "pr_auc_recomputed": recomputed,
        },
        "fp_share_check": {
            "range": [config.FP_SHARE_MIN, config.FP_SHARE_MAX],
            "status": fp_status,
            "suggested_threshold_for_min_share": suggestion,
        },
        "alerts": {
            "validation": len(alerts_val),
            "test": len(alerts_test),
            "validation_alerts_hash": val_alert_hash,
            "validation_labels_hash": val_label_hash,
            "test_alerts_hash": test_alert_hash,
            "test_labels_hash": test_label_hash,
        },
        "seed": config.SEED,
    }
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    with open(config.THRESHOLD_PATH, "w") as f:
        json.dump(result, f, indent=2)
    log("")
    log("Saved " + config.THRESHOLD_PATH)
    write_report()

    print("")
    print("Done. Threshold " + repr(threshold) + ", " + str(len(alerts_val)) + " validation alerts, " + str(len(alerts_test)) + " test alerts.")
    print("FP share check: " + fp_status + " (" + "%.4f" % share + "). Report: reports/threshold_report.md")


if __name__ == "__main__":
    main()
