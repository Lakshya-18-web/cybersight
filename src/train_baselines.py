import os
import json
import time
import warnings
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import ConvergenceWarning

import config
import detector_utils as du

warnings.filterwarnings("ignore", category=ConvergenceWarning)

BASELINE_PATH = os.path.join(config.REPORTS_DIR, "baseline_metrics.json")
BASELINE_REPORT_PATH = os.path.join(config.REPORTS_DIR, "baseline_results.md")


def main():
    features = du.load_features()
    print("features:", len(features))

    x_train, y_train, labels_train = du.load_split(config.TRAIN_PATH, features)
    x_val, y_val, labels_val = du.load_split(config.VAL_PATH, features)
    print("train rows:", len(y_train), "attack share:", round(float(y_train.mean()), 4))
    print("val rows:", len(y_val), "attack share:", round(float(y_val.mean()), 4))

    results = {}

    start = time.time()
    scaler = StandardScaler()
    scaler.fit(x_train)
    x_train_scaled = scaler.transform(x_train)
    x_val_scaled = scaler.transform(x_val)
    logistic = LogisticRegression(max_iter=300, random_state=config.SEED)
    logistic.fit(x_train_scaled, y_train)
    score = logistic.predict_proba(x_val_scaled)[:, 1]
    results["logistic_regression"] = du.evaluate(y_val, score, labels_val, 0.5)
    results["logistic_regression"]["iterations_used"] = int(logistic.n_iter_[0])
    results["logistic_regression"]["seconds"] = round(time.time() - start, 1)
    print("logistic regression val PR-AUC:", round(results["logistic_regression"]["pr_auc"], 4))
    del x_train_scaled
    del x_val_scaled

    start = time.time()
    tree = DecisionTreeClassifier(max_depth=12, random_state=config.SEED)
    tree.fit(x_train, y_train)
    score = tree.predict_proba(x_val)[:, 1]
    results["decision_tree"] = du.evaluate(y_val, score, labels_val, 0.5)
    results["decision_tree"]["seconds"] = round(time.time() - start, 1)
    print("decision tree val PR-AUC:", round(results["decision_tree"]["pr_auc"], 4))

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(BASELINE_PATH, "w") as f:
        json.dump(results, f, indent=2)

    lines = []
    lines.append("# Baseline results (validation)")
    lines.append("")
    lines.append("Logistic regression: features scaled with a scaler fitted on train, max_iter 300.")
    lines.append("Decision tree: max_depth 12, no tuning. Both are fitted on the full train split.")
    lines.append("Precision, recall and F1 use a provisional threshold of 0.5. The real threshold is chosen on Day 5.")
    lines.append("")
    lines.append("| model | PR-AUC | ROC-AUC | Brier | precision | recall | F1 | worst attack class | its recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for name in results:
        r = results[name]
        m = r["at_threshold"]
        lines.append("| " + name + " | " + "%.4f" % r["pr_auc"] + " | " + "%.4f" % r["roc_auc"] + " | " + "%.4f" % r["brier"]
                     + " | " + "%.4f" % m["precision"] + " | " + "%.4f" % m["recall"] + " | " + "%.4f" % m["f1"]
                     + " | " + str(r["worst_attack_class"]) + " | " + "%.4f" % r["worst_attack_recall"] + " |")
    lines.append("")
    lines.append("## Per-class rate at threshold 0.5")
    lines.append("")
    lines.append("Attack classes show recall. BENIGN shows specificity (share correctly left unflagged).")
    lines.append("")
    names = list(results["logistic_regression"]["per_class"].keys())
    lines.append("| class | logistic regression | decision tree |")
    lines.append("|---|---|---|")
    for name in names:
        a = results["logistic_regression"]["per_class"][name]
        b = results["decision_tree"]["per_class"][name]
        lines.append("| " + name + " | " + "%.4f" % a + " | " + "%.4f" % b + " |")
    with open(BASELINE_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")

    print("")
    print("Saved", BASELINE_PATH)
    print("Saved", BASELINE_REPORT_PATH)


if __name__ == "__main__":
    main()
