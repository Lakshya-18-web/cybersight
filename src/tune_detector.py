import os
import sys
import json
import time
import random
import argparse
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

import config
import detector_utils as du

RESULTS_PATH = os.path.join(config.REPORTS_DIR, "tuning_results.csv")
RESULTS_REPORT_PATH = os.path.join(config.REPORTS_DIR, "tuning_results.md")
BEST_PARAMS_PATH = os.path.join(config.MODELS_DIR, "best_params.json")

SPACE = {
    "max_depth": [4, 6, 8, 10, 12],
    "learning_rate": [0.03, 0.05, 0.1, 0.2, 0.3],
    "subsample": [0.6, 0.7, 0.8, 0.9, 1.0],
    "colsample_bytree": [0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    "min_child_weight": [1, 3, 5, 10, 20],
    "reg_lambda": [0.1, 1, 5, 10, 50],
    "weighting": du.WEIGHTING_OPTIONS,
}

TIE_MARGIN = 0.002

parser = argparse.ArgumentParser()
parser.add_argument("--configs", type=int, default=25)
parser.add_argument("--subsample", type=float, default=0.25)
parser.add_argument("--fresh", action="store_true")
args = parser.parse_args()


def make_configs(count):
    rng = random.Random(config.SEED)
    configs = []
    seen = set()
    while len(configs) < count:
        cfg = {}
        for name in SPACE:
            cfg[name] = rng.choice(SPACE[name])
        key = tuple(cfg[name] for name in SPACE)
        if key in seen:
            continue
        seen.add(key)
        configs.append(cfg)
    return configs


def choose_best(rows):
    best_score = max(r["val_pr_auc"] for r in rows)
    near = [r for r in rows if r["val_pr_auc"] >= best_score - TIE_MARGIN]
    rank = {"none": 0, "scale_pos_weight": 1, "class_sqrt": 2}
    near.sort(key=lambda r: (r["max_depth"], r["best_iteration"], rank[r["weighting"]], r["index"]))
    return near[0], near, best_score


def write_report(rows, chosen, near, best_score):
    ordered = sorted(rows, key=lambda r: r["val_pr_auc"], reverse=True)
    lines = []
    lines.append("# Tuning results")
    lines.append("")
    lines.append("Random search, " + str(len(rows)) + " configurations, each fitted on a " + str(int(args.subsample * 100))
                 + "% class-stratified subsample of train. Early stopping (30 rounds, aucpr) and scoring use the full validation split.")
    lines.append("")
    lines.append("## All configurations, best first")
    lines.append("")
    lines.append("| # | depth | lr | subsample | colsample | min child | lambda | weighting | trees | val PR-AUC | worst class | its recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in ordered:
        lines.append("| " + str(r["index"]) + " | " + str(r["max_depth"]) + " | " + str(r["learning_rate"]) + " | " + str(r["subsample"])
                     + " | " + str(r["colsample_bytree"]) + " | " + str(r["min_child_weight"]) + " | " + str(r["reg_lambda"])
                     + " | " + r["weighting"] + " | " + str(r["best_iteration"] + 1) + " | " + "%.5f" % r["val_pr_auc"]
                     + " | " + str(r["worst_class"]) + " | " + "%.4f" % r["worst_class_recall"] + " |")
    lines.append("")
    lines.append("## Weighting options compared")
    lines.append("")
    lines.append("| weighting | configs | mean val PR-AUC | best val PR-AUC | mean worst-class recall | best worst-class recall |")
    lines.append("|---|---|---|---|---|---|")
    for option in du.WEIGHTING_OPTIONS:
        part = [r for r in rows if r["weighting"] == option]
        if len(part) == 0:
            continue
        mean_ap = sum(r["val_pr_auc"] for r in part) / len(part)
        best_ap = max(r["val_pr_auc"] for r in part)
        mean_rec = sum(r["worst_class_recall"] for r in part) / len(part)
        best_rec = max(r["worst_class_recall"] for r in part)
        lines.append("| " + option + " | " + str(len(part)) + " | " + "%.5f" % mean_ap + " | " + "%.5f" % best_ap
                     + " | " + "%.4f" % mean_rec + " | " + "%.4f" % best_rec + " |")
    lines.append("")
    lines.append("## Selection")
    lines.append("")
    lines.append("Best validation PR-AUC: " + "%.5f" % best_score)
    lines.append("Configurations within " + str(TIE_MARGIN) + " of the best: " + str([r["index"] for r in near]))
    lines.append("Tie rule: the simplest wins, meaning smaller max_depth, then fewer trees, then none over scale_pos_weight over class_sqrt.")
    lines.append("")
    lines.append("Chosen configuration #" + str(chosen["index"]) + ": depth " + str(chosen["max_depth"]) + ", lr " + str(chosen["learning_rate"])
                 + ", subsample " + str(chosen["subsample"]) + ", colsample " + str(chosen["colsample_bytree"])
                 + ", min child weight " + str(chosen["min_child_weight"]) + ", lambda " + str(chosen["reg_lambda"])
                 + ", weighting " + chosen["weighting"])
    with open(RESULTS_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")


def main():
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    if args.fresh and os.path.exists(RESULTS_PATH):
        os.remove(RESULTS_PATH)

    features = du.load_features()
    train = pd.read_parquet(config.TRAIN_PATH, columns=features + [config.LABEL_COLUMN])
    labels_all = train[config.LABEL_COLUMN].to_numpy()
    rng = np.random.RandomState(config.SEED)
    picked = []
    for name in sorted(pd.unique(labels_all)):
        positions = np.where(labels_all == name)[0]
        count = max(1, int(round(len(positions) * args.subsample)))
        picked.append(rng.choice(positions, size=count, replace=False))
    picked = np.sort(np.concatenate(picked))
    sub = train.iloc[picked]
    del train
    labels_sub = sub[config.LABEL_COLUMN].to_numpy()
    x_sub = sub[features].astype("float32")
    y_sub = (labels_sub != "BENIGN").astype(int)
    del sub

    x_val, y_val, labels_val = du.load_split(config.VAL_PATH, features)
    print("subsample rows:", len(y_sub), "validation rows:", len(y_val))

    configs = make_configs(args.configs)
    done = set()
    if os.path.exists(RESULTS_PATH):
        old = pd.read_csv(RESULTS_PATH)
        done = set(int(i) for i in old["index"])
        print("already finished:", sorted(done))

    for i in range(len(configs)):
        if i in done:
            continue
        cfg = configs[i]
        start = time.time()
        model = du.fit_model(cfg, x_sub, y_sub, labels_sub, x_val, y_val)
        score = du.predict_scores(model, x_val)
        rates = du.per_class_rates(labels_val, score, 0.5)
        worst_name, worst_value = du.worst_attack_class(rates)
        row = {"index": i}
        for name in SPACE:
            row[name] = cfg[name]
        row["best_iteration"] = int(model.best_iteration)
        row["val_pr_auc"] = float(average_precision_score(y_val, score))
        row["val_roc_auc"] = float(roc_auc_score(y_val, score))
        row["worst_class"] = worst_name
        row["worst_class_recall"] = float(worst_value)
        row["seconds"] = round(time.time() - start, 1)
        header = not os.path.exists(RESULTS_PATH)
        pd.DataFrame([row]).to_csv(RESULTS_PATH, mode="a", header=header, index=False)
        print("config", i, "of", len(configs), "PR-AUC", round(row["val_pr_auc"], 5), "trees", row["best_iteration"] + 1,
              "weighting", cfg["weighting"], "seconds", row["seconds"])

    results = pd.read_csv(RESULTS_PATH)
    results = results[results["index"] < len(configs)]
    rows = results.to_dict("records")
    for r in rows:
        r["index"] = int(r["index"])
        r["max_depth"] = int(r["max_depth"])
        r["best_iteration"] = int(r["best_iteration"])
    chosen, near, best_score = choose_best(rows)

    best = {
        "max_depth": int(chosen["max_depth"]),
        "learning_rate": float(chosen["learning_rate"]),
        "subsample": float(chosen["subsample"]),
        "colsample_bytree": float(chosen["colsample_bytree"]),
        "min_child_weight": float(chosen["min_child_weight"]),
        "reg_lambda": float(chosen["reg_lambda"]),
        "weighting": str(chosen["weighting"]),
        "selection": {
            "config_index": int(chosen["index"]),
            "configs_tried": len(rows),
            "val_pr_auc_on_subsample_fit": float(chosen["val_pr_auc"]),
            "best_pr_auc_among_configs": float(best_score),
            "tie_margin": TIE_MARGIN,
            "configs_within_margin": [int(r["index"]) for r in near],
            "subsample_fraction": args.subsample,
            "seed": config.SEED,
        },
    }
    with open(BEST_PARAMS_PATH, "w") as f:
        json.dump(best, f, indent=2)
    write_report(rows, chosen, near, best_score)

    print("")
    print("Chosen configuration:", chosen["index"], "val PR-AUC", round(chosen["val_pr_auc"], 5))
    print("Saved", BEST_PARAMS_PATH)
    print("Saved", RESULTS_REPORT_PATH)


if __name__ == "__main__":
    main()
