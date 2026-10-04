import json
import math
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score, brier_score_loss
from xgboost import XGBClassifier

import config

WEIGHTING_OPTIONS = ["none", "scale_pos_weight", "class_sqrt"]


def load_features():
    with open(config.FEATURE_LIST_PATH, "r") as f:
        return json.load(f)


def load_split(path, features):
    df = pd.read_parquet(path, columns=features + [config.LABEL_COLUMN])
    labels = df[config.LABEL_COLUMN].to_numpy()
    x = df[features].astype("float32")
    y = (labels != "BENIGN").astype(int)
    return x, y, labels


def make_weights(labels, mode):
    n = len(labels)
    n_attack = int((labels != "BENIGN").sum())
    n_benign = n - n_attack
    if mode == "none":
        return None, 1.0
    if mode == "scale_pos_weight":
        return None, n_benign / n_attack
    if mode == "class_sqrt":
        names = sorted(pd.unique(labels))
        attack_names = [name for name in names if name != "BENIGN"]
        k = len(attack_names)
        weights = np.ones(n)
        for name in attack_names:
            mask = labels == name
            count = int(mask.sum())
            weights[mask] = math.sqrt(n_attack / (k * count))
        return weights, 1.0
    raise ValueError("unknown weighting option: " + str(mode))


def build_model(params, scale_pos_weight):
    return XGBClassifier(
        objective="binary:logistic",
        tree_method="hist",
        eval_metric="aucpr",
        n_estimators=1000,
        early_stopping_rounds=30,
        random_state=config.SEED,
        n_jobs=-1,
        max_depth=int(params["max_depth"]),
        learning_rate=float(params["learning_rate"]),
        subsample=float(params["subsample"]),
        colsample_bytree=float(params["colsample_bytree"]),
        min_child_weight=float(params["min_child_weight"]),
        reg_lambda=float(params["reg_lambda"]),
        scale_pos_weight=float(scale_pos_weight),
    )


def fit_model(params, x_fit, y_fit, labels_fit, x_val, y_val):
    sample_weight, spw = make_weights(labels_fit, params["weighting"])
    model = build_model(params, spw)
    model.fit(x_fit, y_fit, sample_weight=sample_weight, eval_set=[(x_val, y_val)], verbose=False)
    return model


def predict_scores(model, x):
    best = model.best_iteration
    return model.predict_proba(x, iteration_range=(0, best + 1))[:, 1]


def binary_metrics(y, score, threshold):
    predicted = (score >= threshold).astype(int)
    tp = int(((predicted == 1) & (y == 1)).sum())
    fp = int(((predicted == 1) & (y == 0)).sum())
    tn = int(((predicted == 0) & (y == 0)).sum())
    fn = int(((predicted == 0) & (y == 1)).sum())
    precision = 0.0
    if tp + fp > 0:
        precision = tp / (tp + fp)
    recall = 0.0
    if tp + fn > 0:
        recall = tp / (tp + fn)
    f1 = 0.0
    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    fpr = 0.0
    if fp + tn > 0:
        fpr = fp / (fp + tn)
    fp_share = 0.0
    if tp + fp > 0:
        fp_share = fp / (tp + fp)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "alerts_per_1000_flows": 1000.0 * (tp + fp) / len(y),
        "fp_share_of_alerts": fp_share,
    }


def per_class_rates(labels, score, threshold):
    rates = {}
    for name in sorted(pd.unique(labels)):
        mask = labels == name
        flagged = float((score[mask] >= threshold).mean())
        if name == "BENIGN":
            rates[name] = 1.0 - flagged
        else:
            rates[name] = flagged
    return rates


def worst_attack_class(rates):
    worst_name = None
    worst_value = 2.0
    for name in rates:
        if name == "BENIGN":
            continue
        if rates[name] < worst_value:
            worst_value = rates[name]
            worst_name = name
    return worst_name, worst_value


def evaluate(y, score, labels, threshold=0.5):
    rates = per_class_rates(labels, score, threshold)
    worst_name, worst_value = worst_attack_class(rates)
    return {
        "pr_auc": float(average_precision_score(y, score)),
        "roc_auc": float(roc_auc_score(y, score)),
        "brier": float(brier_score_loss(y, score)),
        "threshold": threshold,
        "at_threshold": binary_metrics(y, score, threshold),
        "per_class": rates,
        "worst_attack_class": worst_name,
        "worst_attack_recall": worst_value,
    }
