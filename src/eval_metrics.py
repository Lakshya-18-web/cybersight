"""Day 4 metric calculations. Pure functions on one table, no file access, no model calls.

The input is a pandas DataFrame with one row per alert (built by evaluate.py), with these columns:
  alert_id, label, is_attack (bool), accepted_ids (list of str), primary_id (str),
  status (ok / parse_failed / model_error / not_run), has_verdict (bool),
  pred_malicious (True / False / None), pred_attack_type, pred_technique,
  attempts, model_calls, malformed_first_try (True / False / None), error_code, first_try_error,
  prompt_tokens, output_tokens, thinking_tokens, total_tokens, latency_seconds, finish_reasons (list)

Definitions used throughout (they are repeated in the report):
  - Positive class = malicious. A detector alert is a true positive when the flow is an attack.
  - The detector's own decision on every dev alert is "malicious", because every dev alert is a detector alert.
  - "No verdict" = parse_failed, model_error or not_run. It is never turned into a guessed verdict.
  - Every ratio carries its numerator, denominator and population, so no number is shown without its denominator.
"""
import math

import numpy as np
import pandas as pd

NO_VERDICT_STATUSES = ("parse_failed", "model_error", "not_run")
POLICIES = {
    "valid_only": "Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.",
    "failures_escalated": "All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.",
    "failures_wrong": "All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.",
}


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [max(0.0, centre - half), min(1.0, centre + half)]


def ratio(k, n, population):
    k, n = int(k), int(n)
    return {"value": (k / n) if n > 0 else None, "numerator": k, "denominator": n, "wilson95": wilson(k, n), "population": population}


def _rate(k, n):
    return k / n if n > 0 else None


def population_counts(df):
    s = df["status"]
    return {"alerts": int(len(df)), "ok": int((s == "ok").sum()), "parse_failed": int((s == "parse_failed").sum()),
            "model_error": int((s == "model_error").sum()), "not_run": int((s == "not_run").sum()),
            "true_attacks": int(df["is_attack"].sum()), "true_benign": int((~df["is_attack"]).sum())}


def _predicted_positive(df, policy):
    pm = df["pred_malicious"].eq(True)
    if policy == "valid_only":
        return df[df["has_verdict"]], pm[df["has_verdict"]]
    if policy == "failures_escalated":
        return df, pm | ~df["has_verdict"]
    if policy == "failures_wrong":
        return df, pd.Series(np.where(df["has_verdict"], pm, ~df["is_attack"]), index=df.index)
    raise ValueError("unknown policy " + str(policy))


def _confusion(atk, pos):
    return {"tp": int((pos & atk).sum()), "fp": int((pos & ~atk).sum()), "fn": int((~pos & atk).sum()), "tn": int((~pos & ~atk).sum())}


def _scores(c):
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision, recall = _rate(tp, tp + fp), _rate(tp, tp + fn)
    f1 = None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {"precision": ratio(tp, tp + fp, "predicted malicious"), "recall": ratio(tp, tp + fn, "true attacks"),
            "specificity": ratio(tn, tn + fp, "true benign"), "f1": f1}


def verdict_metrics(df):
    """Precision, recall and F1 with malicious as the positive class, for each denominator policy, next to the detector."""
    out = {}
    for policy, text in POLICIES.items():
        pop, pos = _predicted_positive(df, policy)
        atk = pop["is_attack"]
        llm = _confusion(atk, pos)
        detector = _confusion(atk, pd.Series(True, index=pop.index))
        out[policy] = {"definition": text, "alerts_in_population": int(len(pop)), "llm_confusion": llm, "llm": _scores(llm),
                       "detector_confusion": detector, "detector": _scores(detector)}
    return out


def decision_table(df):
    """What the baseline did with each kind of detector alert. Every alert appears in exactly one cell."""
    def cells(mask):
        sub = df[mask]
        return {"kept_as_malicious": int(sub["pred_malicious"].eq(True).sum()), "dismissed_as_benign": int(sub["pred_malicious"].eq(False).sum()),
                "no_verdict": int((~sub["has_verdict"]).sum()), "total": int(len(sub))}
    return {"true_attacks": cells(df["is_attack"]), "true_benign_false_positives": cells(~df["is_attack"])}


def fp_reduction(df):
    """False positives of the detector against the baseline, on comparable alerts, under each policy."""
    out = {}
    for policy, text in POLICIES.items():
        pop, pos = _predicted_positive(df, policy)
        atk = pop["is_attack"]
        det_fp = int((~atk).sum())
        llm_fp = int((pos & ~atk).sum())
        det_alerts, llm_alerts = int(len(pop)), int(pos.sum())
        out[policy] = {
            "definition": text, "alerts_in_population": det_alerts, "benign_alerts_in_population": det_fp,
            "detector_fp": det_fp, "llm_fp": llm_fp, "fp_removed": det_fp - llm_fp,
            "fp_reduction_pct": None if det_fp == 0 else 100.0 * (det_fp - llm_fp) / det_fp,
            "detector_fp_rate_among_benign_alerts": _rate(det_fp, det_fp), "llm_fp_rate_among_benign_alerts": _rate(llm_fp, det_fp),
            "detector_fp_share_of_alerts": _rate(det_fp, det_alerts), "llm_fp_share_of_alerts": _rate(llm_fp, llm_alerts),
            "alerts_raised_detector": det_alerts, "alerts_raised_llm": llm_alerts,
            "alert_volume_reduction_pct": None if det_alerts == 0 else 100.0 * (det_alerts - llm_alerts) / det_alerts,
            "attacks_missed_by_llm": int((~pos & atk).sum()), "attacks_missed_by_detector": 0,
            "benign_dismissal_rate": ratio(det_fp - llm_fp, det_fp, "benign alerts in the population"),
        }
    return out


def attack_type_metrics(df):
    atk = df[df["is_attack"]]
    valid = atk[atk["has_verdict"]]
    flagged = valid[valid["pred_malicious"].eq(True)]
    correct = lambda sub: int((sub["pred_attack_type"] == sub["label"]).sum())
    return {
        "definition": "Exact match of the predicted attack_type with the true class. A benign verdict on an attack counts as wrong.",
        "on_attacks_with_valid_verdict": ratio(correct(valid), len(valid), "true attacks with a valid verdict"),
        "on_attacks_flagged_malicious": ratio(correct(flagged), len(flagged), "true attacks the baseline called malicious"),
        "all_attacks_failures_wrong": ratio(correct(valid), len(atk), "all true attacks (no-verdict attacks count as wrong; lower bound)"),
        "coverage": ratio(len(valid), len(atk), "true attacks with a valid verdict"),
    }


def _in_accepted(row):
    return isinstance(row["pred_technique"], str) and row["pred_technique"] in row["accepted_ids"]


def mitre_metrics(df):
    """Technique accuracy, defined only for true attacks (a benign alert has no technique)."""
    atk = df[df["is_attack"]]
    valid = atk[atk["has_verdict"]]
    flagged = valid[valid["pred_malicious"].eq(True)]
    accepted = lambda sub: int(sub.apply(_in_accepted, axis=1).sum()) if len(sub) else 0
    primary = lambda sub: int((sub["pred_technique"] == sub["primary_id"]).sum()) if len(sub) else 0
    benign = df[~df["is_attack"] & df["has_verdict"]]
    return {
        "definition": ("A predicted technique is correct if it is one of the accepted ids for the true class in the answer key "
                       "(exact id match, no parent/child inference). Only true attacks are scored. A benign verdict gives technique NONE, "
                       "which is never accepted for an attack, so it counts as wrong."),
        "accepted_on_attacks_with_valid_verdict": ratio(accepted(valid), len(valid), "true attacks with a valid verdict"),
        "accepted_on_attacks_flagged_malicious": ratio(accepted(flagged), len(flagged), "true attacks the baseline called malicious"),
        "accepted_all_attacks_failures_wrong": ratio(accepted(valid), len(atk), "all true attacks (no-verdict attacks count as wrong; lower bound)"),
        "primary_on_attacks_with_valid_verdict": ratio(primary(valid), len(valid), "true attacks with a valid verdict (strict: the single primary id)"),
        "coverage": ratio(len(valid), len(atk), "true attacks with a valid verdict"),
        "benign_alerts_given_NONE": ratio(int((benign["pred_technique"] == "NONE").sum()), len(benign), "true benign alerts with a valid verdict (reported apart from MITRE accuracy)"),
    }


def per_class(df, classes):
    rows = []
    for name in classes:
        sub = df[df["label"] == name]
        valid = sub[sub["has_verdict"]]
        is_benign = name == "BENIGN"
        hit = valid["pred_malicious"].eq(False) if is_benign else valid["pred_malicious"].eq(True)
        row = {"label": name, "alerts": int(len(sub)), "valid_verdicts": int(len(valid)), "no_verdict": int(len(sub) - len(valid)),
               "no_verdict_rate": _rate(len(sub) - len(valid), len(sub)),
               "rate_kind": "dismissed as benign (detector false positives)" if is_benign else "called malicious (recall)",
               "hits": int(hit.sum()), "rate": _rate(int(hit.sum()), len(valid)), "wilson95": wilson(int(hit.sum()), len(valid))}
        if not is_benign:
            row["attack_type_correct"] = int((valid["pred_attack_type"] == name).sum())
            row["attack_type_accuracy"] = _rate(row["attack_type_correct"], len(valid))
            row["mitre_accepted"] = int(valid.apply(_in_accepted, axis=1).sum()) if len(valid) else 0
            row["mitre_accuracy"] = _rate(row["mitre_accepted"], len(valid))
        rows.append(row)
    return rows


def attack_type_confusion(df, classes):
    cols = list(classes) + ["no verdict"]
    table = pd.DataFrame(0, index=list(classes), columns=cols)
    for _, r in df.iterrows():
        col = r["pred_attack_type"] if r["has_verdict"] and r["pred_attack_type"] in classes else "no verdict"
        table.loc[r["label"], col] += 1
    table.index.name = "true_label"
    return table


def reliability(df):
    n = len(df)
    replied = df[df["attempts"].fillna(0) >= 1]
    first_bad = int(replied["malformed_first_try"].eq(True).sum())
    first_codes = replied[replied["malformed_first_try"].eq(True)]["first_try_error"].value_counts().to_dict()
    final_codes = df[df["status"] == "parse_failed"]["error_code"].value_counts().to_dict()
    reasons = {}
    for lst in df["finish_reasons"]:
        for r in (lst or []):
            reasons[str(r)] = reasons.get(str(r), 0) + 1
    return {
        "first_try_malformed": ratio(first_bad, len(replied), "alerts that received at least one reply"),
        "first_try_malformed_of_all_alerts": ratio(first_bad, n, "all alerts"),
        "retry_needed": ratio(int((replied["attempts"] > 1).sum()), len(replied), "alerts that received at least one reply"),
        "final_parse_failure": ratio(int((df["status"] == "parse_failed").sum()), n, "all alerts"),
        "model_error": ratio(int((df["status"] == "model_error").sum()), n, "all alerts"),
        "not_run": ratio(int((df["status"] == "not_run").sum()), n, "all alerts"),
        "successful_verdict_coverage": ratio(int(df["has_verdict"].sum()), n, "all alerts"),
        "recovered_by_retry": ratio(int(((df["status"] == "ok") & (df["attempts"] > 1)).sum()), first_bad, "alerts whose first reply was malformed"),
        "model_calls_total": int(df["model_calls"].fillna(0).sum()),
        "model_calls_per_alert_mean": float(df["model_calls"].fillna(0).mean()) if n else None,
        "first_try_error_codes": first_codes, "final_error_codes": final_codes, "finish_reason_counts": reasons,
        "no_verdict_by_true_label": {k: int(v) for k, v in df[~df["has_verdict"]]["label"].value_counts().items()},
    }


def token_totals(df):
    def total(col):
        s = df[col].dropna()
        return int(s.sum()) if len(s) else None
    counted = int(df["total_tokens"].notna().sum())
    parts = [total("prompt_tokens"), total("output_tokens"), total("thinking_tokens")]
    summed = sum(p for p in parts if p is not None) if any(p is not None for p in parts) else None
    return {"prompt_tokens": parts[0], "output_tokens": parts[1], "thinking_tokens": parts[2], "total_tokens": total("total_tokens"),
            "alerts_with_token_counts": counted, "alerts_without_token_counts": int(len(df) - counted),
            "prompt_plus_output_plus_thinking": summed,
            "parts_add_up_to_total": None if summed is None or total("total_tokens") is None else summed == total("total_tokens"),
            "total_tokens_per_alert_mean": float(df["total_tokens"].dropna().mean()) if counted else None}


PRICING_REQUIRED = ["currency", "per_million_input_tokens", "per_million_output_tokens", "thinking_tokens_billed_as", "source", "as_of"]


def validate_pricing(pricing):
    missing = [k for k in PRICING_REQUIRED if pricing.get(k) in (None, "")]
    if missing:
        raise ValueError("pricing file is missing or has empty values for: " + ", ".join(missing))
    if pricing["thinking_tokens_billed_as"] not in ("output", "input", "not_billed"):
        raise ValueError("thinking_tokens_billed_as must be output, input or not_billed")
    for k in ("per_million_input_tokens", "per_million_output_tokens"):
        if not isinstance(pricing[k], (int, float)) or pricing[k] < 0:
            raise ValueError(k + " must be a number of zero or more")
    return pricing


def cost(tokens, pricing):
    if pricing is None:
        return {"available": False, "reason": "No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date."}
    validate_pricing(pricing)
    p_in, p_out = tokens["prompt_tokens"] or 0, tokens["output_tokens"] or 0
    thinking = tokens["thinking_tokens"] or 0
    billed = pricing["thinking_tokens_billed_as"]
    in_tokens = p_in + (thinking if billed == "input" else 0)
    out_tokens = p_out + (thinking if billed == "output" else 0)
    amount = in_tokens / 1e6 * pricing["per_million_input_tokens"] + out_tokens / 1e6 * pricing["per_million_output_tokens"]
    return {"available": True, "currency": pricing["currency"], "total": amount, "per_alert_mean": amount / max(1, tokens["alerts_with_token_counts"]),
            "input_tokens_billed": in_tokens, "output_tokens_billed": out_tokens, "pricing": pricing,
            "note": "Counts only the alerts that have token counts (" + str(tokens["alerts_with_token_counts"]) + "). Alerts whose calls all failed have none."}


def percentile(values, q):
    return float(np.percentile(np.asarray(values, dtype=float), q)) if len(values) else None


def _stats(values):
    return {"n": len(values), "mean": float(np.mean(values)) if len(values) else None, "median": percentile(values, 50), "p95": percentile(values, 95),
            "min": float(np.min(values)) if len(values) else None, "max": float(np.max(values)) if len(values) else None}


def find_latency_anomaly(df, seconds, tolerance=0.05):
    """Alert ids whose recorded latency equals the documented anomaly. The caller requires exactly one."""
    hit = df[(df["latency_seconds"] - seconds).abs() <= tolerance]
    return list(hit["alert_id"])


def latency_stats(df, excluded_ids=(), calls=None):
    """Latency per alert (all of its calls added up) and per call. The raw table is never changed; the excluded
    observations are listed. Statistics are given with and without the exclusion."""
    excluded = set(excluded_ids)
    lat = df.dropna(subset=["latency_seconds"])
    kept = lat[~lat["alert_id"].isin(excluded)]
    out = {"unit": "seconds", "excluded_alert_ids": sorted(excluded), "excluded_values": [float(v) for v in lat[lat["alert_id"].isin(excluded)]["latency_seconds"]],
           "per_alert_all_observations": _stats(list(lat["latency_seconds"])), "per_alert_excluding_anomaly": _stats(list(kept["latency_seconds"]))}
    if calls is not None and len(calls):
        c = calls.dropna(subset=["latency_seconds"])
        drop = pd.Series(False, index=c.index)
        for alert_id in excluded:
            mine = c[c["alert_id"] == alert_id]
            total = float(lat[lat["alert_id"] == alert_id]["latency_seconds"].sum())
            if len(mine) and total > 0:
                big = mine["latency_seconds"].idxmax()
                if mine.loc[big, "latency_seconds"] >= 0.5 * total:
                    drop.loc[big] = True
        out["per_call_all_observations"] = _stats(list(c["latency_seconds"]))
        out["per_call_excluding_anomaly"] = _stats(list(c[~drop]["latency_seconds"]))
        out["excluded_call_count"] = int(drop.sum())
    return out


def build_metrics(df, classes, pricing=None, excluded_latency_ids=(), calls=None):
    tokens = token_totals(df)
    return {
        "population": population_counts(df),
        "reliability": reliability(df),
        "verdict": verdict_metrics(df),
        "decision_table": decision_table(df),
        "fp_reduction": fp_reduction(df),
        "attack_type": attack_type_metrics(df),
        "mitre": mitre_metrics(df),
        "per_class": per_class(df, classes),
        "tokens": tokens,
        "cost": cost(tokens, pricing),
        "latency": latency_stats(df, excluded_latency_ids, calls),
    }
