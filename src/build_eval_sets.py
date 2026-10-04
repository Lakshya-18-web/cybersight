import os
import sys
import json
import math
import zlib
import shutil
import hashlib
import argparse
import subprocess
import datetime
import numpy as np
import pandas as pd

import config

parser = argparse.ArgumentParser()
parser.add_argument("--check-only", action="store_true",
                    help="run every check in memory and write nothing")
parser.add_argument("--force", action="store_true",
                    help="overwrite an existing MANIFEST.json (the old one is kept as MANIFEST.previous.json)")
parser.add_argument("--out-dir", default=config.EVAL_DIR,
                    help="where to write the eval files (default eval/). Use another folder to test reproducibility.")
args = parser.parse_args()

OUT_DIR = args.out_dir
report_lines = []
check_results = []


def log(text=""):
    print(text)
    report_lines.append(text)


def check(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    line = "- " + status + ": " + name
    if detail != "":
        line = line + " (" + detail + ")"
    log(line)
    check_results.append(bool(passed))


def write_report():
    if args.check_only:
        return
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(config.BUILD_REPORT_PATH, "w", encoding="utf-8") as f:
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


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def out_path(default_path):
    return os.path.join(OUT_DIR, os.path.basename(default_path))


def seed_for(set_name, key):
    return (config.SEED + zlib.crc32((set_name + "|" + key).encode("utf-8"))) % (2 ** 32 - 1)


def allocate(limits, total):
    """Share `total` attack alerts across classes as evenly as the per-class limits allow."""
    quota = {name: 0 for name in limits}
    active = sorted([name for name in limits if limits[name] > 0])
    remaining = total
    while remaining > 0 and len(active) > 0:
        base = remaining // len(active)
        extra = remaining % len(active)
        given = 0
        still_open = []
        for i, name in enumerate(active):
            want = base + (1 if i < extra else 0)
            take = min(want, limits[name] - quota[name])
            quota[name] = quota[name] + take
            given = given + take
            if quota[name] < limits[name]:
                still_open.append(name)
        remaining = remaining - given
        if given == 0:
            break
        active = still_open
    return quota, remaining


def draw_set(set_name, data, target, cap):
    """Pick alerts for one evaluation set. Random inside each class, fixed seeds, no use of the detector score."""
    n_fp = int(round(target * config.SET_FP_SHARE))
    n_attack = target - n_fp
    attack = data[data["is_attack"] == 1]
    benign = data[data["is_attack"] == 0]
    classes = sorted(attack["label"].unique())
    available = {name: int((attack["label"] == name).sum()) for name in classes}
    limits = {name: min(cap, available[name]) for name in classes}
    quota, shortfall = allocate(limits, n_attack)

    picked = []
    for name in classes:
        pool = attack[attack["label"] == name].sort_values("alert_id")
        if quota[name] == 0:
            continue
        rng = np.random.RandomState(seed_for(set_name, name))
        positions = rng.choice(len(pool), size=quota[name], replace=False)
        picked.append(pool.iloc[np.sort(positions)])

    fp_pool = benign.sort_values("alert_id")
    fp_take = min(n_fp, len(fp_pool))
    if fp_take > 0:
        rng = np.random.RandomState(seed_for(set_name, "BENIGN"))
        positions = rng.choice(len(fp_pool), size=fp_take, replace=False)
        picked.append(fp_pool.iloc[np.sort(positions)])

    chosen = pd.concat(picked, ignore_index=True).sort_values("alert_id").reset_index(drop=True)
    rng = np.random.RandomState(seed_for(set_name, "shuffle"))
    chosen = chosen.iloc[rng.permutation(len(chosen))].reset_index(drop=True)
    info = {"n_fp_wanted": n_fp, "n_attack_wanted": n_attack, "available": available, "quota": quota,
            "attack_shortfall": shortfall, "fp_available": len(fp_pool), "fp_taken": fp_take}
    return chosen, info


def build_flow_store(split_path, features):
    id_raw = list(config.ALERT_ID_COLUMNS.keys())
    wanted = []
    for col in list(features) + id_raw + ["source_file", "original_row"]:
        if col not in wanted:
            wanted.append(col)
    df = pd.read_parquet(split_path, columns=wanted)
    df = df.sort_values(["Timestamp", "source_file", "original_row"], kind="stable").reset_index(drop=True)
    df["flow_row"] = np.arange(len(df))
    keys = df[["source_file", "original_row", "flow_row"]].copy()
    store = pd.DataFrame({"flow_row": df["flow_row"].values})
    for raw in id_raw:
        store[config.ALERT_ID_COLUMNS[raw]] = df[raw].values
    for col in features:
        if col not in id_raw:
            store[col] = df[col].astype("float32").values
    return store, keys


def mitre_columns(labels):
    tactic, technique, accepted = [], [], []
    for name in labels:
        entry = config.MITRE_MAP[name]
        tactic.append(entry["tactic"])
        technique.append(entry["technique_id"])
        accepted.append(";".join(entry["accepted"]) if len(entry["accepted"]) > 0 else "NONE")
    return tactic, technique, accepted


def finish_set(prefix, chosen, alert_columns, keys):
    chosen = chosen.merge(keys, on=["source_file", "original_row"], how="left", validate="many_to_one")
    ids = [prefix + "-" + "%04d" % (i + 1) for i in range(len(chosen))]
    chosen["source_alert_id"] = chosen["alert_id"]
    chosen["alert_id"] = ids
    alerts = chosen[["alert_id", "flow_row"] + [c for c in alert_columns if c != "alert_id"]].copy()
    tactic, technique, accepted = mitre_columns(chosen["label"].tolist())
    labels = pd.DataFrame({
        "alert_id": ids,
        "label": chosen["label"].values,
        "is_attack": chosen["is_attack"].values,
        "mitre_tactic": tactic,
        "mitre_technique_id": technique,
        "mitre_accepted_ids": accepted,
        "source_alert_id": chosen["source_alert_id"].values,
        "source_file": chosen["source_file"].values,
        "original_row": chosen["original_row"].values,
    })
    return alerts, labels


def check_set(name, alerts, labels, store, info, target, min_per_class, cap):
    check(name + ": size is " + str(target), len(alerts) == target, str(len(alerts)))
    check(name + ": every attack class could be filled to its share",
          info["attack_shortfall"] == 0 and info["fp_taken"] == info["n_fp_wanted"],
          "attack shortfall " + str(info["attack_shortfall"]) + ", FP available " + str(info["fp_available"])
          + " needed " + str(info["n_fp_wanted"]))
    fp_count = int((labels["is_attack"] == 0).sum())
    share = fp_count / max(1, len(labels))
    check(name + ": false positive share is inside " + str(config.FP_SHARE_MIN) + " to " + str(config.FP_SHARE_MAX),
          config.FP_SHARE_MIN <= share <= config.FP_SHARE_MAX, "%.4f" % share + " (" + str(fp_count) + " of " + str(len(labels)) + ")")
    counts = labels[labels["is_attack"] == 1]["label"].value_counts()
    expected_classes = sorted([c for c in config.MITRE_MAP if c != "BENIGN"])
    missing = [c for c in expected_classes if c not in counts.index]
    check(name + ": all " + str(len(expected_classes)) + " attack classes are present", len(missing) == 0, str(missing))
    thin = [c for c in counts.index if counts[c] < min_per_class]
    check(name + ": every attack class has at least " + str(min_per_class) + " alerts", len(thin) == 0,
          str(thin) + (" - too few alerts in that class. Lower MIN_" + name.upper() + "_PER_CLASS in config.py only if you accept wider uncertainty for it, and say so in the report" if len(thin) > 0 else ""))
    over = [c for c in counts.index if counts[c] > cap]
    check(name + ": no class is above its cap of " + str(cap), len(over) == 0, str(over))
    check(name + ": alert ids are unique", alerts["alert_id"].is_unique)
    check(name + ": alert file and label file have the same ids in the same order",
          list(alerts["alert_id"]) == list(labels["alert_id"]))
    bad_columns = [c for c in alerts.columns if c in config.FORBIDDEN_ALERT_COLUMNS or c == "source_alert_id"]
    check(name + ": alert file has no label, file name, row number or source alert id", len(bad_columns) == 0, str(bad_columns))
    stamps = pd.to_datetime(alerts["timestamp"])
    check(name + ": rows are shuffled, not in time order", not stamps.is_monotonic_increasing)
    check(name + ": every label has a MITRE entry", all(l in config.MITRE_MAP for l in labels["label"].unique()))
    linked = store.set_index("flow_row").loc[alerts["flow_row"].values]
    same = True
    for column in ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port"]:
        if not (linked[column].values == alerts[column].values).all():
            same = False
    check(name + ": every alert points to the matching row in the flow store", same)
    nan_columns = [c for c in alerts.columns if alerts[c].isna().any()]
    check(name + ": no missing values in the alert file", len(nan_columns) == 0, str(nan_columns))


def write_mitre_csv(path):
    rows = []
    for name in sorted(config.MITRE_MAP):
        entry = config.MITRE_MAP[name]
        rows.append({
            "label": name, "tactic": entry["tactic"], "technique_id": entry["technique_id"],
            "technique_name": entry["technique_name"],
            "accepted_ids": ";".join(entry["accepted"]) if len(entry["accepted"]) > 0 else "NONE",
            "note": entry["note"]})
    pd.DataFrame(rows).to_csv(path, index=False)


def git_commit():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=config.PROJECT_ROOT, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def composition_table(name, labels, info):
    log("")
    log("### " + name + " composition")
    log("")
    log("| class | Day 5 alerts available | selected |")
    log("|---|---|---|")
    counts = labels["label"].value_counts()
    for cls in sorted(info["available"]):
        log("| " + cls + " | " + str(info["available"][cls]) + " | " + str(int(counts.get(cls, 0))) + " |")
    log("| BENIGN (false positives) | " + str(info["fp_available"]) + " | " + str(int(counts.get("BENIGN", 0))) + " |")


def write_dataset_card(path, manifest, dev_labels, frozen_labels, threshold_info):
    dev_counts = dev_labels["label"].value_counts()
    frozen_counts = frozen_labels["label"].value_counts()
    classes = [c for c in sorted(config.MITRE_MAP) if c != "BENIGN"]
    val = threshold_info["validation"]
    lines = []
    lines.append("# Dataset card: SOC triage evaluation sets")
    lines.append("")
    lines.append("Two sets of detector alerts, one for development (dev) and one for the final numbers (frozen), built from CIC-IDS2017.")
    lines.append("")
    lines.append("## Source")
    lines.append("")
    lines.append("- CIC-IDS2017, Canadian Institute for Cybersecurity, University of New Brunswick. Labelled network flows captured Monday 3 July to Friday 7 July 2017.")
    lines.append("- Reference: Sharafaldin, Lashkari, Ghorbani. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018.")
    lines.append("- Cleaning (Day 2): empty rows, label text repair, timestamp repair, NaN and inf rows, exact and feature-vector duplicates removed. "
                 "Infiltration and Heartbleed dropped (too few flows). Web Attack XSS and SQL injection merged into one class. See reports/cleaning_log.md.")
    lines.append("- Split (Day 3): inside every (source file, label) group in time order, 60% train, 20% validation, 20% test, with 1% gap rows dropped at each boundary.")
    lines.append("")
    lines.append("## How the alerts were made")
    lines.append("")
    lines.append("- Detector: XGBoost, " + str(threshold_info["n_features"]) + " features, Destination Port " +
                 ("used" if threshold_info["uses_destination_port"] else "not used") + ", trained on the train split only.")
    lines.append("- Alert rule: detector score >= " + repr(threshold_info["threshold"]) + " (accepted at the end of Day 5).")
    lines.append("- The threshold is the highest one with pooled validation recall >= " + str(config.TARGET_RECALL) + " and validation false positive share >= "
                 + str(config.FP_SHARE_MIN) + ". The first rule (recall only) gave a threshold that missed most of the small attack classes and left almost no false positives, so it was replaced.")
    lines.append("- On the full validation split at this threshold: recall " + "%.4f" % val["recall"] + ", precision " + "%.4f" % val["precision"] + ", "
                 + str(val["alerts"]) + " alerts of which " + str(val["fp"]) + " are false positives. The worst attack class is " + str(val["worst_attack_class"])
                 + " with recall " + "%.4f" % val["worst_attack_recall"] + ".")
    lines.append("")
    lines.append("## How the sets were built")
    lines.append("")
    lines.append("- Dev set: " + str(len(dev_labels)) + " alerts sampled from the validation-split alerts. Frozen set: " + str(len(frozen_labels))
                 + " alerts sampled from the test-split alerts. Dev and frozen never share a flow.")
    lines.append("- False positives are " + str(int(config.SET_FP_SHARE * 100)) + "% of each set by design. Attack alerts are shared across the " + str(len(classes))
                 + " attack classes as evenly as the number of available alerts allows (caps: " + str(config.DEV_CAP_PER_CLASS) + " per class dev, "
                 + str(config.FROZEN_CAP_PER_CLASS) + " per class frozen).")
    lines.append("- Inside each class and for the false positives, alerts are drawn uniformly at random with fixed seeds. The detector score is not used to choose alerts. Rows are shuffled and given new ids, so the id order says nothing about time or class.")
    lines.append("- Labels, MITRE answers, source file names and row numbers are only in the *_labels.parquet files. The alert files carry none of them.")
    lines.append("- The frozen set was built and frozen on Week 1, Day 6 and stays closed to tuning and development. Reads go through src/eval_io.py, which logs every frozen access.")
    lines.append("")
    lines.append("## Composition")
    lines.append("")
    lines.append("| class | dev | frozen |")
    lines.append("|---|---|---|")
    for cls in classes:
        lines.append("| " + cls + " | " + str(int(dev_counts.get(cls, 0))) + " | " + str(int(frozen_counts.get(cls, 0))) + " |")
    lines.append("| BENIGN (detector false positives) | " + str(int(dev_counts.get("BENIGN", 0))) + " | " + str(int(frozen_counts.get("BENIGN", 0))) + " |")
    lines.append("| total | " + str(len(dev_labels)) + " | " + str(len(frozen_labels)) + " |")
    lines.append("")
    lines.append("## Files")
    lines.append("")
    lines.append("- *_alerts.parquet: alert_id, flow_row, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score and 12 flow features.")
    lines.append("- *_labels.parquet: label, is_attack, MITRE tactic, technique and accepted ids, source alert id, source file, row number. Read only by the evaluation harness.")
    lines.append("- flow_store_dev.parquet and flow_store_frozen.parquet: every flow of the validation or test split without labels, for the agent's flow log tool. flow_row links an alert to its flow.")
    lines.append("- mitre_map.csv: answer key from class to ATT&CK technique. Never given to the agent or to its MITRE lookup tool.")
    lines.append("- MANIFEST.json: content hashes of every file, the threshold, the seed and the sizes.")
    lines.append("")
    lines.append("## Known limitations")
    lines.append("")
    lines.append("- The traffic is generated in a lab on a fixed weekly schedule. Attacker and victim IP addresses and attack times are well known for this dataset, so a language model may recognise attacks from them rather than from the traffic. An IP and time masked ablation is planned.")
    lines.append("- CIC-IDS2017 has documented flow-construction and labelling problems (for example Engelen, Rimmer, Joosen, 2021). Some labels are noisy.")
    lines.append("- Sets are class-balanced samples with a built-in " + str(int(config.SET_FP_SHARE * 100)) + "% false positive share. They do not show real attack prevalence. "
                 "Any false positive reduction is measured against this mix and must be reported with the detector's natural precision (" + "%.2f" % val["precision"] + " at this threshold).")
    lines.append("- The threshold is low, so the alert stream is large (" + str(val["alerts"]) + " validation alerts). That is a design choice to keep small classes visible, not an operating recommendation.")
    lines.append("- Small classes have few alerts. Per-class results for them rest on a few dozen alerts and carry wide uncertainty.")
    lines.append("- MITRE labels are one reasonable mapping per class, with a list of accepted ids. DoS variants share one technique and the DDoS mapping is a judgment call. See mitre_map.csv.")
    lines.append("- The detector score is part of every alert, so the agent sees what the detector thought. Alerts with high scores are mostly true positives, and the false positives sit at low scores. A score-masked ablation shows how much the agent leans on it.")
    lines.append("- One fixed seed (" + str(config.SEED) + ") and one draw. No resampling variance is reported.")
    lines.append("")
    lines.append("## Integrity")
    lines.append("")
    lines.append("Run python src/verify_eval.py to compare every file with MANIFEST.json.")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")


def main():
    log("# Evaluation set build report")
    log("")
    if args.check_only:
        log("Mode: check only. Nothing is written.")
    log("Output folder: " + OUT_DIR)
    manifest_path = out_path(config.MANIFEST_PATH)
    if os.path.exists(manifest_path) and not args.check_only and not args.force:
        stop_here(manifest_path + " already exists. The frozen set must not change silently. Use --force to rebuild, or --out-dir to build somewhere else and compare.")

    log("")
    log("## Inputs from Day 5")
    log("")
    needed = [config.THRESHOLD_PATH, config.ALERTS_VAL_PATH, config.ALERTS_VAL_LABELS_PATH, config.ALERTS_TEST_PATH,
              config.ALERTS_TEST_LABELS_PATH, config.VAL_PATH, config.TEST_PATH, config.FEATURE_LIST_PATH]
    absent = [p for p in needed if not os.path.exists(p)]
    if len(absent) > 0:
        stop_here("missing input files: " + ", ".join(absent))
    with open(config.THRESHOLD_PATH, "r") as f:
        threshold_info = json.load(f)
    with open(config.FEATURE_LIST_PATH, "r") as f:
        features = json.load(f)

    check("threshold.json holds the accepted threshold " + repr(config.ACCEPTED_THRESHOLD),
          math.isclose(threshold_info["threshold"], config.ACCEPTED_THRESHOLD, rel_tol=1e-12, abs_tol=0.0),
          repr(threshold_info["threshold"]))
    check("validation alert count is " + str(config.ACCEPTED_VAL_ALERTS),
          threshold_info["validation"]["alerts"] == config.ACCEPTED_VAL_ALERTS, str(threshold_info["validation"]["alerts"]))
    check("validation false positive count is " + str(config.ACCEPTED_VAL_FP),
          threshold_info["validation"]["fp"] == config.ACCEPTED_VAL_FP, str(threshold_info["validation"]["fp"]))
    check("threshold.json recall target was met", threshold_info["validation"]["recall"] >= config.TARGET_RECALL)

    alerts_val = pd.read_parquet(config.ALERTS_VAL_PATH)
    labels_val = pd.read_parquet(config.ALERTS_VAL_LABELS_PATH)
    alerts_test = pd.read_parquet(config.ALERTS_TEST_PATH)
    labels_test = pd.read_parquet(config.ALERTS_TEST_LABELS_PATH)
    recorded = threshold_info["alerts"]
    inputs_ok = (content_hash(alerts_val) == recorded["validation_alerts_hash"]
                 and content_hash(labels_val) == recorded["validation_labels_hash"]
                 and content_hash(alerts_test) == recorded["test_alerts_hash"]
                 and content_hash(labels_test) == recorded["test_labels_hash"])
    check("the four Day 5 alert files match the hashes recorded in threshold.json", inputs_ok)
    check("Day 5 alert counts match threshold.json",
          len(alerts_val) == recorded["validation"] and len(alerts_test) == recorded["test"],
          str(len(alerts_val)) + " validation, " + str(len(alerts_test)) + " test")
    if not all(check_results):
        stop_here("the Day 5 inputs are not the accepted ones. Nothing was built.")

    alert_columns = list(alerts_val.columns)
    dev_data = alerts_val.merge(labels_val, on="alert_id", how="inner", validate="one_to_one")
    test_data = alerts_test.merge(labels_test, on="alert_id", how="inner", validate="one_to_one")
    check("alert and label files join one to one", len(dev_data) == len(alerts_val) and len(test_data) == len(alerts_test))

    log("")
    log("## Sampling")
    log("")
    log("Seed " + str(config.SEED) + ". Targets: dev " + str(config.DEV_TARGET_SIZE) + ", frozen " + str(config.FROZEN_TARGET_SIZE)
        + ", false positive share " + str(config.SET_FP_SHARE) + ".")
    dev_chosen, dev_info = draw_set("dev", dev_data, config.DEV_TARGET_SIZE, config.DEV_CAP_PER_CLASS)
    frozen_chosen, frozen_info = draw_set("frozen", test_data, config.FROZEN_TARGET_SIZE, config.FROZEN_CAP_PER_CLASS)
    again, ignore = draw_set("dev", dev_data, config.DEV_TARGET_SIZE, config.DEV_CAP_PER_CLASS)
    again_frozen, ignore = draw_set("frozen", test_data, config.FROZEN_TARGET_SIZE, config.FROZEN_CAP_PER_CLASS)
    check("sampling is deterministic (two draws give the same alerts in the same order)",
          list(again["alert_id"]) == list(dev_chosen["alert_id"]) and list(again_frozen["alert_id"]) == list(frozen_chosen["alert_id"]))

    log("")
    log("## Flow stores")
    dev_store, dev_keys = build_flow_store(config.VAL_PATH, features)
    frozen_store, frozen_keys = build_flow_store(config.TEST_PATH, features)
    log("")
    log("Dev flow store (validation split): " + str(len(dev_store)) + " flows. Frozen flow store (test split): " + str(len(frozen_store)) + " flows.")
    forbidden_store = [c for c in list(dev_store.columns) + list(frozen_store.columns) if c in config.FORBIDDEN_ALERT_COLUMNS]
    check("flow stores have no label, file name or row number column", len(forbidden_store) == 0, str(forbidden_store))
    check("flow stores are 'flow_row' indexed 0..n-1 in time order",
          bool((dev_store["flow_row"].values == np.arange(len(dev_store))).all())
          and bool((frozen_store["flow_row"].values == np.arange(len(frozen_store))).all()))

    dev_alerts, dev_labels = finish_set("DEV", dev_chosen, alert_columns, dev_keys)
    frozen_alerts, frozen_labels = finish_set("FRZ", frozen_chosen, alert_columns, frozen_keys)
    check("every selected alert found its flow in the flow store",
          not dev_alerts["flow_row"].isna().any() and not frozen_alerts["flow_row"].isna().any())
    if not all(check_results):
        stop_here("alerts could not be linked to the flow stores. Nothing was written.")
    dev_alerts["flow_row"] = dev_alerts["flow_row"].astype("int64")
    frozen_alerts["flow_row"] = frozen_alerts["flow_row"].astype("int64")

    log("")
    log("## Checks: dev set")
    log("")
    check_set("dev", dev_alerts, dev_labels, dev_store, dev_info, config.DEV_TARGET_SIZE, config.MIN_DEV_PER_CLASS, config.DEV_CAP_PER_CLASS)
    log("")
    log("## Checks: frozen set")
    log("")
    check_set("frozen", frozen_alerts, frozen_labels, frozen_store, frozen_info, config.FROZEN_TARGET_SIZE,
              config.MIN_FROZEN_PER_CLASS, config.FROZEN_CAP_PER_CLASS)

    log("")
    log("## Checks: dev versus frozen")
    log("")
    dev_keys_set = set(zip(dev_labels["source_file"], dev_labels["original_row"]))
    frozen_keys_set = set(zip(frozen_labels["source_file"], frozen_labels["original_row"]))
    check("dev and frozen share no flow", len(dev_keys_set & frozen_keys_set) == 0, str(len(dev_keys_set & frozen_keys_set)) + " shared")
    check("dev alerts all come from validation and frozen alerts all from test",
          dev_labels["source_alert_id"].str.startswith("VAL-").all() and frozen_labels["source_alert_id"].str.startswith("TEST-").all())
    check("dev and frozen share no alert id", len(set(dev_labels["alert_id"]) & set(frozen_labels["alert_id"])) == 0)
    dev_time = pd.to_datetime(dev_store["timestamp"])
    frozen_time = pd.to_datetime(frozen_store["timestamp"])
    log("- Info: dev flows span " + str(dev_time.min()) + " to " + str(dev_time.max()) + "; frozen flows span "
        + str(frozen_time.min()) + " to " + str(frozen_time.max()) + ". Splits were made inside each (file, label) group, so the ranges overlap by design.")

    composition_table("Dev", dev_labels, dev_info)
    composition_table("Frozen", frozen_labels, frozen_info)

    if not all(check_results):
        stop_here("at least one check failed. Nothing was written.")

    if args.check_only:
        log("")
        log("All checks passed. Check-only mode: nothing was written.")
        print("")
        print("Check-only run finished. Run again without --check-only to build the files.")
        return

    os.makedirs(OUT_DIR, exist_ok=True)
    if os.path.exists(manifest_path) and args.force:
        shutil.copy2(manifest_path, os.path.join(OUT_DIR, "MANIFEST.previous.json"))

    paths = {
        "dev_alerts": out_path(config.DEV_ALERTS_PATH), "dev_labels": out_path(config.DEV_LABELS_PATH),
        "frozen_alerts": out_path(config.FROZEN_ALERTS_PATH), "frozen_labels": out_path(config.FROZEN_LABELS_PATH),
        "flow_store_dev": out_path(config.FLOW_STORE_DEV_PATH), "flow_store_frozen": out_path(config.FLOW_STORE_FROZEN_PATH),
    }
    frames = {
        "dev_alerts": dev_alerts, "dev_labels": dev_labels, "frozen_alerts": frozen_alerts, "frozen_labels": frozen_labels,
        "flow_store_dev": dev_store, "flow_store_frozen": frozen_store,
    }
    for key in paths:
        frames[key].to_parquet(paths[key], index=False)
    mitre_path = out_path(config.MITRE_MAP_PATH)
    write_mitre_csv(mitre_path)

    files = {}
    log("")
    log("## Written files")
    log("")
    log("| file | rows | content hash (first 16) |")
    log("|---|---|---|")
    for key in paths:
        back = pd.read_parquet(paths[key])
        same_rows = len(back) == len(frames[key])
        check(key + ": file reads back with the same row count", same_rows)
        files[key] = {"file": os.path.basename(paths[key]), "rows": int(len(back)), "content_hash": content_hash(back),
                      "file_sha256": file_sha256(paths[key])}
        log("| " + files[key]["file"] + " | " + str(files[key]["rows"]) + " | " + files[key]["content_hash"][:16] + " |")
    files["mitre_map"] = {"file": os.path.basename(mitre_path), "rows": len(config.MITRE_MAP), "content_hash": None,
                          "file_sha256": file_sha256(mitre_path)}
    log("| " + files["mitre_map"]["file"] + " | " + str(files["mitre_map"]["rows"]) + " | sha256 " + files["mitre_map"]["file_sha256"][:16] + " |")

    manifest = {
        "built_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": git_commit(),
        "seed": config.SEED,
        "threshold": threshold_info["threshold"],
        "sizes": {"dev_target": config.DEV_TARGET_SIZE, "frozen_target": config.FROZEN_TARGET_SIZE, "fp_share": config.SET_FP_SHARE,
                  "dev_cap_per_class": config.DEV_CAP_PER_CLASS, "frozen_cap_per_class": config.FROZEN_CAP_PER_CLASS},
        "inputs": {
            "validation_alerts_hash": recorded["validation_alerts_hash"], "validation_labels_hash": recorded["validation_labels_hash"],
            "test_alerts_hash": recorded["test_alerts_hash"], "test_labels_hash": recorded["test_labels_hash"]},
        "composition": {
            "dev": {k: int(v) for k, v in dev_labels["label"].value_counts().sort_index().items()},
            "frozen": {k: int(v) for k, v in frozen_labels["label"].value_counts().sort_index().items()}},
        "files": files,
        "frozen_rule": "Frozen alerts, labels and flow store were frozen on Week 1, Day 6. Read them only for the final evaluation runs, through src/eval_io.py.",
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    log("")
    log("Saved " + manifest_path)

    card_path = out_path(config.DATASET_CARD_PATH)
    write_dataset_card(card_path, manifest, dev_labels, frozen_labels, threshold_info)
    log("Saved " + card_path)

    if not all(check_results):
        stop_here("a written file did not read back correctly.")
    write_report()
    print("")
    print("Done. Dev " + str(len(dev_alerts)) + " alerts, frozen " + str(len(frozen_alerts)) + " alerts. Report: reports/eval_build_report.md")
    print("Next: python src/verify_eval.py")


if __name__ == "__main__":
    main()
