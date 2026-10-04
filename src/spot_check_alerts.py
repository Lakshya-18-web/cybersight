"""30-alert spot check on the DEV set only.

  python src/spot_check_alerts.py             picks 30 dev alerts and writes reports/spot_check_30.md and .csv
  (you fill in human_verdict in the csv: OK, PROBLEM or UNSURE, and notes)
  python src/spot_check_alerts.py --finalize  checks the csv and writes reports/spot_check_summary.json

22 attack alerts (2 per class) and 8 false positives. The frozen set is never opened here.
The card shows the label, because this check is about whether the alert and its label make sense together.
"""
import os
import sys
import json
import zlib
import hashlib
import argparse
import datetime
import numpy as np
import pandas as pd

import config
import eval_io

parser = argparse.ArgumentParser()
parser.add_argument("--finalize", action="store_true")
parser.add_argument("--force", action="store_true", help="overwrite an existing csv (this throws away verdicts)")
args = parser.parse_args()

VERDICTS = ["OK", "PROBLEM", "UNSURE"]


def seed_for(key):
    return (config.SEED + zlib.crc32(("spot|" + key).encode("utf-8"))) % (2 ** 32 - 1)


def pick(merged):
    chosen = []
    attack_classes = sorted([c for c in config.MITRE_MAP if c != "BENIGN"])
    for name in attack_classes:
        pool = merged[merged["label"] == name].sort_values("alert_id")
        take = min(config.SPOT_CHECK_PER_CLASS, len(pool))
        if take == 0:
            continue
        rng = np.random.RandomState(seed_for(name))
        chosen.append(pool.iloc[np.sort(rng.choice(len(pool), size=take, replace=False))])
    pool = merged[merged["label"] == "BENIGN"].sort_values("alert_id")
    rng = np.random.RandomState(seed_for("BENIGN"))
    take = min(config.SPOT_CHECK_BENIGN, len(pool))
    chosen.append(pool.iloc[np.sort(rng.choice(len(pool), size=take, replace=False))])
    picked = pd.concat(chosen, ignore_index=True)
    return picked.sort_values(["is_attack", "label", "alert_id"], ascending=[False, True, True]).reset_index(drop=True)


def evaluate(row, store, store_time):
    failed = []
    label = row["label"]
    weekday = str(row["source_file"]).split("-")[0].strip().capitalize()
    if label != "BENIGN":
        expected = config.EXPECTED_WEEKDAY_BY_LABEL.get(label)
        if expected is None or weekday != expected:
            failed.append("weekday_of_source_file_is_" + weekday + "_expected_" + str(expected))
    stamp = pd.Timestamp(row["timestamp"])
    day = config.DAY_OF_MONTH_BY_WEEKDAY.get(weekday)
    if day is None or (stamp.year, stamp.month, stamp.day) != (config.CAPTURE_YEAR, config.CAPTURE_MONTH, day):
        failed.append("timestamp_date_does_not_match_source_file_day")
    linked = store.loc[store["flow_row"] == row["flow_row"]]
    same = len(linked) == 1
    if same:
        link = linked.iloc[0]
        for column in ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port"]:
            if link[column] != row[column]:
                same = False
        if pd.Timestamp(link["timestamp"]) != stamp:
            same = False
    if not same:
        failed.append("flow_store_row_does_not_match_alert")
    if not float(row["detector_score"]) >= config.ACCEPTED_THRESHOLD:
        failed.append("score_below_accepted_threshold")
    entry = config.MITRE_MAP.get(label)
    if entry is None:
        failed.append("label_not_in_mitre_map")
    else:
        expected_ids = ";".join(entry["accepted"]) if len(entry["accepted"]) > 0 else "NONE"
        if row["mitre_technique_id"] != entry["technique_id"] or row["mitre_accepted_ids"] != expected_ids:
            failed.append("mitre_columns_differ_from_config_map")

    window = pd.Timedelta(minutes=config.SPOT_CHECK_WINDOW_MINUTES)
    near = store[(store["src_ip"] == row["src_ip"]) & (store_time >= stamp - window) & (store_time <= stamp + window)]
    return failed, len(near), int(near["dst_port"].nunique()), int(near["dst_ip"].nunique())


def generate():
    if os.path.exists(config.SPOT_CHECK_CSV) and not args.force:
        print("STOPPED: " + config.SPOT_CHECK_CSV + " already exists. Fill it in, then run with --finalize. (--force starts over and discards verdicts.)")
        sys.exit(1)
    alerts = eval_io.load_alerts("dev")
    labels = eval_io.load_labels("dev")
    store = eval_io.load_flow_store("dev")
    store_time = pd.to_datetime(store["timestamp"])
    merged = alerts.merge(labels, on="alert_id", validate="one_to_one")
    picked = pick(merged)
    if len(picked) != config.SPOT_CHECK_TOTAL:
        print("STOPPED: expected " + str(config.SPOT_CHECK_TOTAL) + " alerts but could pick " + str(len(picked)))
        sys.exit(1)

    forbidden = [c for c in alerts.columns if c in config.FORBIDDEN_ALERT_COLUMNS or c == "source_alert_id"]
    rows = []
    cards = []
    for i, row in picked.iterrows():
        failed, near, ports, targets = evaluate(row, store, store_time)
        rows.append({
            "alert_id": row["alert_id"], "label": row["label"], "is_attack": int(row["is_attack"]), "source_file": row["source_file"],
            "timestamp": str(row["timestamp"]), "src_ip": row["src_ip"], "dst_ip": row["dst_ip"], "dst_port": row["dst_port"],
            "flows_from_same_src_in_window": near, "distinct_dst_ports_in_window": ports, "distinct_dst_ips_in_window": targets,
            "auto_failed": ";".join(failed), "human_verdict": "", "notes": ""})
        card = ["## " + str(i + 1) + ". " + row["alert_id"] + " - " + row["label"], "",
                "- Source file: " + str(row["source_file"]) + " (" + ("false positive of the detector" if row["is_attack"] == 0 else "attack") + ")",
                "- Timestamp " + str(row["timestamp"]) + ", " + str(row["src_ip"]) + ":" + str(row["src_port"]) + " -> " + str(row["dst_ip"]) + ":" + str(row["dst_port"])
                + ", protocol " + str(row["protocol"]) + ", detector score " + "%.5f" % float(row["detector_score"]),
                "- Expected for this label: " + config.CLASS_HINTS[row["label"]],
                "- Context (same source, +/- " + str(config.SPOT_CHECK_WINDOW_MINUTES) + " min, from the dev flow store): " + str(near) + " flows, "
                + str(ports) + " distinct destination ports, " + str(targets) + " distinct destination IPs",
                "- MITRE answer key: " + str(row["mitre_technique_id"]) + " (accepted: " + str(row["mitre_accepted_ids"]) + ")",
                "- Flow features: " + ", ".join([c + " = " + "%.4g" % float(row[c]) for c in config.DISPLAY_FEATURES]),
                "- Automatic checks: " + ("all passed" if len(failed) == 0 else "FAILED: " + ", ".join(failed)),
                "- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)", ""]
        cards.append("\n".join(card))

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    pd.DataFrame(rows).to_csv(config.SPOT_CHECK_CSV, index=False)
    header = ["# Spot check: 30 dev alerts", "",
              "Drawn from the dev set only (seeded). 2 alerts per attack class and 8 detector false positives. The frozen set was not opened.",
              "Alert file has no label columns: " + ("yes" if len(forbidden) == 0 else "NO - " + str(forbidden)) + ".",
              "For each alert decide whether the alert, its label and the context make sense together. Fill human_verdict (OK, PROBLEM or UNSURE) and notes in "
              + os.path.basename(config.SPOT_CHECK_CSV) + ", then run: python src/spot_check_alerts.py --finalize",
              "A PROBLEM means something looks wrong with the data or the label. Do not fix it by editing the frozen files: report it.", ""]
    with open(config.SPOT_CHECK_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(header) + "\n" + "\n".join(cards))
    auto_fail = sum(1 for r in rows if r["auto_failed"] != "")
    print("Wrote " + config.SPOT_CHECK_MD + " and " + config.SPOT_CHECK_CSV)
    print(str(len(rows)) + " alerts, " + str(auto_fail) + " with an automatic check failure.")
    print("Next: review the cards, fill the csv, then run with --finalize.")


def finalize():
    if not os.path.exists(config.SPOT_CHECK_CSV):
        print("STOPPED: no csv yet. Run without --finalize first.")
        sys.exit(1)
    table = pd.read_csv(config.SPOT_CHECK_CSV, keep_default_na=False, dtype=str)
    problems = []
    if len(table) != config.SPOT_CHECK_TOTAL:
        problems.append("the csv has " + str(len(table)) + " rows, expected " + str(config.SPOT_CHECK_TOTAL))
    verdicts = table["human_verdict"].str.strip().str.upper()
    blank = [table.loc[i, "alert_id"] for i in range(len(table)) if verdicts[i] == ""]
    wrong = [table.loc[i, "alert_id"] for i in range(len(table)) if verdicts[i] != "" and verdicts[i] not in VERDICTS]
    if len(blank) > 0:
        problems.append("no verdict yet for: " + ", ".join(blank))
    if len(wrong) > 0:
        problems.append("verdict must be OK, PROBLEM or UNSURE for: " + ", ".join(wrong))
    needs_notes = []
    for i in range(len(table)):
        has_note = table.loc[i, "notes"].strip() != ""
        if (verdicts[i] in ["UNSURE", "PROBLEM"] or table.loc[i, "auto_failed"] != "") and not has_note:
            needs_notes.append(table.loc[i, "alert_id"])
    if len(needs_notes) > 0:
        problems.append("notes are required for UNSURE, PROBLEM and automatically failed alerts: " + ", ".join(needs_notes))
    if len(problems) > 0:
        print("NOT FINALIZED:")
        for p in problems:
            print("- " + p)
        sys.exit(1)

    counts = {v: int((verdicts == v).sum()) for v in VERDICTS}
    auto_failed = [table.loc[i, "alert_id"] for i in range(len(table)) if table.loc[i, "auto_failed"] != ""]
    status = "PASS" if counts["PROBLEM"] == 0 else "FAIL"
    with open(config.SPOT_CHECK_CSV, "rb") as f:
        csv_hash = hashlib.sha256(f.read()).hexdigest()
    summary = {
        "status": status, "alerts_checked": int(len(table)), "set": "dev", "ok": counts["OK"], "unsure": counts["UNSURE"], "problem": counts["PROBLEM"],
        "automatic_check_failures": auto_failed, "problem_ids": [table.loc[i, "alert_id"] for i in range(len(table)) if verdicts[i] == "PROBLEM"],
        "csv_sha256": csv_hash, "finalized_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(config.SPOT_CHECK_SUMMARY, "w") as f:
        json.dump(summary, f, indent=2)
    print("Spot check " + status + ": " + str(counts["OK"]) + " OK, " + str(counts["UNSURE"]) + " unsure, " + str(counts["PROBLEM"]) + " problem, "
          + str(len(auto_failed)) + " with an automatic check failure (explained in notes).")
    print("Wrote " + config.SPOT_CHECK_SUMMARY)
    if status != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    if args.finalize:
        finalize()
    else:
        generate()
