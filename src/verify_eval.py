import os
import sys
import json
import hashlib
import argparse
import pandas as pd

import config

parser = argparse.ArgumentParser()
parser.add_argument("--dir", default=config.EVAL_DIR, help="folder with the eval files to check (default eval/)")
parser.add_argument("--manifest", default=config.MANIFEST_PATH, help="manifest to compare against (default eval/MANIFEST.json)")
parser.add_argument("--skip-flow-stores", action="store_true", help="skip the two large flow store files")
args = parser.parse_args()

results = []


def check(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    line = "- " + status + ": " + name
    if detail != "":
        line = line + " (" + detail + ")"
    print(line)
    results.append(bool(passed))


def content_hash(df):
    row_hashes = pd.util.hash_pandas_object(df, index=False).values
    return hashlib.sha256(row_hashes.tobytes()).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    print("# Evaluation set integrity check")
    print("")
    print("Folder: " + args.dir)
    print("Manifest: " + args.manifest)
    print("This is an integrity check only. It hashes the files and prints no labels and no results.")
    print("")
    if not os.path.exists(args.manifest):
        print("STOPPED: manifest not found.")
        sys.exit(1)
    with open(args.manifest, "r") as f:
        manifest = json.load(f)

    print("## Inputs")
    print("")
    if os.path.exists(config.THRESHOLD_PATH):
        with open(config.THRESHOLD_PATH, "r") as f:
            recorded = json.load(f)["alerts"]
        for key in ["validation_alerts_hash", "validation_labels_hash", "test_alerts_hash", "test_labels_hash"]:
            check("Day 5 " + key + " matches the manifest", recorded[key] == manifest["inputs"][key])
        check("threshold matches the manifest", json.load(open(config.THRESHOLD_PATH))["threshold"] == manifest["threshold"],
              repr(manifest["threshold"]))
    else:
        check("models/threshold.json exists", False)

    print("")
    print("## Files")
    print("")
    frames = {}
    for key in manifest["files"]:
        entry = manifest["files"][key]
        path = os.path.join(args.dir, entry["file"])
        if args.skip_flow_stores and key.startswith("flow_store"):
            print("- SKIP: " + entry["file"])
            continue
        if not os.path.exists(path):
            check(entry["file"] + " exists", False)
            continue
        if entry["content_hash"] is None:
            check(entry["file"] + " is byte-identical to the manifest", file_sha256(path) == entry["file_sha256"])
            continue
        df = pd.read_parquet(path)
        frames[key] = df
        check(entry["file"] + " has " + str(entry["rows"]) + " rows", len(df) == entry["rows"], str(len(df)))
        check(entry["file"] + " content hash matches", content_hash(df) == entry["content_hash"])
        if file_sha256(path) != entry["file_sha256"]:
            print("  note: the file bytes differ from the manifest but the content matches. Different library versions can do that.")

    print("")
    print("## Structure")
    print("")
    for name in ["dev", "frozen"]:
        if name + "_alerts" in frames and name + "_labels" in frames:
            alerts = frames[name + "_alerts"]
            labels = frames[name + "_labels"]
            check(name + ": alert and label ids match in order", list(alerts["alert_id"]) == list(labels["alert_id"]))
            bad = [c for c in alerts.columns if c in config.FORBIDDEN_ALERT_COLUMNS or c == "source_alert_id"]
            check(name + ": alert file has no label, file name, row number or source alert id", len(bad) == 0, str(bad))
    if "dev_labels" in frames and "frozen_labels" in frames:
        dev_keys = set(zip(frames["dev_labels"]["source_file"], frames["dev_labels"]["original_row"]))
        frozen_keys = set(zip(frames["frozen_labels"]["source_file"], frames["frozen_labels"]["original_row"]))
        check("dev and frozen share no flow", len(dev_keys & frozen_keys) == 0)
    for key in frames:
        if key.startswith("flow_store"):
            bad = [c for c in frames[key].columns if c in config.FORBIDDEN_ALERT_COLUMNS]
            check(key + ": no label, file name or row number column", len(bad) == 0, str(bad))

    log_path = config.FROZEN_ACCESS_LOG
    print("")
    print("## Frozen access log")
    print("")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [line for line in f.read().splitlines() if line.strip() != ""]
        print(str(len(lines)) + " recorded reads of the frozen set.")
        for line in lines:
            print("  " + line)
    else:
        print("0 recorded reads. The frozen set has not been opened through eval_io.py.")

    print("")
    if all(results):
        print("All checks passed.")
    else:
        print("INTEGRITY FAILED: at least one check did not pass.")
        sys.exit(1)


if __name__ == "__main__":
    main()
