import os
import sys
import numpy as np
import pandas as pd

import config

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
    with open(config.SPLIT_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
        f.write("\n")


def hash_rows(df, columns):
    return pd.util.hash_pandas_object(df[columns], index=False).values


def main():
    label = config.LABEL_COLUMN
    df = pd.read_parquet(config.CLEAN_PATH)
    feature_cols = [c for c in df.columns if c not in config.NON_FEATURE_COLUMNS]

    log("# Split report")
    log("")
    log("Input: " + config.CLEAN_PATH)
    log("Rows: " + str(len(df)))
    log("Feature columns used for duplicate checks: " + str(len(feature_cols)))
    log("Split inside every (source file, label) group, in time order: "
        + str(int(config.TRAIN_FRACTION * 100)) + "% train, "
        + str(int(config.VAL_FRACTION * 100)) + "% validation, "
        + str(int(config.TEST_FRACTION * 100)) + "% test")
    log("Gap rows dropped after each boundary: " + str(config.BOUNDARY_TRIM_FRACTION * 100) + "% of the group")

    df = df.sort_values(["source_file", label, "Timestamp", "original_row"], kind="stable").reset_index(drop=True)

    split = np.full(len(df), "gap", dtype=object)
    groups = df.groupby(["source_file", label], sort=False).indices
    group_table = []
    for key in groups:
        positions = np.sort(groups[key])
        n = len(positions)
        gap = int(round(config.BOUNDARY_TRIM_FRACTION * n))
        train_end = int(round(n * config.TRAIN_FRACTION))
        val_end = int(round(n * (config.TRAIN_FRACTION + config.VAL_FRACTION)))
        val_start = min(train_end + gap, val_end)
        test_start = min(val_end + gap, n)
        split[positions[:train_end]] = "train"
        split[positions[val_start:val_end]] = "val"
        split[positions[test_start:]] = "test"
        n_train = train_end
        n_val = val_end - val_start
        n_test = n - test_start
        group_table.append((key[0], key[1], n, n_train, n_val, n_test, n - n_train - n_val - n_test))

    df["split"] = split
    train = df[df["split"] == "train"].drop(columns=["split"])
    val = df[df["split"] == "val"].drop(columns=["split"])
    test = df[df["split"] == "test"].drop(columns=["split"])
    gap_rows = int((df["split"] == "gap").sum())

    log("")
    log("## Rows per split")
    log("")
    log("| split | rows | share of kept rows | attack share | first time | last time |")
    log("|---|---|---|---|---|---|")
    kept_total = len(train) + len(val) + len(test)
    for name, part in [("train", train), ("val", val), ("test", test)]:
        attack_share = 100.0 * float((part[label] != "BENIGN").sum()) / len(part)
        share = 100.0 * len(part) / kept_total
        log("| " + name + " | " + str(len(part)) + " | " + "%.1f" % share + "% | " + "%.1f" % attack_share + "% | "
            + str(part["Timestamp"].min()) + " | " + str(part["Timestamp"].max()) + " |")
    log("")
    log("Gap rows dropped at boundaries: " + str(gap_rows))

    classes = sorted(df[label].unique())
    log("")
    log("## Rows per class per split")
    log("")
    log("| label | train | val | test | gap dropped | total |")
    log("|---|---|---|---|---|---|")
    class_counts = {}
    for name in classes:
        a = int((train[label] == name).sum())
        b = int((val[label] == name).sum())
        c = int((test[label] == name).sum())
        total = int((df[label] == name).sum())
        class_counts[name] = (a, b, c)
        log("| " + name + " | " + str(a) + " | " + str(b) + " | " + str(c) + " | " + str(total - a - b - c) + " | " + str(total) + " |")

    log("")
    log("## Rows per (source file, label) group")
    log("")
    log("| source file | label | rows | train | val | test | gap |")
    log("|---|---|---|---|---|---|---|")
    for row in group_table:
        log("| " + " | ".join([str(x) for x in row]) + " |")

    log("")
    log("## Leakage checks")
    log("")

    check("every row is in exactly one split or the gap",
          len(train) + len(val) + len(test) + gap_rows == len(df),
          str(len(train)) + " + " + str(len(val)) + " + " + str(len(test)) + " + " + str(gap_rows) + " = " + str(len(df)))

    keys = pd.concat([
        train[["source_file", "original_row"]],
        val[["source_file", "original_row"]],
        test[["source_file", "original_row"]],
    ])
    check("no row appears in two splits", int(keys.duplicated().sum()) == 0)

    bounds = df[df["split"] != "gap"].groupby(["source_file", label, "split"])["Timestamp"].agg(["min", "max"])
    order_problems = 0
    for key in groups:
        file_name = key[0]
        label_name = key[1]
        pairs = [("train", "val"), ("val", "test"), ("train", "test")]
        for first, second in pairs:
            if (file_name, label_name, first) in bounds.index and (file_name, label_name, second) in bounds.index:
                first_end = bounds.loc[(file_name, label_name, first), "max"]
                second_start = bounds.loc[(file_name, label_name, second), "min"]
                if first_end > second_start:
                    order_problems = order_problems + 1
    check("inside every group train ends before val starts and val ends before test starts",
          order_problems == 0, str(order_problems) + " problems")

    train_hash = hash_rows(train, feature_cols)
    val_hash = hash_rows(val, feature_cols)
    test_hash = hash_rows(test, feature_cols)
    val_in_train = int(np.isin(val_hash, train_hash).sum())
    test_in_train = int(np.isin(test_hash, train_hash).sum())
    test_in_val = int(np.isin(test_hash, val_hash).sum())
    check("no identical feature vector in two splits",
          val_in_train + test_in_train + test_in_val == 0,
          "val in train " + str(val_in_train) + ", test in train " + str(test_in_train) + ", test in val " + str(test_in_val))

    missing_classes = []
    small_classes = []
    for name in classes:
        a, b, c = class_counts[name]
        if a == 0 or b == 0 or c == 0:
            missing_classes.append(name)
        if b < config.MIN_ROWS_PER_SPLIT or c < config.MIN_ROWS_PER_SPLIT:
            small_classes.append(name)
    check("every class appears in train, val and test", len(missing_classes) == 0, str(missing_classes))
    check("every class has at least " + str(config.MIN_ROWS_PER_SPLIT) + " rows in val and test",
          len(small_classes) == 0, str(small_classes))

    bad_columns = []
    for col in feature_cols:
        values = df[col]
        if values.isna().any() or np.isinf(values).any():
            bad_columns.append(col)
    check("no NaN or inf in any feature column", len(bad_columns) == 0, str(bad_columns))

    if not all(check_results):
        log("")
        log("STOPPED: at least one check failed. No split files were written.")
        write_report()
        sys.exit(1)

    os.makedirs(config.PROCESSED_DIR, exist_ok=True)
    for path, part in [(config.TRAIN_PATH, train), (config.VAL_PATH, val), (config.TEST_PATH, test)]:
        part = part.sort_values(["Timestamp", "source_file", "original_row"], kind="stable").reset_index(drop=True)
        part.to_parquet(path, index=False)
        log("")
        log("Saved " + str(len(part)) + " rows to " + path)

    write_report()
    print("")
    print("Done. All checks passed. Report: reports/split_report.md")


if __name__ == "__main__":
    main()
