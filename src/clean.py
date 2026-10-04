import os
import sys
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import config

parser = argparse.ArgumentParser()
parser.add_argument("--force", action="store_true")
args = parser.parse_args()

log_lines = []
step_names = []
step_counts = []


def log(text=""):
    print(text)
    log_lines.append(text)


def record(step_name, df):
    counts = df[config.LABEL_COLUMN].value_counts()
    step_names.append(step_name)
    step_counts.append(counts)
    log("")
    log("After " + step_name + ": " + str(len(df)) + " rows")


def stop_here(message):
    log("")
    log("STOPPED: " + message)
    write_log()
    sys.exit(1)


def write_log():
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    path = os.path.join(config.REPORTS_DIR, "cleaning_log.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
        f.write("\n")


def fix_label_text(raw_label):
    text = str(raw_label)
    cleaned = ""
    for ch in text:
        code = ord(ch)
        if code >= 32 and code <= 126:
            cleaned = cleaned + ch
        else:
            cleaned = cleaned + "-"
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    while "  " in cleaned:
        cleaned = cleaned.replace("  ", " ")
    cleaned = cleaned.strip()
    if cleaned.lower().startswith("web attack"):
        rest = cleaned[len("web attack"):].strip(" -").lower()
        if rest in config.WEB_ATTACK_NAMES:
            return config.WEB_ATTACK_NAMES[rest]
    return cleaned


def fix_labels(df):
    unique_values = df[config.LABEL_COLUMN].unique()
    mapping = {}
    for value in unique_values:
        mapping[value] = fix_label_text(value)
    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].map(mapping)
    return df


def parse_timestamps(series):
    parsed = pd.to_datetime(series, format="%d/%m/%Y %H:%M", errors="coerce")
    missing = parsed.isna()
    if missing.any():
        retry = pd.to_datetime(series[missing], format="%d/%m/%Y %H:%M:%S", errors="coerce")
        parsed[missing] = retry
    hours = parsed.dt.hour
    afternoon = (hours >= 1) & (hours <= 7)
    shifted = parsed + pd.Timedelta(hours=12)
    parsed = parsed.where(~afternoon, shifted)
    return parsed


def read_one_file(name):
    path = os.path.join(config.RAW_DIR, name)
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df["source_file"] = name
    df["original_row"] = np.arange(len(df))
    return df


def prepare_one_file(name, feature_cols_holder):
    df = read_one_file(name)
    raw_rows = len(df)

    data_columns = [c for c in df.columns if c not in config.BOOKKEEPING_COLUMNS]
    empty_mask = df[data_columns].isna().all(axis=1)
    empty_rows = int(empty_mask.sum())
    df = df[~empty_mask].copy()

    df = fix_labels(df)

    weekday = name.split("-")[0]
    if weekday not in config.DAY_OF_MONTH_BY_WEEKDAY:
        stop_here("cannot read the weekday from file name " + name)
    expected_day = config.DAY_OF_MONTH_BY_WEEKDAY[weekday]

    df["Timestamp"] = parse_timestamps(df["Timestamp"])
    unparsed = int(df["Timestamp"].isna().sum())
    known = df["Timestamp"].notna()
    wrong_day = known & (
        (df["Timestamp"].dt.year != config.CAPTURE_YEAR)
        | (df["Timestamp"].dt.month != config.CAPTURE_MONTH)
        | (df["Timestamp"].dt.day != expected_day)
    )
    wrong_day_rows = int(wrong_day.sum())

    if len(feature_cols_holder) == 0:
        for col in df.columns:
            if col not in config.NON_FEATURE_COLUMNS:
                feature_cols_holder.append(col)
    feature_cols = feature_cols_holder

    inf_count = 0
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        infinite = np.isinf(df[col])
        inf_count = inf_count + int(infinite.sum())
        df.loc[infinite, col] = np.nan

    first_time = df["Timestamp"].min()
    last_time = df["Timestamp"].max()

    log("| " + name + " | " + str(raw_rows) + " | " + str(empty_rows) + " | " + str(len(df)) + " | "
        + str(unparsed) + " | " + str(wrong_day_rows) + " | " + str(inf_count) + " | "
        + str(first_time) + " | " + str(last_time) + " |")

    if wrong_day_rows > 0:
        if not args.force:
            stop_here(str(wrong_day_rows) + " rows in " + name + " fall on the wrong date. Check the AM/PM fix or run with --force to drop them.")
        df = df[~wrong_day].copy()

    return df, raw_rows, empty_rows


def main():
    file_names = sorted([f for f in os.listdir(config.RAW_DIR) if f.endswith(".csv")])
    if len(file_names) == 0:
        print("No CSV files found in", config.RAW_DIR)
        sys.exit(1)

    log("# Cleaning log")
    log("")
    log("## Step 1 to 4: load, label fix, timestamps, numeric conversion")
    log("")
    log("| file | raw rows | empty rows | kept | unparsed timestamps | wrong date | inf values | first time | last time |")
    log("|---|---|---|---|---|---|---|---|---|")

    frames = []
    feature_cols_holder = []
    raw_total = 0
    empty_total = 0
    for name in file_names:
        df, raw_rows, empty_rows = prepare_one_file(name, feature_cols_holder)
        frames.append(df)
        raw_total = raw_total + raw_rows
        empty_total = empty_total + empty_rows

    feature_cols = feature_cols_holder
    df = pd.concat(frames, ignore_index=True)
    del frames

    log("")
    log("Raw rows: " + str(raw_total))
    log("Completely empty rows removed: " + str(empty_total))
    log("Rows with data: " + str(raw_total - empty_total))
    log("Feature columns: " + str(len(feature_cols)))
    log("Labels after fixing: " + str(sorted(df[config.LABEL_COLUMN].unique())))
    record("load, label fix, timestamps, numeric", df)

    log("")
    log("## Step 5: rows with NaN or inf in a feature")
    nan_by_column = df[feature_cols].isna().sum()
    nan_by_column = nan_by_column[nan_by_column > 0].sort_values(ascending=False)
    for col in nan_by_column.index:
        log("- " + col + ": " + str(int(nan_by_column[col])))
    before_counts = df[config.LABEL_COLUMN].value_counts()
    nan_rows = df[feature_cols].isna().any(axis=1)
    dropped_counts = df.loc[nan_rows, config.LABEL_COLUMN].value_counts()
    worst_loss = 0.0
    for label in before_counts.index:
        lost = int(dropped_counts.get(label, 0))
        percent = 100.0 * lost / before_counts[label]
        if percent > worst_loss:
            worst_loss = percent
        log("- " + label + " lost " + str(lost) + " of " + str(before_counts[label]) + " (" + "%.2f" % percent + "%)")
    if worst_loss > config.MAX_CLASS_LOSS_PERCENT and not args.force:
        stop_here("a class lost more than " + str(config.MAX_CLASS_LOSS_PERCENT) + "% of its rows to NaN. Review before continuing or run with --force.")
    df = df[~nan_rows].copy()
    record("NaN drop", df)

    log("")
    log("## Step 6: rows missing a required field")
    missing_required = df[config.REQUIRED_COLUMNS].isna().any(axis=1)
    log("Rows dropped: " + str(int(missing_required.sum())))
    df = df[~missing_required].copy()
    record("required fields", df)

    log("")
    log("## Step 7: exact duplicate rows")
    subset = config.IDENTIFIER_COLUMNS + feature_cols + [config.LABEL_COLUMN]
    duplicate_mask = df.duplicated(subset=subset, keep="first")
    log("Rows dropped: " + str(int(duplicate_mask.sum())))
    df = df[~duplicate_mask].copy()
    record("exact duplicates", df)

    log("")
    log("## Step 8: negative value audit")
    negative_counts = {}
    for col in feature_cols:
        count = int((df[col] < 0).sum())
        if count > 0:
            negative_counts[col] = count
    for col in sorted(negative_counts, key=negative_counts.get, reverse=True):
        log("- " + col + ": " + str(negative_counts[col]) + " negative values")
    if "Flow Duration" in df.columns:
        bad_duration = df["Flow Duration"] < 0
        log("Rows dropped for negative Flow Duration: " + str(int(bad_duration.sum())))
        df = df[~bad_duration].copy()
    record("negative duration", df)

    log("")
    log("## Step 9: dropped and merged classes")
    for label in config.DROPPED_CLASSES:
        log("- dropping " + label + ": " + str(int((df[config.LABEL_COLUMN] == label).sum())) + " rows")
    df = df[~df[config.LABEL_COLUMN].isin(config.DROPPED_CLASSES)].copy()
    for old_label in config.MERGED_CLASSES:
        log("- merging " + old_label + " into " + config.MERGED_CLASSES[old_label] + ": " + str(int((df[config.LABEL_COLUMN] == old_label).sum())) + " rows")
    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].replace(config.MERGED_CLASSES)
    record("class drop and merge", df)

    log("")
    log("## Step 10: feature-vector duplicates")
    df["vec_hash"] = pd.util.hash_pandas_object(df[feature_cols], index=False).values
    label_codes = df[config.LABEL_COLUMN].astype("category").cat.codes.values
    pairs = pd.DataFrame({"vec_hash": df["vec_hash"].values, "label_code": label_codes})
    labels_per_hash = pairs.groupby("vec_hash")["label_code"].nunique()
    conflicting_hashes = labels_per_hash[labels_per_hash > 1].index
    conflict_mask = df["vec_hash"].isin(conflicting_hashes)
    log("Rows with identical features but different labels (all copies dropped): " + str(int(conflict_mask.sum())))
    conflict_by_label = df.loc[conflict_mask, config.LABEL_COLUMN].value_counts()
    for label in conflict_by_label.index:
        log("- " + label + ": " + str(int(conflict_by_label[label])))
    df = df[~conflict_mask].copy()

    df = df.sort_values(["Timestamp", "source_file", "original_row"], kind="stable")
    same_vector = df.duplicated(subset=["vec_hash", config.LABEL_COLUMN], keep="first")
    log("Repeated identical vectors with the same label dropped: " + str(int(same_vector.sum())))
    df = df[~same_vector].copy()
    df = df.drop(columns=["vec_hash"])
    df = df.reset_index(drop=True)
    record("feature-vector dedupe", df)

    log("")
    log("## Class check")
    final_counts = df[config.LABEL_COLUMN].value_counts()
    for label in final_counts.index:
        note = ""
        if final_counts[label] < config.SMALL_CLASS_LIMIT:
            note = "  <-- under " + str(config.SMALL_CLASS_LIMIT) + ", review"
        log("- " + label + ": " + str(int(final_counts[label])) + note)

    log("")
    log("## Rows per class after every step")
    log("")
    all_labels = []
    for counts in step_counts:
        for label in counts.index:
            if label not in all_labels:
                all_labels.append(label)
    log("| label | " + " | ".join(step_names) + " |")
    log("|---|" + "---|" * len(step_names))
    for label in sorted(all_labels):
        cells = []
        for counts in step_counts:
            cells.append(str(int(counts.get(label, 0))))
        log("| " + label + " | " + " | ".join(cells) + " |")

    os.makedirs(config.PROCESSED_DIR, exist_ok=True)
    out_path = os.path.join(config.PROCESSED_DIR, "flows_clean.parquet")
    df.to_parquet(out_path, index=False)
    log("")
    log("Saved " + str(len(df)) + " rows and " + str(df.shape[1]) + " columns to " + out_path)
    write_log()

    plt.figure(figsize=(9, 5))
    names = list(final_counts.index)
    values = [int(final_counts[n]) for n in names]
    plt.bar(names, values, color="#4C72B0")
    plt.yscale("log")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("flows (log scale)")
    plt.title("Flows per class after cleaning")
    plt.tight_layout()
    plt.savefig(os.path.join(config.REPORTS_DIR, "class_distribution.png"), dpi=150)
    plt.close()

    print("")
    print("Done. Log: reports/cleaning_log.md  Chart: reports/class_distribution.png")


main()
