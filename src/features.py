import os
import sys
import json
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

import config

section = []


def log(text=""):
    print(text)
    section.append(text)


def hash_rows(df, columns):
    return pd.util.hash_pandas_object(df[columns], index=False).values


def write_section():
    marker = "## Feature selection (train only)"
    old = ""
    if os.path.exists(config.SPLIT_REPORT_PATH):
        with open(config.SPLIT_REPORT_PATH, "r", encoding="utf-8") as f:
            old = f.read()
    head = old
    if marker in old:
        head = old.split(marker)[0]
    new_text = head.rstrip() + "\n\n" + "\n".join(section) + "\n"
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(config.SPLIT_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(new_text)


def main():
    label = config.LABEL_COLUMN
    all_columns = pq.ParquetFile(config.TRAIN_PATH).schema.names
    candidates = [c for c in all_columns if c not in config.NON_FEATURE_COLUMNS]
    train = pd.read_parquet(config.TRAIN_PATH, columns=candidates)

    log("## Feature selection (train only)")
    log("")
    log("Candidate numeric columns: " + str(len(candidates)))
    log("Excluded before selection: " + ", ".join(config.NON_FEATURE_COLUMNS))

    constant_cols = []
    for col in candidates:
        if train[col].nunique(dropna=False) == 1:
            constant_cols.append(col)
    remaining = [c for c in candidates if c not in constant_cols]
    log("")
    log("### Constant columns in train (" + str(len(constant_cols)) + ")")
    for col in constant_cols:
        log("- " + col)

    duplicate_cols = []
    if "Fwd Header Length.1" in remaining and "Fwd Header Length" in remaining:
        same = bool((train["Fwd Header Length.1"] == train["Fwd Header Length"]).all())
        duplicate_cols.append("Fwd Header Length.1")
        remaining = [c for c in remaining if c != "Fwd Header Length.1"]
        log("")
        log("### Duplicate column")
        log("- Fwd Header Length.1 dropped. Identical to Fwd Header Length on train: " + str(same))

    sample_size = min(len(train), config.FEATURE_SAMPLE_ROWS)
    sample = train[remaining].sample(n=sample_size, random_state=config.SEED)
    corr = sample.corr().abs()
    del sample

    kept = []
    dropped_corr = []
    for col in remaining:
        partner = None
        best = 0.0
        for earlier in kept:
            value = corr.loc[earlier, col]
            if value >= config.CORRELATION_LIMIT:
                partner = earlier
                best = float(value)
                break
        if partner is None or col in config.PROTECTED_FEATURES:
            kept.append(col)
        else:
            dropped_corr.append((col, partner, best))

    log("")
    log("### Correlated columns dropped (|corr| >= " + str(config.CORRELATION_LIMIT) + " on " + str(sample_size) + " train rows)")
    for col, partner, value in dropped_corr:
        log("- " + col + " (kept " + partner + ", corr " + "%.4f" % value + ")")

    features = kept
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    with open(config.FEATURE_LIST_PATH, "w") as f:
        json.dump(features, f, indent=2)

    log("")
    log("### Final model features (" + str(len(features)) + ")")
    log("")
    log("Candidates " + str(len(candidates)) + " - constant " + str(len(constant_cols)) + " - duplicate "
        + str(len(duplicate_cols)) + " - correlated " + str(len(dropped_corr)) + " = " + str(len(features)))
    if len(features) < 60 or len(features) > 70:
        log("Note: the blueprint expected about 60 to 70. The count above comes from the data and the rules, so it is not an error.")
    for i, col in enumerate(features):
        log(str(i + 1) + ". " + col)
    log("")
    log("Saved " + config.FEATURE_LIST_PATH)

    train_hash = hash_rows(train, features)
    del train

    val = pd.read_parquet(config.VAL_PATH)
    test = pd.read_parquet(config.TEST_PATH)
    val_hash = hash_rows(val, features)
    test_hash = hash_rows(test, features)
    val_remove = np.isin(val_hash, train_hash)
    test_remove = np.isin(test_hash, train_hash) | np.isin(test_hash, val_hash)

    log("")
    log("### Duplicate check on the model's own features")
    log("")
    log("Rows in val identical to a train row: " + str(int(val_remove.sum())))
    log("Rows in test identical to a train or val row: " + str(int(test_remove.sum())))

    if val_remove.sum() + test_remove.sum() > 0:
        val_by_label = val.loc[val_remove, label].value_counts()
        test_by_label = test.loc[test_remove, label].value_counts()
        for name in val_by_label.index:
            log("- val " + name + ": " + str(int(val_by_label[name])))
        for name in test_by_label.index:
            log("- test " + name + ": " + str(int(test_by_label[name])))
        val = val[~val_remove].reset_index(drop=True)
        test = test[~test_remove].reset_index(drop=True)
        log("These rows were removed from val and test only. Train was not touched.")

    train_labels = pd.read_parquet(config.TRAIN_PATH, columns=[label])[label]
    problems = []
    log("")
    log("### Final rows per class per split")
    log("")
    log("| label | train | val | test |")
    log("|---|---|---|---|")
    for name in sorted(train_labels.unique()):
        a = int((train_labels == name).sum())
        b = int((val[label] == name).sum())
        c = int((test[label] == name).sum())
        log("| " + name + " | " + str(a) + " | " + str(b) + " | " + str(c) + " |")
        if b < config.MIN_ROWS_PER_SPLIT or c < config.MIN_ROWS_PER_SPLIT:
            problems.append(name)

    if len(problems) > 0:
        log("")
        log("STOPPED: these classes have fewer than " + str(config.MIN_ROWS_PER_SPLIT) + " rows in val or test: " + str(problems))
        write_section()
        sys.exit(1)

    if val_remove.sum() + test_remove.sum() > 0:
        val.to_parquet(config.VAL_PATH, index=False)
        test.to_parquet(config.TEST_PATH, index=False)
        log("")
        log("Rewrote val.parquet and test.parquet without the rows above.")

    missing_display = [c for c in config.DISPLAY_FEATURES if c not in all_columns]
    log("")
    log("### Display features for the agent alert (not used for training)")
    for col in config.DISPLAY_FEATURES:
        log("- " + col)
    if len(missing_display) > 0:
        log("")
        log("MISSING from the data: " + str(missing_display))

    write_section()

    if len(missing_display) > 0:
        print("")
        print("Fix config.DISPLAY_FEATURES. These names are not in the data:", missing_display)
        print("Available columns:", candidates)
        sys.exit(1)

    print("")
    print("Done. " + str(len(features)) + " features saved to models/feature_list.json. Report updated.")


if __name__ == "__main__":
    main()
