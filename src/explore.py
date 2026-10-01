import os
import pandas as pd

raw_folder = "data/raw"
needed_columns = ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]

total_rows = 0
all_labels = {}
first_file = True

for name in sorted(os.listdir(raw_folder)):
    if not name.endswith(".csv"):
        continue

    path = os.path.join(raw_folder, name)
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    print(name)
    print("shape:", df.shape)

    if first_file:
        print("number of columns:", len(df.columns))
        for col in needed_columns:
            print("has", col, ":", col in df.columns)
        first_file = False

    counts = df["Label"].value_counts()
    for label in counts.index:
        print("   ", label, counts[label])
        if label in all_labels:
            all_labels[label] = all_labels[label] + counts[label]
        else:
            all_labels[label] = counts[label]

    total_rows = total_rows + df.shape[0]
    print()

print("total rows:", total_rows)
print("rows per label:")
for label in all_labels:
    print("   ", label, all_labels[label])
