import os
import csv
import json
import hashlib

VERDICT_FIELDS = ["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"]
CSV_COLUMNS = ["alert_id", "status"] + VERDICT_FIELDS + ["attempts", "malformed_first_try", "error_code"]


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        block = f.read(1 << 20)
        while block != b"":
            h.update(block)
            block = f.read(1 << 20)
    return h.hexdigest()


def text_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def append_jsonl(path, record):
    line = json.dumps(record, sort_keys=True) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path, repair=False):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")
    if lines[-1] == "":
        lines = lines[:-1]
    records = []
    for i in range(len(lines)):
        try:
            records.append(json.loads(lines[i]))
        except ValueError:
            if i == len(lines) - 1 and repair:
                good = "\n".join(lines[:i])
                if good != "":
                    good = good + "\n"
                with open(path, "w", encoding="utf-8") as f:
                    f.write(good)
                print("removed an unfinished last line from " + os.path.basename(path))
                break
            raise ValueError(os.path.basename(path) + " line " + str(i + 1) + " is not valid JSON")
    return records


def write_json_atomic(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def latest_results(records):
    latest = {}
    for record in records:
        latest[record["alert_id"]] = record
    return latest


def write_verdicts_csv(path, alert_ids, latest):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_COLUMNS)
        for alert_id in alert_ids:
            if alert_id not in latest:
                continue
            r = latest[alert_id]
            verdict = r.get("verdict")
            row = [alert_id, r["status"]]
            for name in VERDICT_FIELDS:
                if verdict is None:
                    row.append("")
                else:
                    row.append(verdict[name])
            row.append(r.get("attempts", ""))
            row.append(r.get("malformed_first_try", ""))
            row.append(r.get("error_code") or "")
            writer.writerow(row)


class RunDir:
    def __init__(self, path):
        self.path = path
        self.results = os.path.join(path, "results.jsonl")
        self.raw = os.path.join(path, "raw_responses.jsonl")
        self.meta = os.path.join(path, "run_meta.json")
        self.verdicts_csv = os.path.join(path, "verdicts.csv")
        self.prompt_snapshot = os.path.join(path, "prompt_snapshot.txt")
