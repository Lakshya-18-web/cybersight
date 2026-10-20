"""The evaluation data object and the SYNTHETIC fixture used by every test and rehearsal. This module never reads a file and never imports eval_io.

EvalData.labels has exactly the columns of eval_io.load_labels (alert_id, label, is_attack, mitre_technique_id, mitre_accepted_ids) so the Week 2 scoring code (evaluate.check_inputs / build_table) is reused unchanged.
The fixture's labels are invented from the pattern of each synthetic alert (a beacon, a port scan, benign traffic) and are NOT a measure of anything.
"""
import hashlib
import json

import pandas as pd

from week5 import fixtures

SET_NAMES = ("fixture", "dev", "frozen")


def frame_sha256(df, columns=None):
    """Order-sensitive SHA-256 of a DataFrame's content (stable across machines: values are written as JSON text)."""
    frame = df if columns is None else df[list(columns)]
    text = frame.to_json(orient="split", double_precision=12, index=False, date_format="iso", default_handler=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvalData:
    def __init__(self, set_name, alerts, labels, flows):
        if set_name not in SET_NAMES:
            raise ValueError("set_name must be one of " + ", ".join(SET_NAMES))
        self.set_name, self.alerts, self.labels, self.flows = set_name, alerts, labels, flows

    def hashes(self):
        """What a run records about its input, so two runs can be proven to have used the same records and the same label definitions."""
        return {"set": self.set_name, "alert_count": int(len(self.alerts)), "alerts_sha256": frame_sha256(self.alerts), "alert_ids_sha256": hashlib.sha256("\n".join(self.alerts["alert_id"]).encode("utf-8")).hexdigest(),
                "labels_sha256": frame_sha256(self.labels), "flows_sha256": frame_sha256(self.flows) if self.flows is not None else None}


FIXTURE_LABELS = {0: ("Bot", "T1071"), 1: ("PortScan", "T1046")}        # pattern index -> (class, accepted MITRE id); patterns 2 and 3 are benign


def fixture_data(n=24):
    """A tiny synthetic set. Alert i has the traffic pattern i % 4, so the flow store really contains the traffic the tools will find."""
    alerts = pd.DataFrame(fixtures.alerts(n, "EV"))
    rows = []
    for i, alert_id in enumerate(alerts["alert_id"]):
        label, mitre = FIXTURE_LABELS.get(i % 4, ("BENIGN", "NONE"))
        rows.append({"alert_id": alert_id, "label": label, "is_attack": int(label != "BENIGN"), "mitre_technique_id": mitre, "mitre_accepted_ids": mitre})
    return EvalData("fixture", alerts, pd.DataFrame(rows), pd.DataFrame(fixtures.flow_rows()))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
