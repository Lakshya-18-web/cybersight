"""What the model is allowed to see for one alert: the alert row plus label-free flow context.

Agent-side module. It reads only the dev alert file and the dev flow store, through eval_io.
It has no access to labels, the MITRE answer key or the frozen set, and must never import them.
The frozen set is deliberately not reachable from here: the dev set is the only one used for prompt work.
"""
import json
import pandas as pd

import eval_io

CONTEXT_WINDOW_MINUTES = 5

# Anything that would identify the answer. An alert file containing one of these is rejected.
FORBIDDEN_COLUMNS = {"label", "is_attack", "source_file", "original_row", "source_alert_id",
                     "mitre_tactic", "mitre_technique_id", "mitre_accepted_ids"}
# Columns that are links or bookkeeping, not evidence, so they are not shown to the model.
HIDDEN_COLUMNS = {"flow_row"}


def assert_label_free(alerts):
    bad = [c for c in alerts.columns if c.lower() in FORBIDDEN_COLUMNS]
    if len(bad) > 0:
        raise ValueError("alert data contains answer-bearing columns and was not passed on: " + ", ".join(bad))
    return alerts


def load_dev_alerts():
    return assert_label_free(eval_io.load_alerts("dev"))


def load_dev_flow_store():
    return assert_label_free(eval_io.load_flow_store("dev"))


def _plain(value):
    if isinstance(value, pd.Timestamp):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if hasattr(value, "item"):
        return value.item()
    return value


def build_model_input(alert_row, store, window_minutes=CONTEXT_WINDOW_MINUTES):
    """One alert (a pandas Series) plus a summary of nearby flows from the same source IP.
    Returns a plain, JSON-serialisable dict."""
    alert = {name: _plain(alert_row[name]) for name in alert_row.index if name not in HIDDEN_COLUMNS and name.lower() not in FORBIDDEN_COLUMNS}
    stamp = pd.Timestamp(alert_row["timestamp"])
    window = pd.Timedelta(minutes=window_minutes)
    times = pd.to_datetime(store["timestamp"])
    near = store[(store["src_ip"] == alert_row["src_ip"]) & (times >= stamp - window) & (times <= stamp + window)]
    context = {
        "window_minutes": window_minutes,
        "flows_from_same_source": int(len(near)),
        "distinct_destination_ports": int(near["dst_port"].nunique()),
        "distinct_destination_ips": int(near["dst_ip"].nunique()),
    }
    return {"alert": alert, "context": context}


def to_prompt_json(model_input):
    return json.dumps(model_input, sort_keys=True, default=str)
