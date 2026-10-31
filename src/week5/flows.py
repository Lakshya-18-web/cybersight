"""Flow records from the sensor, as the flow store the existing analysis agents already query.

The Week 3 tools (summarize_flows, beacon_stats ...) read a FlowStore: a table of flows with the CIC feature names. For an alert that came from a sensor, the table is built from the flow events the
sensor sent (soc.sensor_events), for the addresses in the alert and a time window around it. The agents are not changed; they get a different table.

Missing is missing: a feature EVE cannot give stays NaN (the tools report "no value", never a made-up one), and when NO flow event exists for either address in the window the store is None, so the flow tools
answer "unavailable" and the specialists report a failed analysis (which blocks auto-close) instead of reporting "no flows" as though the log had been searched.
"""
import pandas as pd

import config

from . import eve

WINDOW_MINUTES = 120
MAX_FLOWS = 5000


def frame_from_records(records):
    rows = []
    for i, r in enumerate(records):
        start = eve.parse_time(r["start"]) if r.get("start") else None
        if start is None:
            continue
        end = eve.parse_time(r["end"]) if r.get("end") else None
        age = r.get("age_seconds")
        duration = float(age) if age is not None else ((end - start).total_seconds() if end else None)
        counts = {k: r.get(k) for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient")}
        feats = eve.features_from(counts, duration)
        row = {"flow_row": i, "flow_id": "%s:%s" % (r["sensor"], r["flow_ref"]), "timestamp": start.replace(tzinfo=None), "src_ip": r["src_ip"], "src_port": r["src_port"], "dst_ip": r["dst_ip"],
               "dst_port": r["dst_port"], "protocol": r["protocol"]}
        for name in config.DISPLAY_FEATURES:
            value = feats.get(name)
            row[name] = float("nan") if value is None else float(value)
        rows.append(row)
    return pd.DataFrame(rows)


def flow_store_for(repo, alert, window_minutes=WINDOW_MINUTES):
    """-> (FlowStore or None, n_flows). repo: a Repo5 (flows_near). None when the sensor sent no usable flow for the alert's addresses in the window."""
    from tools import FlowStore
    around = eve.parse_time(alert["timestamp"].replace(" ", "T")).isoformat()
    records = repo.flows_near([alert["src_ip"], alert["dst_ip"]], around, window_minutes, MAX_FLOWS)
    frame = frame_from_records(records)
    if frame.empty:
        return None, 0
    return FlowStore(frame), int(len(frame))
