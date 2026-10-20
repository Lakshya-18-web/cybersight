"""Synthetic, label-free fixtures shared by the Week 5 tests, the load tester and the prompt-injection suite.

Nothing here reads a file, the dev set or the frozen set. The flow store is a small invented traffic table (a beacon, a port scan, an irregular talker, DNS noise) and the alerts are invented rows
with exactly the Week 2 alert fields, so the Week 4 graph runs to completion on them (the tools find flows to analyse) while no real data is involved. The values are deterministic functions of the
index, so two runs build identical alerts. Synthetic traffic is not a measurement of detection quality, and every number produced from it is labelled as such.
"""
import hashlib

import baseline_prompt
import config

BASE_TIME = "2017-07-05 10:00:00"
BEACON = ("192.168.10.5", "52.1.2.3", 80)
SCAN = ("192.168.10.9", "10.0.0.2", 22)
IRREGULAR = ("192.168.10.7", "52.9.9.9", 443)
OTHER = ("203.0.113.7", "203.0.113.8", 80)
PATTERNS = (BEACON, SCAN, IRREGULAR, OTHER)


def flow_rows():
    import pandas as pd
    t0 = pd.Timestamp(BASE_TIME)
    rows = []

    def add(ts, src, dst, dport, proto=6, fwd=100.0, dur=5.0, sport=40000):
        row = {"flow_row": len(rows), "flow_id": "fx-" + str(len(rows)), "timestamp": ts, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto}
        for name in config.DISPLAY_FEATURES:
            row[name] = 1.0
        row["Total Length of Fwd Packets"] = fwd
        row["Flow Duration"] = dur
        row["Fwd IAT Mean"] = 0.5
        rows.append(row)

    for i in range(10):
        add(t0 + pd.Timedelta(seconds=60 * i), BEACON[0], BEACON[1], 80)
    for i, port in enumerate(range(1, 31)):
        add(t0 + pd.Timedelta(seconds=i), SCAN[0], SCAN[1], port, fwd=0.0, dur=0.1)
    offset = 0
    for gap in [0, 10, 200, 30, 400]:
        offset += gap
        add(t0 + pd.Timedelta(seconds=offset), IRREGULAR[0], IRREGULAR[1], 443, fwd=50.0 + offset)
    add(t0 + pd.Timedelta(hours=3), "192.168.10.50", "10.0.0.2", 53, proto=17)
    add(t0 + pd.Timedelta(hours=3, seconds=1), "192.168.10.51", "10.0.0.2", 53, proto=17)
    return rows


def flow_store():
    import pandas as pd
    from tools import FlowStore
    return FlowStore(pd.DataFrame(flow_rows()))


def _unit(index, salt):
    """A deterministic number in [0, 1) from an index and a salt."""
    return int(hashlib.sha256((salt + ":" + str(index)).encode("utf-8")).hexdigest()[:8], 16) / float(16 ** 8)


def make_alert(index=0, prefix="SYN", pattern=None, **overrides):
    """An alert with exactly baseline_prompt.ALERT_FIELDS. alert_id = <prefix>-<index:06d>. Deterministic."""
    src, dst, dport = pattern or PATTERNS[index % len(PATTERNS)]
    alert = {
        "alert_id": "%s-%06d" % (prefix, index), "timestamp": BASE_TIME, "flow_id": "%s-flow-%06d" % (prefix.lower(), index), "src_ip": src, "src_port": 40000 + index % 1000,
        "dst_ip": dst, "dst_port": dport, "protocol": 6, "detector_score": round(0.5 + 0.5 * _unit(index, "score"), 4),
    }
    for name in baseline_prompt.ALERT_FIELDS:
        if name not in alert:
            alert[name] = round(1.0 + 99.0 * _unit(index, name), 3)
    alert.update(overrides)
    return alert


def alerts(n, prefix="SYN"):
    return [make_alert(i, prefix) for i in range(n)]


def main(argv=None):
    """python -m week5.fixtures [INDEX]   prints one synthetic request body ({"alert": ...}) as JSON, for a manual smoke test of the API. Invented values; no file is read."""
    import json
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    index = int(args[0]) if args else 0
    print(json.dumps({"alert": make_alert(index, "DEMO")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
