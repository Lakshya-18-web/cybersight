"""Flow-log tools over the project's label-free flow store.

  query_flows      matching flows, newest or oldest first, capped
  summarize_flows  counts and feature statistics for one host over a time window
  beacon_stats     timing and size regularity of the flows between one source and one destination

The store is fixed when the tool object is built (normally the dev flow store, loaded through triage_inputs / eval_io). A tool argument
is only ever a value (an address, a port, a time), never a path, a column name or a set name, so a call cannot read anything else.
The tools report facts. They never say whether something is an attack.
"""
import pandas as pd

import config
import triage_inputs
from .base import P, ToolSpec, ToolFailure, CODE_INVALID, CODE_UNAVAILABLE

ID_COLUMNS = ["flow_row", "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol"]
MAX_ROWS = 200
DEFAULT_ROWS = 50
TOP_N = 10
NOTE_FEATURES = "feature values are shown as stored in the flow store"
FWD_BYTES = "Total Length of Fwd Packets"
FLOW_DURATION = "Flow Duration"


def _round(value, digits=6):
    if value is None or pd.isna(value):
        return None
    return round(float(value), digits)


class FlowStore:
    """An in-memory, label-free flow table sorted by time. Built from a DataFrame, or from the dev store with from_dev()."""

    def __init__(self, frame):
        missing = [c for c in ID_COLUMNS if c not in frame.columns]
        if missing:
            raise ValueError("flow store is missing columns: " + ", ".join(missing))
        triage_inputs.assert_label_free(frame)
        data = frame.copy()
        data["timestamp"] = pd.to_datetime(data["timestamp"])
        self.frame = data.sort_values(["timestamp", "flow_row"], kind="stable").reset_index(drop=True)
        self.feature_columns = [c for c in self.frame.columns if c not in ID_COLUMNS]
        self.display_columns = [c for c in config.DISPLAY_FEATURES if c in self.frame.columns]

    @classmethod
    def from_dev(cls):
        """The dev flow store only. There is no argument that selects another set."""
        return cls(triage_inputs.load_dev_flow_store())

    def __len__(self):
        return len(self.frame)

    def select(self, src_ip=None, dst_ip=None, ip=None, direction="src", src_port=None, dst_port=None, protocol=None, start=None, end=None):
        f = self.frame
        mask = pd.Series(True, index=f.index)
        if src_ip is not None:
            mask &= f["src_ip"] == src_ip
        if dst_ip is not None:
            mask &= f["dst_ip"] == dst_ip
        if ip is not None:
            if direction == "src":
                mask &= f["src_ip"] == ip
            elif direction == "dst":
                mask &= f["dst_ip"] == ip
            else:
                mask &= (f["src_ip"] == ip) | (f["dst_ip"] == ip)
        if src_port is not None:
            mask &= f["src_port"] == src_port
        if dst_port is not None:
            mask &= f["dst_port"] == dst_port
        if protocol is not None:
            mask &= f["protocol"] == protocol
        if start is not None:
            mask &= f["timestamp"] >= pd.Timestamp(start)
        if end is not None:
            mask &= f["timestamp"] <= pd.Timestamp(end)
        return f[mask]

    def host_summary(self, ip):
        """Used by the IP tool: how often an address appears in the store."""
        as_src = self.frame[self.frame["src_ip"] == ip]
        as_dst = self.frame[self.frame["dst_ip"] == ip]
        both = pd.concat([as_src["timestamp"], as_dst["timestamp"]])
        return {"flows_as_source": int(len(as_src)), "flows_as_destination": int(len(as_dst)),
                "first_seen": None if both.empty else both.min(), "last_seen": None if both.empty else both.max()}


def _window(c):
    """(start, end) from either around + window_minutes or start/end. None means unbounded."""
    around, start, end = c.get("around"), c.get("start"), c.get("end")
    if around is not None and (start is not None or end is not None):
        raise ToolFailure(CODE_INVALID, "use either around + window_minutes or start/end, not both")
    if around is not None:
        delta = pd.Timedelta(minutes=c["window_minutes"])
        return pd.Timestamp(around) - delta, pd.Timestamp(around) + delta
    start = pd.Timestamp(start) if start is not None else None
    end = pd.Timestamp(end) if end is not None else None
    if start is not None and end is not None and start > end:
        raise ToolFailure(CODE_INVALID, "start is after end")
    return start, end


def _stats(series):
    s = series.dropna()
    if s.empty:
        return {"mean": None, "median": None, "min": None, "max": None}
    return {"mean": _round(s.mean()), "median": _round(s.median()), "min": _round(s.min()), "max": _round(s.max())}


def _top(frame, column):
    counts = frame.groupby(column).size().reset_index(name="flows")
    counts = counts.sort_values(["flows", column], ascending=[False, True], kind="stable").head(TOP_N)
    return [{column: (v.item() if hasattr(v, "item") else v), "flows": int(n)} for v, n in zip(counts[column], counts["flows"])]


class FlowTools:
    def __init__(self, store=None):
        self.store = store

    def _need_store(self):
        if self.store is None:
            raise ToolFailure(CODE_UNAVAILABLE, "no flow store is attached to this tool set")
        return self.store

    # -------------------------------------------------------------------------------- query_flows
    def query(self, c):
        store = self._need_store()
        filters = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "around", "start", "end"]
        if all(c.get(name) is None for name in filters):
            raise ToolFailure(CODE_INVALID, "give at least one filter: " + ", ".join(filters))
        start, end = _window(c)
        found = store.select(src_ip=c["src_ip"], dst_ip=c["dst_ip"], src_port=c["src_port"], dst_port=c["dst_port"], protocol=c["protocol"], start=start, end=end)
        total = int(len(found))
        limit = c["limit"]
        shown = found.head(limit) if c["order"] == "asc" else found.tail(limit).iloc[::-1]
        if c["fields"] == "identity":
            columns = ID_COLUMNS
        elif c["fields"] == "all":
            columns = ID_COLUMNS + store.feature_columns
        else:
            columns = ID_COLUMNS + store.display_columns
        return {"total_matches": total, "returned": int(len(shown)), "truncated": total > len(shown), "order": c["order"], "fields": c["fields"],
                "flows": shown[columns].to_dict("records"), "note": NOTE_FEATURES if c["fields"] != "identity" else None}

    # -------------------------------------------------------------------------------- summarize_flows
    def summarize(self, c):
        store = self._need_store()
        start, end = _window(c)
        found = store.select(ip=c["ip"], direction=c["direction"], dst_port=c["dst_port"], start=start, end=end)
        out = {"ip": c["ip"], "direction": c["direction"], "dst_port_filter": c["dst_port"], "window_start": start, "window_end": end, "n_flows": int(len(found))}
        if found.empty:
            out.update({"first_flow": None, "last_flow": None, "distinct_source_ips": 0, "distinct_destination_ips": 0, "distinct_destination_ports": 0,
                        "protocol_counts": {}, "top_destination_ports": [], "top_destination_ips": [], "feature_summary": {}})
            return out
        out.update({
            "first_flow": found["timestamp"].min(), "last_flow": found["timestamp"].max(),
            "distinct_source_ips": int(found["src_ip"].nunique()), "distinct_destination_ips": int(found["dst_ip"].nunique()),
            "distinct_destination_ports": int(found["dst_port"].nunique()),
            "protocol_counts": {str(k): int(v) for k, v in found["protocol"].value_counts().sort_index().items()},
            "top_destination_ports": _top(found, "dst_port"), "top_destination_ips": _top(found, "dst_ip"),
            "feature_summary": {name: _stats(found[name]) for name in store.display_columns},
            "note": NOTE_FEATURES,
        })
        return out

    # -------------------------------------------------------------------------------- beacon_stats
    def beacon(self, c):
        store = self._need_store()
        start, end = _window(c)
        found = store.select(src_ip=c["src_ip"], dst_ip=c["dst_ip"], dst_port=c["dst_port"], start=start, end=end)
        n = int(len(found))
        out = {"src_ip": c["src_ip"], "dst_ip": c["dst_ip"], "dst_port_filter": c["dst_port"], "window_start": start, "window_end": end, "n_flows": n,
               "sufficient_for_interval_stats": n >= 4}
        if n == 0:
            out.update({"first_flow": None, "last_flow": None, "span_seconds": None, "intervals_seconds": None, "forward_bytes": None, "flow_duration": None})
            return out
        times = found["timestamp"]
        gaps = times.diff().dropna().dt.total_seconds()
        intervals = None
        if len(gaps) > 0:
            mean = float(gaps.mean())
            median = float(gaps.median())
            std = float(gaps.std(ddof=1)) if len(gaps) >= 2 else None
            within = None
            if median > 0:
                within = _round(float(((gaps - median).abs() <= 0.1 * median).mean()), 4)
            zeros = int((gaps == 0).sum())
            intervals = {"count": int(len(gaps)), "mean": _round(mean), "median": _round(median), "std": _round(std), "min": _round(gaps.min()), "max": _round(gaps.max()),
                         "cv": _round(std / mean, 4) if (std is not None and mean > 0) else None, "share_within_10pct_of_median": within,
                         "zero_length_intervals": zeros,
                         "caveat": "many flows share one timestamp, so timing resolution may be coarse" if zeros / len(gaps) > 0.5 else None}
        out.update({"first_flow": times.min(), "last_flow": times.max(), "span_seconds": _round((times.max() - times.min()).total_seconds()), "intervals_seconds": intervals,
                    "forward_bytes": None, "flow_duration": None, "note": NOTE_FEATURES})
        if FWD_BYTES in found.columns:
            s = found[FWD_BYTES].dropna()
            out["forward_bytes"] = {"column": FWD_BYTES, "mean": _round(s.mean()), "std": _round(s.std(ddof=1)) if len(s) >= 2 else None, "min": _round(s.min()), "max": _round(s.max())}
        if FLOW_DURATION in found.columns:
            s = found[FLOW_DURATION].dropna()
            out["flow_duration"] = {"column": FLOW_DURATION, "mean": _round(s.mean()), "std": _round(s.std(ddof=1)) if len(s) >= 2 else None, "min": _round(s.min()), "max": _round(s.max())}
        return out

    # -------------------------------------------------------------------------------- tool descriptions
    def specs(self):
        window = {"around": P("timestamp", "Centre of a time window (use with window_minutes)."),
                  "start": P("timestamp", "Earliest flow time, inclusive."), "end": P("timestamp", "Latest flow time, inclusive.")}
        query_params = {
            "src_ip": P("ip", "Source address."), "dst_ip": P("ip", "Destination address."),
            "src_port": P("integer", "Source port.", minimum=0, maximum=65535), "dst_port": P("integer", "Destination port.", minimum=0, maximum=65535),
            "protocol": P("integer", "IP protocol number (6 = TCP, 17 = UDP).", minimum=0, maximum=255),
            "around": window["around"], "window_minutes": P("integer", "Half-width of the window around 'around', in minutes.", default=triage_inputs.CONTEXT_WINDOW_MINUTES, minimum=1, maximum=720),
            "start": window["start"], "end": window["end"],
            "fields": P("enum", "identity = addresses, ports, protocol; display = plus the main flow features; all = every feature.", default="display", enum=["identity", "display", "all"]),
            "limit": P("integer", "Maximum flows returned.", default=DEFAULT_ROWS, minimum=1, maximum=MAX_ROWS),
            "order": P("enum", "Time order of the returned flows.", default="asc", enum=["asc", "desc"]),
        }
        summary_params = {
            "ip": P("ip", "The host to summarise.", required=True),
            "direction": P("enum", "Whether the host is the source, the destination, or either.", default="src", enum=["src", "dst", "either"]),
            "dst_port": P("integer", "Only flows to this destination port.", minimum=0, maximum=65535),
            "around": window["around"], "window_minutes": P("integer", "Half-width of the window around 'around', in minutes.", default=triage_inputs.CONTEXT_WINDOW_MINUTES, minimum=1, maximum=720),
            "start": window["start"], "end": window["end"],
        }
        beacon_params = {
            "src_ip": P("ip", "Source address (the suspected client).", required=True), "dst_ip": P("ip", "Destination address (the suspected server).", required=True),
            "dst_port": P("integer", "Only flows to this destination port.", minimum=0, maximum=65535),
            "around": window["around"], "window_minutes": P("integer", "Half-width of the window around 'around', in minutes.", default=60, minimum=1, maximum=720),
            "start": window["start"], "end": window["end"],
        }
        return [
            ToolSpec("query_flows", "List flow records that match the filters (addresses, ports, protocol, time window). Returns at most 'limit' flows and says how many matched in total.",
                     query_params, self.query),
            ToolSpec("summarize_flows", "Summarise one host's flows in a time window: flow count, distinct destinations and ports, protocol mix, busiest ports and addresses, feature statistics. Facts only.",
                     summary_params, self.summarize),
            ToolSpec("beacon_stats", "Timing and size statistics for the flows from one source to one destination: gaps between flows (mean, median, spread, share close to the median), forward bytes and duration. "
                     "Facts only; it does not say whether the pattern is beaconing.", beacon_params, self.beacon),
        ]
